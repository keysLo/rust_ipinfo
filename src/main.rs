use axum::{
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use arc_swap::ArcSwap;
use dashmap::DashMap;
use maxminddb::{geoip2, Reader};
use maxminddb::geoip2::Names;
use memmap2::Mmap;
use once_cell::sync::Lazy;
use prometheus::{
    register_histogram_vec, register_int_counter_vec, Encoder, HistogramVec, IntCounterVec,
    TextEncoder,
};
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::Result as IoResult;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::time;

// ---------------- Metrics ----------------

static HTTP_REQUESTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "http_requests_total",
        "Number of HTTP requests received",
        &["path", "method", "status"]
    )
    .expect("failed to create http_requests_total")
});

static HTTP_REQUEST_DURATION_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "http_request_duration_seconds",
        "HTTP request latencies in seconds",
        &["path", "method"]
    )
    .expect("failed to create http_request_duration_seconds")
});

// ---------------- Output Struct ----------------

#[derive(Serialize, Clone)]
struct Output {
    ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    as_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    as_domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    geolocation_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asn_error: Option<String>,
}

fn english_name(names: &Names<'_>) -> Option<String> {
    names.english.map(|s| s.to_string())
}

// ---------------- State ----------------

struct DbState {
    city_db: ArcSwap<Reader<Mmap>>,
    asn_db: ArcSwap<Reader<Mmap>>,
    cache: Arc<DashMap<IpAddr, CachedEntry>>,
}

#[derive(Clone)]
struct AppConfig {
    restrict_admin_to_localhost: bool,
}

#[derive(Clone)]
struct AppState {
    inner: Arc<DbState>,
    config: Arc<AppConfig>,
}

struct CachedEntry {
    data: Output,
    expires_at: Instant,
}

const CACHE_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

fn admin_local_only_enabled() -> bool {
    env::var("ADMIN_LOCAL_ONLY")
        .ok()
        .as_deref()
        .map(|value| value.trim().to_ascii_lowercase())
        .and_then(|normalized| match normalized.as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
        .unwrap_or(true)
}

fn load_mmap_reader(path: &str) -> IoResult<Reader<Mmap>> {
    let file = File::open(path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    Reader::from_source(mmap).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

fn parse_ip_from_addr(addr: &str) -> Option<IpAddr> {
    // Try the full string first (useful when connection info already strips the port).
    if let Ok(ip) = addr.parse() {
        return Some(ip);
    }

    // Handle common "IP:PORT" and "[IPv6]:PORT" formats from connection_info().
    if let Some(stripped) = addr.strip_prefix('[') {
        if let Some((ip, _)) = stripped.rsplit_once(']') {
            return ip.parse().ok();
        }
    }

    addr.rsplit_once(':').and_then(|(ip, _)| ip.parse().ok())
}

fn extract_forwarded_ip(headers: &HeaderMap) -> Option<IpAddr> {
    if let Some(value) = headers.get("x-forwarded-for") {
        if let Ok(text) = value.to_str() {
            if let Some(first) = text.split(',').next() {
                if let Some(ip) = parse_ip_from_addr(first.trim()) {
                    return Some(ip);
                }
            }
        }
    }

    if let Some(value) = headers.get("forwarded") {
        if let Ok(text) = value.to_str() {
            for part in text.split(';') {
                for token in part.split(',') {
                    let token = token.trim();
                    if let Some(rest) = token.strip_prefix("for=") {
                        let cleaned = rest.trim_matches('"');
                        if let Some(ip) =
                            parse_ip_from_addr(cleaned.trim_matches(|c| c == '[' || c == ']'))
                        {
                            return Some(ip);
                        }
                    }
                }
            }
        }
    }

    None
}

fn eval_admin_access(forwarded: Option<IpAddr>, peer: Option<IpAddr>) -> (bool, String) {
    if let Some(real) = forwarded {
        if !real.is_loopback() {
            return (
                false,
                format!(
                    "blocked: forwarded={real}, peer={:?} (non-loopback forwarded)",
                    peer
                ),
            );
        }
    }

    if let Some(peer_ip) = peer {
        let allow = peer_ip.is_loopback();
        let reason = if allow {
            format!("allowed: forwarded={forwarded:?}, peer={peer_ip} (loopback peer)")
        } else {
            format!("blocked: forwarded={forwarded:?}, peer={peer_ip} (non-loopback peer)")
        };
        return (allow, reason);
    }

    (
        false,
        format!("blocked: forwarded={forwarded:?}, peer=None (missing peer address)"),
    )
}

fn guard_admin_endpoint(
    headers: &HeaderMap,
    peer: Option<IpAddr>,
    config: &AppConfig,
) -> Result<(), Response> {
    if !config.restrict_admin_to_localhost {
        return Ok(());
    }

    let forwarded = extract_forwarded_ip(headers);
    let (allow, reason) = eval_admin_access(forwarded, peer);

    if allow {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, format!("403 \n详情: {reason}")).into_response())
    }
}

fn start_cache_cleaner(cache: Arc<DashMap<IpAddr, CachedEntry>>) {
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(60 * 60));
        loop {
            interval.tick().await;
            let now = Instant::now();
            cache.retain(|_, entry| entry.expires_at > now);
        }
    });
}

// ---------------- Handlers ----------------

async fn lookup(
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let timer = Instant::now();
    let forwarded = extract_forwarded_ip(&headers);

    // 1. 获取 IP 字符串
    let client_ip_str = query.get("ip").cloned().unwrap_or_else(|| {
        forwarded
            .map(|x| x.to_string())
            .unwrap_or_else(|| peer.ip().to_string())
    });

    // 2. ½âÎö IP
    let ip: IpAddr = match client_ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => {
            HTTP_REQUESTS_TOTAL
                .with_label_values(&["/", "GET", "400"])
                .inc();
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!("非法 IP 地址: {}", client_ip_str)
                })),
            )
                .into_response();
        }
    };

    // 3. 查询缓存
    let now = Instant::now();
    if let Some(mut cached) = state.inner.cache.get_mut(&ip) {
        if cached.expires_at <= now {
            // Expired entry: drop guard before removal
            drop(cached);
            state.inner.cache.remove(&ip);
        } else {
            cached.expires_at = now + CACHE_TTL;
            let mut res = cached.data.clone();
        // Ensure the ip field mirrors the request string (usually identical).
        res.ip = client_ip_str.clone();

        let elapsed = timer.elapsed().as_secs_f64();
        HTTP_REQUEST_DURATION_SECONDS
            .with_label_values(&["/", "GET"])
            .observe(elapsed);
        HTTP_REQUESTS_TOTAL
            .with_label_values(&["/", "GET", "200"])
            .inc();

        return Json(res).into_response();
        }
    }

    // 4. 正常查询
    let mut result = Output {
        ip: client_ip_str.clone(),
        country: None,
        region: None,
        city: None,
        asn: None,
        as_name: None,
        as_domain: None,
        network: None,
        geolocation_error: None,
        asn_error: None,
    };

    // ---- GeoLite2-City 查询 ----
    let city_reader = state.inner.city_db.load();
    match city_reader.lookup(ip) {
        Ok(lookup) => match lookup.decode::<geoip2::City>() {
            Ok(Some(city)) => {
                result.country = english_name(&city.country.names);

                result.region = city
                    .subdivisions
                    .get(0)
                    .and_then(|r| english_name(&r.names));

                result.city = english_name(&city.city.names);
            }
            Ok(None) => {
                result.geolocation_error =
                    Some("IP 未在 GeoLite2-City.mmdb 中找到".to_string());
            }
            Err(e) => {
                result.geolocation_error = Some(format!("GeoLite2-City 查询失败: {}", e));
            }
        },
        Err(e) => {
            result.geolocation_error = Some(format!("GeoLite2-City 查询失败: {}", e));
        }
    }

    // ---- ipinfo_lite 查询 (ASN) ----
    let asn_reader = state.inner.asn_db.load();
    match asn_reader.lookup(ip) {
        Ok(lookup) => {
            let network = lookup.network().ok();
            match lookup.decode::<serde_json::Value>() {
                Ok(Some(val)) => {
                    result.asn = val.get("asn").and_then(|v| v.as_u64()).map(|v| v as u32);
                    result.as_name = val
                        .get("as_name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    result.as_domain = val
                        .get("as_domain")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    if let Some(prefix) = network {
                        result.network = Some(prefix.to_string());
                    }
                }
                Ok(None) => {
                    result.asn_error = Some("IP 未在 ipinfo_lite.mmdb 中找到".to_string());
                }
                Err(e) => {
                    result.asn_error = Some(format!("ipinfo_lite 查询失败: {}", e));
                }
            }
        }
        Err(e) => {
            result.asn_error = Some(format!("ipinfo_lite 查询失败: {}", e));
        }
    }

    // 5. 更新缓存（简单限制最大大小）
    const MAX_CACHE_SIZE: usize = 100_000;
    if state.inner.cache.len() < MAX_CACHE_SIZE {
        state.inner.cache.insert(
            ip,
            CachedEntry {
                data: result.clone(),
                expires_at: Instant::now() + CACHE_TTL,
            },
        );
    }

    // 6. Metrics & response
    let elapsed = timer.elapsed().as_secs_f64();
    HTTP_REQUEST_DURATION_SECONDS
        .with_label_values(&["/", "GET"])
        .observe(elapsed);
    HTTP_REQUESTS_TOTAL
        .with_label_values(&["/", "GET", "200"])
        .inc();

    Json(result).into_response()
}

async fn reload(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let timer = Instant::now();

    if let Err(resp) = guard_admin_endpoint(&headers, Some(peer.ip()), state.config.as_ref()) {
        let elapsed = timer.elapsed().as_secs_f64();
        HTTP_REQUEST_DURATION_SECONDS
            .with_label_values(&["/reload", "POST"])
            .observe(elapsed);
        HTTP_REQUESTS_TOTAL
            .with_label_values(&["/reload", "POST", "403"])
            .inc();

        return resp;
    }

    match (
        load_mmap_reader("./GeoLite2-City.mmdb"),
        load_mmap_reader("./ipinfo_lite.mmdb"),
    ) {
        (Ok(city), Ok(asn)) => {
            // Zero-copy reload: ArcSwap keeps old Arcs alive until all references drop.
            state.inner.city_db.store(Arc::new(city));
            state.inner.asn_db.store(Arc::new(asn));

            let elapsed = timer.elapsed().as_secs_f64();
            HTTP_REQUEST_DURATION_SECONDS
                .with_label_values(&["/reload", "POST"])
                .observe(elapsed);
            HTTP_REQUESTS_TOTAL
                .with_label_values(&["/reload", "POST", "200"])
                .inc();

            (StatusCode::OK, "数据仓已重新加载").into_response()
        }
        (Err(e), _) => {
            HTTP_REQUESTS_TOTAL
                .with_label_values(&["/reload", "POST", "500"])
                .inc();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Geo DB 加载失败: {}", e),
            )
                .into_response()
        }
        (_, Err(e)) => {
            HTTP_REQUESTS_TOTAL
                .with_label_values(&["/reload", "POST", "500"])
                .inc();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("ASN DB 加载失败: {}", e),
            )
                .into_response()
        }
    }
}

// Prometheus metrics endpoint
async fn metrics(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let timer = Instant::now();

    if let Err(resp) = guard_admin_endpoint(&headers, Some(peer.ip()), state.config.as_ref()) {
        let elapsed = timer.elapsed().as_secs_f64();
        HTTP_REQUEST_DURATION_SECONDS
            .with_label_values(&["/metrics", "GET"])
            .observe(elapsed);
        HTTP_REQUESTS_TOTAL
            .with_label_values(&["/metrics", "GET", "403"])
            .inc();

        return resp;
    }

    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("encode metrics error: {}", e),
        )
            .into_response();
    }

    if buffer.is_empty() {
        return (
            StatusCode::OK,
            [("Content-Type", "text/plain; charset=utf-8")],
            "# No metrics recorded yet\n",
        )
            .into_response();
    }

    let elapsed = timer.elapsed().as_secs_f64();
    HTTP_REQUEST_DURATION_SECONDS
        .with_label_values(&["/metrics", "GET"])
        .observe(elapsed);
    HTTP_REQUESTS_TOTAL
        .with_label_values(&["/metrics", "GET", "200"])
        .inc();

    (
        StatusCode::OK,
        [("Content-Type", "text/plain; charset=utf-8")],
        buffer,
    )
        .into_response()
}

// Swagger/OpenAPI£¨¼òÒ×°æ£©
async fn openapi(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let timer = Instant::now();

    if let Err(resp) = guard_admin_endpoint(&headers, Some(peer.ip()), state.config.as_ref()) {
        let elapsed = timer.elapsed().as_secs_f64();
        HTTP_REQUEST_DURATION_SECONDS
            .with_label_values(&["/openapi.json", "GET"])
            .observe(elapsed);
        HTTP_REQUESTS_TOTAL
            .with_label_values(&["/openapi.json", "GET", "403"])
            .inc();

        return resp;
    }

    let spec = json!({
        "openapi": "3.0.0",
        "info": {
            "title": "IP Info Service",
            "version": "1.0.0"
        },
        "paths": {
            "/": {
                "get": {
                    "summary": "根据 IP 查询地理位置与 ASN 信息",
                    "parameters": [
                        {
                            "name": "ip",
                            "in": "query",
                            "required": false,
                            "schema": { "type": "string", "format": "ip" },
                            "description": "要查询的 IP 地址，不传则使用客户端 IP"
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "²éÑ¯³É¹¦",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/Output" }
                                }
                            }
                        },
                        "400": {
                            "description": "非法 IP"
                        }
                    }
                }
            },
            "/reload": {
                "post": {
                    "summary": "重新加载 mmdb 数据库（热更新）",
                    "responses": {
                        "200": { "description": "重新加载成功" },
                        "500": { "description": "加载失败" }
                    }
                }
            },
            "/metrics": {
                "get": {
                    "summary": "Prometheus metrics",
                    "responses": {
                        "200": {
                            "description": "Prometheus 文本格式的 metrics",
                            "content": {
                                "text/plain": {}
                            }
                        }
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "Output": {
                    "type": "object",
                    "properties": {
                        "ip": { "type": "string" },
                        "country": { "type": "string", "nullable": true },
                        "region": { "type": "string", "nullable": true },
                        "city": { "type": "string", "nullable": true },
                        "asn": { "type": "integer", "format": "int32", "nullable": true },
                        "as_name": { "type": "string", "nullable": true },
                        "as_domain": { "type": "string", "nullable": true },
                        "network": { "type": "string", "nullable": true },
                        "geolocation_error": { "type": "string", "nullable": true },
                        "asn_error": { "type": "string", "nullable": true }
                    },
                    "required": ["ip"]
                }
            }
        }
    });

    let elapsed = timer.elapsed().as_secs_f64();
    HTTP_REQUEST_DURATION_SECONDS
        .with_label_values(&["/openapi.json", "GET"])
        .observe(elapsed);
    HTTP_REQUESTS_TOTAL
        .with_label_values(&["/openapi.json", "GET", "200"])
        .inc();

    Json(spec).into_response()
}

// ---------------- main ----------------

#[tokio::main]
async fn main() -> std::io::Result<()> {
    println!("服务启动于 http://0.0.0.0:8080/");

    let city_db =
        load_mmap_reader("./GeoLite2-City.mmdb").expect("GeoLite2-City.mmdb 加载失败");
    let asn_db =
        load_mmap_reader("./ipinfo_lite.mmdb").expect("ipinfo_lite.mmdb 加载失败");

    let config = Arc::new(AppConfig {
        restrict_admin_to_localhost: admin_local_only_enabled(),
    });

    let state = AppState {
        inner: Arc::new(DbState {
            city_db: ArcSwap::new(Arc::new(city_db)),
            asn_db: ArcSwap::new(Arc::new(asn_db)),
            cache: Arc::new(DashMap::new()),
        }),
        config,
    };

    start_cache_cleaner(state.inner.cache.clone());

    let app = Router::new()
        .route("/", get(lookup))
        .route("/reload", post(reload))
        .route("/metrics", get(metrics))
        .route("/openapi.json", get(openapi))
        .with_state(state);

    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}
