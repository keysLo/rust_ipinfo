use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use arc_swap::ArcSwap;
use dashmap::DashMap;
use maxminddb::{geoip2, Reader};
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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Instant;

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

// ---------------- Network Helpers ----------------

fn get_network(ip: IpAddr, prefix_len: u16) -> String {
    match ip {
        IpAddr::V4(ipv4) => {
            let p = prefix_len.min(32);
            let mask = if p == 0 {
                0u32
            } else {
                !((1u32 << (32 - p)) - 1)
            };
            let mask = if p == 0 { 0u32 } else { !((1u32 << (32 - p)) - 1) };
            let network = u32::from(ipv4) & mask;
            format!("{}/{}", Ipv4Addr::from(network), p)
        }
        IpAddr::V6(ipv6) => {
            let p = prefix_len.min(128);
            let mut octets = ipv6.octets();
            let bits = p as usize;
            for i in bits..128 {
                let byte_index = i / 8;
                let bit_index = 7 - (i % 8);
                octets[byte_index] &= !(1 << bit_index);
            }
            format!("{}/{}", Ipv6Addr::from(octets), p)
        }
    }
}

// ---------------- State ----------------

struct DbState {
    city_db: ArcSwap<Reader<Mmap>>,
    asn_db: ArcSwap<Reader<Mmap>>,
    cache: DashMap<IpAddr, Output>,
}

#[derive(Clone)]
struct AppConfig {
    restrict_admin_to_localhost: bool,
}

fn admin_local_only_enabled() -> bool {
    env::var("ADMIN_LOCAL_ONLY")
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn load_mmap_reader(path: &str) -> IoResult<Reader<Mmap>> {
    let file = File::open(path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    Reader::from_source(mmap).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

fn is_local_request(req: &HttpRequest) -> bool {
    match req.peer_addr().map(|addr| addr.ip()) {
        Some(IpAddr::V4(v4)) => v4 == Ipv4Addr::LOCALHOST,
        Some(IpAddr::V6(v6)) => v6 == Ipv6Addr::LOCALHOST,
        _ => false,
    }
}

fn guard_admin_endpoint(req: &HttpRequest, config: &AppConfig) -> Option<HttpResponse> {
    if !config.restrict_admin_to_localhost {
        return None;
    }

    if is_local_request(req) {
        None
    } else {
        Some(HttpResponse::Forbidden().body("仅允许 127.0.0.1 访问此接口"))
    }
}

// ---------------- Handlers ----------------

async fn lookup(
    req: HttpRequest,
    query: web::Query<HashMap<String, String>>,
    data: web::Data<DbState>,
) -> impl Responder {
    let timer = Instant::now();

    // 1. 获取 IP 字符串
    let client_ip_str = query.get("ip").cloned().unwrap_or_else(|| {
        req.peer_addr()
            .map(|x| x.ip().to_string())
            .unwrap_or_else(|| "0.0.0.0".to_string())
    });
    let client_ip_str = query
        .get("ip")
        .cloned()
        .unwrap_or_else(|| {
            req.peer_addr()
                .map(|x| x.ip().to_string())
                .unwrap_or_else(|| "0.0.0.0".to_string())
        });

    // 2. 解析 IP
    let ip: IpAddr = match client_ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => {
            HTTP_REQUESTS_TOTAL
                .with_label_values(&["/", req.method().as_str(), "400"])
                .inc();
            return HttpResponse::BadRequest().json(json!({
                "error": format!("非法 IP 地址: {}", client_ip_str)
            }));
        }
    };

    // 3. 缓存命中
    if let Some(cached) = data.cache.get(&ip) {
        let mut res = cached.clone();
        // 保证 ip 字段是这次请求看到的字符串（通常一样）
        res.ip = client_ip_str.clone();

        let elapsed = timer.elapsed().as_secs_f64();
        HTTP_REQUEST_DURATION_SECONDS
            .with_label_values(&["/", req.method().as_str()])
            .observe(elapsed);
        HTTP_REQUESTS_TOTAL
            .with_label_values(&["/", req.method().as_str(), "200"])
            .inc();

        return HttpResponse::Ok().json(res);
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
    let city_reader = data.city_db.load();
    match city_reader.lookup::<geoip2::City>(ip) {
        Ok(Some(city)) => {
            let country = city
                .country
                .and_then(|c| c.names.and_then(|n| n.get("en").map(|s| s.to_string())));
            result.country = country;

            let region = city.subdivisions.and_then(|subs| {
                subs.get(0)
                    .and_then(|r| r.names.as_ref()?.get("en").map(|s| s.to_string()))
            });
            result.region = region;

            let city_name = city
                .city
                .and_then(|c| c.names.and_then(|n| n.get("en").map(|s| s.to_string())));
            result.city = city_name;
        }
        Ok(None) => {
            result.geolocation_error = Some("IP 未在 GeoLite2-City.mmdb 中找到".to_string());
        }
        Err(e) => {
            result.geolocation_error = Some(format!("GeoLite2-City 查询失败: {}", e));
        }
    }

    // ---- ipinfo_lite 查询 (ASN) ----
    let asn_reader = data.asn_db.load();
    match asn_reader.lookup_prefix::<serde_json::Value>(ip) {
        Ok((Some(val), prefix_len)) => {
            result.asn = val.get("asn").and_then(|v| v.as_u64()).map(|v| v as u32);
            result.as_name = val
                .get("as_name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            result.as_domain = val
                .get("as_domain")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            if let Ok(p) = u16::try_from(prefix_len) {
                result.network = Some(get_network(ip, p));
            } else {
                result.asn_error = Some(format!("无效的前缀长度: {}", prefix_len));
            }
        }
        Ok((None, _)) => {
            result.asn_error = Some("IP 未在 ipinfo_lite.mmdb 中找到".to_string());
        }
        Err(e) => {
            result.asn_error = Some(format!("ipinfo_lite 查询失败: {}", e));
        }
    }

    // 5. 更新缓存（简单限制最大大小）
    const MAX_CACHE_SIZE: usize = 100_000;
    if data.cache.len() < MAX_CACHE_SIZE {
        data.cache.insert(ip, result.clone());
    }

    // 6. Metrics & 返回
    let elapsed = timer.elapsed().as_secs_f64();
    HTTP_REQUEST_DURATION_SECONDS
        .with_label_values(&["/", req.method().as_str()])
        .observe(elapsed);
    HTTP_REQUESTS_TOTAL
        .with_label_values(&["/", req.method().as_str(), "200"])
        .inc();

    HttpResponse::Ok().json(result)
}

async fn reload(
    data: web::Data<DbState>,
    config: web::Data<AppConfig>,
    req: HttpRequest,
) -> impl Responder {
    let timer = Instant::now();

    if let Some(resp) = guard_admin_endpoint(&req, &config) {
        let elapsed = timer.elapsed().as_secs_f64();
        HTTP_REQUEST_DURATION_SECONDS
            .with_label_values(&["/reload", req.method().as_str()])
            .observe(elapsed);
        HTTP_REQUESTS_TOTAL
            .with_label_values(&["/reload", req.method().as_str(), "403"])
            .inc();

        return resp;
    }

async fn reload(data: web::Data<DbState>, req: HttpRequest) -> impl Responder {
    let timer = Instant::now();

    match (
        load_mmap_reader("./GeoLite2-City.mmdb"),
        load_mmap_reader("./ipinfo_lite.mmdb"),
    ) {
        (Ok(city), Ok(asn)) => {
            // Zero-copy reload：ArcSwap 会让旧 Arc 持续存在直到所有引用释放
            data.city_db.store(Arc::new(city));
            data.asn_db.store(Arc::new(asn));

            let elapsed = timer.elapsed().as_secs_f64();
            HTTP_REQUEST_DURATION_SECONDS
                .with_label_values(&["/reload", req.method().as_str()])
                .observe(elapsed);
            HTTP_REQUESTS_TOTAL
                .with_label_values(&["/reload", req.method().as_str(), "200"])
                .inc();

            HttpResponse::Ok().body("数据库已重新加载")
        }
        (Err(e), _) => {
            HTTP_REQUESTS_TOTAL
                .with_label_values(&["/reload", req.method().as_str(), "500"])
                .inc();
            HttpResponse::InternalServerError().body(format!("Geo DB 加载失败: {}", e))
        }
        (_, Err(e)) => {
            HTTP_REQUESTS_TOTAL
                .with_label_values(&["/reload", req.method().as_str(), "500"])
                .inc();
            HttpResponse::InternalServerError().body(format!("ASN DB 加载失败: {}", e))
        }
    }
}

// Prometheus metrics endpoint
async fn metrics(req: HttpRequest, config: web::Data<AppConfig>) -> impl Responder {
    if let Some(resp) = guard_admin_endpoint(&req, &config) {
        return resp;
    }

async fn metrics() -> impl Responder {
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        return HttpResponse::InternalServerError().body(format!("encode metrics error: {}", e));
    }

    HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(buffer)
}

// Swagger/OpenAPI（简易版）
async fn openapi(req: HttpRequest, config: web::Data<AppConfig>) -> impl Responder {
    if let Some(resp) = guard_admin_endpoint(&req, &config) {
        return resp;
    }

async fn openapi() -> impl Responder {
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
                            "description": "查询成功",
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

    HttpResponse::Ok().json(spec)
}

// ---------------- main ----------------

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("服务启动于 http://0.0.0.0:8080/");

    let city_db = load_mmap_reader("./GeoLite2-City.mmdb").expect("GeoLite2-City.mmdb 加载失败");
    let asn_db = load_mmap_reader("./ipinfo_lite.mmdb").expect("ipinfo_lite.mmdb 加载失败");

    let config = web::Data::new(AppConfig {
        restrict_admin_to_localhost: admin_local_only_enabled(),
    });

    let state = web::Data::new(DbState {
        city_db: ArcSwap::new(Arc::new(city_db)),
        asn_db: ArcSwap::new(Arc::new(asn_db)),
        cache: DashMap::new(),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .app_data(config.clone())
            .route("/", web::get().to(lookup))
            .route("/reload", web::post().to(reload))
            .route("/metrics", web::get().to(metrics))
            .route("/openapi.json", web::get().to(openapi))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
