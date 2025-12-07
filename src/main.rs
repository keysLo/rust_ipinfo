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

fn eval_admin_access(req: &HttpRequest) -> (bool, String) {
    let forwarded = req
        .connection_info()
        .realip_remote_addr()
        .and_then(parse_ip_from_addr);
    let peer = req.peer_addr().map(|addr| addr.ip());

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

    // If no peer IP is available, err on the side of blocking.
    (
        false,
        format!("blocked: forwarded={forwarded:?}, peer=None (missing peer address)"),
    )
}

fn guard_admin_endpoint(req: &HttpRequest, config: &AppConfig) -> Result<(), HttpResponse> {
    if !config.restrict_admin_to_localhost {
        return Ok(());
    }

    let (allow, reason) = eval_admin_access(req);

    if allow {
        Ok(())
    } else {
        Err(HttpResponse::Forbidden()
            .content_type("text/plain; charset=utf-8")
            .body(format!("403 \nÏêÇé: {reason}")))
    }
}

// ---------------- Handlers ----------------

async fn lookup(
    req: HttpRequest,
    query: web::Query<HashMap<String, String>>,
    data: web::Data<DbState>,
) -> impl Responder {
    let timer = Instant::now();

    // 1. »ñÈ¡ IP ×Ö·û´®
    let client_ip_str = query.get("ip").cloned().unwrap_or_else(|| {
        req.peer_addr()
            .map(|x| x.ip().to_string())
            .unwrap_or_else(|| "0.0.0.0".to_string())
    });

    // 2. ½âÎö IP
    let ip: IpAddr = match client_ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => {
            HTTP_REQUESTS_TOTAL
                .with_label_values(&["/", req.method().as_str(), "400"])
                .inc();
            return HttpResponse::BadRequest().json(json!({
                "error": format!("·Ç·¨ IP µØÖ·: {}", client_ip_str)
            }));
        }
    };

    // 3. »º´æÃüÖÐ
    if let Some(cached) = data.cache.get(&ip) {
        let mut res = cached.clone();
        // ±£Ö¤ ip ×Ö¶ÎÊÇÕâ´ÎÇëÇó¿´µ½µÄ×Ö·û´®£¨Í¨³£Ò»Ñù£©
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

    // 4. Õý³£²éÑ¯
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

    // ---- GeoLite2-City ²éÑ¯ ----
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
            result.geolocation_error = Some("IP Î´ÔÚ GeoLite2-City.mmdb ÖÐÕÒµ½".to_string());
        }
        Err(e) => {
            result.geolocation_error = Some(format!("GeoLite2-City ²éÑ¯Ê§°Ü: {}", e));
        }
    }

    // ---- ipinfo_lite ²éÑ¯ (ASN) ----
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
                result.asn_error = Some(format!("ÎÞÐ§µÄÇ°×º³¤¶È: {}", prefix_len));
            }
        }
        Ok((None, _)) => {
            result.asn_error = Some("IP Î´ÔÚ ipinfo_lite.mmdb ÖÐÕÒµ½".to_string());
        }
        Err(e) => {
            result.asn_error = Some(format!("ipinfo_lite ²éÑ¯Ê§°Ü: {}", e));
        }
    }

    // 5. ¸üÐÂ»º´æ£¨¼òµ¥ÏÞÖÆ×î´ó´óÐ¡£©
    const MAX_CACHE_SIZE: usize = 100_000;
    if data.cache.len() < MAX_CACHE_SIZE {
        data.cache.insert(ip, result.clone());
    }

    // 6. Metrics & ·µ»Ø
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

    if let Err(resp) = guard_admin_endpoint(&req, &config) {
        let elapsed = timer.elapsed().as_secs_f64();
        HTTP_REQUEST_DURATION_SECONDS
            .with_label_values(&["/reload", req.method().as_str()])
            .observe(elapsed);
        HTTP_REQUESTS_TOTAL
            .with_label_values(&["/reload", req.method().as_str(), "403"])
            .inc();

        return resp;
    }

    match (
        load_mmap_reader("./GeoLite2-City.mmdb"),
        load_mmap_reader("./ipinfo_lite.mmdb"),
    ) {
        (Ok(city), Ok(asn)) => {
            // Zero-copy reload£ºArcSwap »áÈÃ¾É Arc ³ÖÐø´æÔÚÖ±µ½ËùÓÐÒýÓÃÊÍ·Å
            data.city_db.store(Arc::new(city));
            data.asn_db.store(Arc::new(asn));

            let elapsed = timer.elapsed().as_secs_f64();
            HTTP_REQUEST_DURATION_SECONDS
                .with_label_values(&["/reload", req.method().as_str()])
                .observe(elapsed);
            HTTP_REQUESTS_TOTAL
                .with_label_values(&["/reload", req.method().as_str(), "200"])
                .inc();

            HttpResponse::Ok().body("Êý¾Ý¿âÒÑÖØÐÂ¼ÓÔØ")
        }
        (Err(e), _) => {
            HTTP_REQUESTS_TOTAL
                .with_label_values(&["/reload", req.method().as_str(), "500"])
                .inc();
            HttpResponse::InternalServerError().body(format!("Geo DB ¼ÓÔØÊ§°Ü: {}", e))
        }
        (_, Err(e)) => {
            HTTP_REQUESTS_TOTAL
                .with_label_values(&["/reload", req.method().as_str(), "500"])
                .inc();
            HttpResponse::InternalServerError().body(format!("ASN DB ¼ÓÔØÊ§°Ü: {}", e))
        }
    }
}

// Prometheus metrics endpoint
async fn metrics(req: HttpRequest, config: web::Data<AppConfig>) -> impl Responder {
    let timer = Instant::now();

    if let Err(resp) = guard_admin_endpoint(&req, &config) {
        let elapsed = timer.elapsed().as_secs_f64();
        HTTP_REQUEST_DURATION_SECONDS
            .with_label_values(&["/metrics", req.method().as_str()])
            .observe(elapsed);
        HTTP_REQUESTS_TOTAL
            .with_label_values(&["/metrics", req.method().as_str(), "403"])
            .inc();

        return resp;
    }

    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        return HttpResponse::InternalServerError().body(format!("encode metrics error: {}", e));
    }

    if buffer.is_empty() {
        return HttpResponse::Ok()
            .content_type("text/plain; charset=utf-8")
            .body("# No metrics recorded yet\n");
    }

    let elapsed = timer.elapsed().as_secs_f64();
    HTTP_REQUEST_DURATION_SECONDS
        .with_label_values(&["/metrics", req.method().as_str()])
        .observe(elapsed);
    HTTP_REQUESTS_TOTAL
        .with_label_values(&["/metrics", req.method().as_str(), "200"])
        .inc();

    HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(buffer)
}

// Swagger/OpenAPI£¨¼òÒ×°æ£©
async fn openapi(req: HttpRequest, config: web::Data<AppConfig>) -> impl Responder {
    let timer = Instant::now();

    if let Err(resp) = guard_admin_endpoint(&req, &config) {
        let elapsed = timer.elapsed().as_secs_f64();
        HTTP_REQUEST_DURATION_SECONDS
            .with_label_values(&["/openapi.json", req.method().as_str()])
            .observe(elapsed);
        HTTP_REQUESTS_TOTAL
            .with_label_values(&["/openapi.json", req.method().as_str(), "403"])
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
                    "summary": "¸ù¾Ý IP ²éÑ¯µØÀíÎ»ÖÃÓë ASN ÐÅÏ¢",
                    "parameters": [
                        {
                            "name": "ip",
                            "in": "query",
                            "required": false,
                            "schema": { "type": "string", "format": "ip" },
                            "description": "Òª²éÑ¯µÄ IP µØÖ·£¬²»´«ÔòÊ¹ÓÃ¿Í»§¶Ë IP"
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
                            "description": "·Ç·¨ IP"
                        }
                    }
                }
            },
            "/reload": {
                "post": {
                    "summary": "ÖØÐÂ¼ÓÔØ mmdb Êý¾Ý¿â£¨ÈÈ¸üÐÂ£©",
                    "responses": {
                        "200": { "description": "ÖØÐÂ¼ÓÔØ³É¹¦" },
                        "500": { "description": "¼ÓÔØÊ§°Ü" }
                    }
                }
            },
            "/metrics": {
                "get": {
                    "summary": "Prometheus metrics",
                    "responses": {
                        "200": {
                            "description": "Prometheus ÎÄ±¾¸ñÊ½µÄ metrics",
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
        .with_label_values(&["/openapi.json", req.method().as_str()])
        .observe(elapsed);
    HTTP_REQUESTS_TOTAL
        .with_label_values(&["/openapi.json", req.method().as_str(), "200"])
        .inc();

    HttpResponse::Ok().json(spec)
}

// ---------------- main ----------------

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("·þÎñÆô¶¯ÓÚ http://0.0.0.0:8080/");

    let city_db = load_mmap_reader("./GeoLite2-City.mmdb").expect("GeoLite2-City.mmdb ¼ÓÔØÊ§°Ü");
    let asn_db = load_mmap_reader("./ipinfo_lite.mmdb").expect("ipinfo_lite.mmdb ¼ÓÔØÊ§°Ü");

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
