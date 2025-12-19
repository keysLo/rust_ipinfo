# Rust IP Info Service

**Language / 语言**: English (default) | [简体中文](#简体中文)

---

## English

A small Actix Web service that performs IP geolocation and ASN lookups using MaxMind-compatible MMDB databases. It exposes Prometheus metrics, supports hot-reloading of the database files, and returns a simple JSON payload for each lookup.

### Features
- GeoLite2 City and ASN lookups backed by memory-mapped MMDB readers.
- Caching of lookup results for repeat queries.
- Prometheus metrics (`/metrics`) for request counts and latency histograms.
- Hot reload of the database files via `POST /reload` without restarting the server.
- Lightweight OpenAPI description available at `/openapi.json`.
- Optional localhost-only protection for admin-style endpoints (`/reload`, `/metrics`, `/openapi.json`).

### Requirements
- Rust toolchain (e.g., via `rustup`).
- Database files placed in the working directory:
  - `GeoLite2-City.mmdb`
  - `ipinfo_lite.mmdb` (MaxMind-format ASN database)

### Running the service
1. Ensure the two MMDB files are present in the current directory.
2. Start the server (defaults to `0.0.0.0:8080`):
   ```bash
   cargo run
   ```

### Optional security toggle (ADMIN_LOCAL_ONLY)
The admin-style endpoints (`/reload`, `/metrics`, `/openapi.json`) can be locked down to localhost. Control this via the `ADMIN_LOCAL_ONLY` environment variable at process start:

| Value accepted (case-insensitive) | Effect |
| --- | --- |
| `1` (also accepts `true/yes/on`) or unset | **Default.** Restrict admin endpoints to `127.0.0.1` / `::1`; remote clients receive `403`. |
| `0` (also accepts `false/no/off`) | Admin endpoints remain reachable from any client; the guard is bypassed. |

Examples:
```bash
# Enable localhost-only protection (default)
ADMIN_LOCAL_ONLY=true cargo run

# Disable the guard
ADMIN_LOCAL_ONLY=0 cargo run
```

**`nohup` example**
```bash
cargo build --release
ADMIN_LOCAL_ONLY=1 nohup ./target/release/ipinfo > /dev/null 2>&1 &
```

### Endpoints
- `GET /` — IP lookup. Optional query param: `ip=<IPv4|IPv6>`. If omitted, the client address is used. Response fields include `country`, `region`, `city`, `asn`, `as_name`, `as_domain`, `network`, and error hints (`geolocation_error`, `asn_error`) when data is missing.
- `POST /reload` — Hot reload `GeoLite2-City.mmdb` and `ipinfo_lite.mmdb` atomically.
- `GET /metrics` — Prometheus text format (`http_requests_total`, `http_request_duration_seconds`). Returns `# No metrics recorded yet` when no traffic has been served.
- `GET /openapi.json` — Minimal OpenAPI 3.0 document describing the endpoints and the `Output` schema.

### Data handling notes
- Lookups are memory-mapped for performance (`memmap2`) and swapped atomically on reload (`ArcSwap`).
- A `DashMap` cache (up to 100,000 entries) stores responses by `IpAddr` for repeat queries.
- Errors: bad input returns HTTP `400`; reload failures return `500` with details about which database failed to load.

### Development
- Main crates: `actix-web`, `arc-swap`, `dashmap`, `maxminddb`, `memmap2`, `prometheus`, `serde`, `serde_json`.
- To verify builds locally:
  ```bash
  cargo check
  ```
  (Network access may be required to download dependencies on first run.)

---

## 简体中文

这是一个使用 Actix Web 编写的小型服务，利用兼容 MaxMind 的 MMDB 数据库完成 IP 地理位置和 ASN 查询。它提供 Prometheus 指标、支持热重载数据库文件，并为每次查询返回简洁的 JSON 结果。

### 功能
- 使用内存映射的 MMDB 读取器查询 GeoLite2 城市库和 ASN 库。
- 针对重复请求的查询结果缓存。
- Prometheus 指标（`/metrics`），包含请求计数与延迟直方图。
- 通过 `POST /reload` 热重载数据库文件，无需重启服务。
- `/openapi.json` 提供精简版 OpenAPI 描述。
- 可选的本地回环限制保护管理类接口（`/reload`、`/metrics`、`/openapi.json`）。

### 环境要求
- Rust 工具链（例如通过 `rustup` 安装）。
- 工作目录下需要的数据库文件：
  - `GeoLite2-City.mmdb`
  - `ipinfo_lite.mmdb`（MaxMind 格式的 ASN 数据库）

### 运行服务
1. 确认上述两个 MMDB 文件已在当前目录。
2. 启动服务（默认监听 `0.0.0.0:8080`）：
   ```bash
   cargo run
   ```

### 可选安全开关（ADMIN_LOCAL_ONLY）
管理类接口可限制仅本地访问。启动前设置环境变量 `ADMIN_LOCAL_ONLY`：

| 可接受值（不区分大小写） | 效果 |
| --- | --- |
| `1`（或 `true/yes/on`）或未设置 | **默认。** 将管理接口限制为 `127.0.0.1` / `::1`，远程请求返回 `403`。 |
| `0`（或 `false/no/off`） | 允许任何客户端访问管理接口，不再校验来源。 |

示例：
```bash
# 启用仅本地访问（默认）
ADMIN_LOCAL_ONLY=true cargo run

# 关闭限制
ADMIN_LOCAL_ONLY=0 cargo run
```

**`nohup` 示例**
```bash
cargo build --release
ADMIN_LOCAL_ONLY=1 nohup ./target/release/ipinfo > /dev/null 2>&1 &
```

### 接口
- `GET /` — IP 查询。可选参数 `ip=<IPv4|IPv6>`；若省略则使用客户端地址。响应包含 `country`、`region`、`city`、`asn`、`as_name`、`as_domain`、`network`，以及缺失数据的提示字段 `geolocation_error`、`asn_error`。
- `POST /reload` — 热重载 `GeoLite2-City.mmdb` 与 `ipinfo_lite.mmdb`，原子替换。
- `GET /metrics` — Prometheus 文本格式（`http_requests_total`、`http_request_duration_seconds`）。若暂无流量则返回 `# No metrics recorded yet` 提示。
- `GET /openapi.json` — 返回精简版 OpenAPI 3.0 文档，描述接口和 `Output` 结构。

### 数据处理说明
- 查询使用内存映射（`memmap2`），通过 `ArcSwap` 原子替换实现热重载。
- `DashMap` 缓存（最多 100,000 条）按 `IpAddr` 存储响应，加速重复查询。
- 错误处理：非法输入返回 HTTP `400`；重载失败返回 `500` 并指明加载失败的数据库。

### 开发
- 主要依赖：`actix-web`、`arc-swap`、`dashmap`、`maxminddb`、`memmap2`、`prometheus`、`serde`、`serde_json`。
- 本地校验构建：
  ```bash
  cargo check
  ```
  （首次运行可能需要网络下载依赖。）
