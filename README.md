# Rust IP Info Service

A small Actix-web service that performs IP geolocation and ASN lookups using MaxMind-compatible MMDB databases. It exposes Prometheus metrics, supports hot-reloading of the database files, and returns a simple JSON payload for each lookup.

## Features
- GeoLite2 City and ASN lookups backed by memory-mapped MMDB readers.
- Caching of lookup results for repeat queries.
- Prometheus metrics (`/metrics`) for request counts and latency histograms.
- Hot reload of the database files via `POST /reload` without restarting the server.
- Lightweight OpenAPI description available at `/openapi.json`.

## Requirements
- Rust toolchain (e.g., via `rustup`).
- Database files placed in the working directory:
  - `GeoLite2-City.mmdb`
  - `ipinfo_lite.mmdb` (MaxMind-format ASN database)

## Running the service
1. Ensure the two MMDB files are present in the current directory.
2. Start the server (defaults to `0.0.0.0:8080`):
   ```bash
   cargo run
   ```

You should see a startup message:
```
服务启动于 http://0.0.0.0:8080/
```

## Endpoints
### `GET /` — IP lookup
- Optional query parameter: `ip=<IPv4|IPv6>`.
- If `ip` is omitted, the service uses the client address from the connection.
- Successful responses include fields such as `country`, `region`, `city`, `asn`, `as_name`, `as_domain`, and `network` (CIDR). If a record is missing in either database, the response includes `geolocation_error` or `asn_error` to explain the absence.

Example:
```bash
curl "http://localhost:8080/?ip=8.8.8.8"
```

### `POST /reload` — Hot reload databases
Reloads both `GeoLite2-City.mmdb` and `ipinfo_lite.mmdb` from the working directory. This uses zero-copy swapping via `ArcSwap`, so requests in flight are not interrupted.

```bash
curl -X POST http://localhost:8080/reload
```

### `GET /metrics` — Prometheus metrics
Exports standard Prometheus text format containing `http_requests_total` and `http_request_duration_seconds`.

```bash
curl http://localhost:8080/metrics
```

### `GET /openapi.json`
Returns a minimal OpenAPI 3.0 document describing the available endpoints and the `Output` schema returned by `/`.

## Notes on data handling
- Lookups are memory-mapped for performance (`memmap2`) and swapped atomically on reload.
- A `DashMap` cache (default capacity up to 100,000 entries) stores responses keyed by `IpAddr` to speed up repeat queries.
- All successful responses are JSON; errors for bad input are surfaced as HTTP `400`, while reload failures return `500` with details about which database could not be loaded.

## Development
- The project depends on crates such as `actix-web`, `arc-swap`, `dashmap`, `memmap2`, `prometheus`, and `serde`/`serde_json`.
- To verify builds locally, run:
  ```bash
  cargo check
  ```
  (Network access may be required to download dependencies on first run.)

