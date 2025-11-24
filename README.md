# Rust IP Info Service

A small Actix-web service that performs IP geolocation and ASN lookups using MaxMind-compatible MMDB databases. It exposes Prometheus metrics, supports hot-reloading of the database files, and returns a simple JSON payload for each lookup.

## Features
- GeoLite2 City and ASN lookups backed by memory-mapped MMDB readers.
- Caching of lookup results for repeat queries.
- Prometheus metrics (`/metrics`) for request counts and latency histograms.
- Hot reload of the database files via `POST /reload` without restarting the server.
- Lightweight OpenAPI description available at `/openapi.json`.
- Optional localhost-only protection for admin-style endpoints (`/reload`, `/metrics`, `/openapi.json`).

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

### Optional security toggle (ADMIN_LOCAL_ONLY)
The admin-style endpoints (`/reload`, `/metrics`, `/openapi.json`) can be locked down to localhost if desired. Control this via the
`ADMIN_LOCAL_ONLY` environment variable at process start:

| Value accepted (case-insensitive) | Effect |
| --- | --- |
| `1` (also accepts `true/yes/on`) or unset | **Default.** Restrict admin endpoints to `127.0.0.1` / `::1`; remote clients receive `403`. |
| `0` (also accepts `false/no/off`) | Admin endpoints remain reachable from any client; the guard is bypassed without evaluating client IPs. |

Example:

```bash
# Enable localhost-only protection (default)
ADMIN_LOCAL_ONLY=1 cargo run

# Explicitly disable the guard
ADMIN_LOCAL_ONLY=0 cargo run
```

The flag is read once at startup; restart the service after changing the value.

**`nohup` example**

If you want to keep the process running in the background with stdout/stderr suppressed, set the flag the same way before the
command:

```bash
# Build the release binary first
cargo build --release

# Start with localhost-only protection enabled (default)
ADMIN_LOCAL_ONLY=1 nohup ./target/release/ipinfo > /dev/null 2>&1 &

# Start without restriction
ADMIN_LOCAL_ONLY=0 nohup ./target/release/ipinfo > /dev/null 2>&1 &
```

When enabled, the server rejects any admin request that includes a non-loopback `X-Forwarded-For` / `Forwarded` address before
checking the TCP peer; spoofed loopback headers do not bypass the peer check. Any non-loopback IPv4/IPv6 client receives HTTP 403
on admin endpoints.

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

If no requests have been processed yet, the endpoint returns `# No metrics recorded yet` to make it clear the exporter is run
ning.

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

