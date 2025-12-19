use std::{env, io::ErrorKind, net::SocketAddr, path::PathBuf, time::Duration};

use dotenvy::dotenv;
use tracing::warn;

use crate::AppError;

#[derive(Clone)]
pub struct AppConfig {
    pub address: SocketAddr,
    pub storage_dir: PathBuf,
    pub ttl: Duration,
    pub cleanup_interval: Duration,
    pub max_downloads: u32,
    pub url_prefix: Option<String>,
    pub upload_page_enabled: bool,
    pub upload_password: String,
    pub use_filename_suffix: bool,
    pub upload_debug_logs: bool,
    pub max_upload_bytes: usize,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, AppError> {
        let address = env::var("ADDRESS").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

        let storage_dir = env::var("STORAGE_DIR").unwrap_or_else(|_| "data".to_string());

        let ttl = env::var("DEFAULT_TTL_MINS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|minutes| minutes.saturating_mul(60))
            .map(Duration::from_secs)
            .unwrap_or_else(|| Duration::from_secs(60 * 60));

        let cleanup_interval = env::var("CLEANUP_INTERVAL_MINS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|minutes| minutes.saturating_mul(60))
            .map(Duration::from_secs)
            .unwrap_or_else(|| Duration::from_secs(60));

        let max_downloads = env::var("MAX_DOWNLOADS")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(3);

        let url_prefix = env::var("URL_PREFIX")
            .ok()
            .map(|prefix| prefix.trim_end_matches('/').to_string())
            .filter(|prefix| !prefix.is_empty());

        let upload_page_enabled = env::var("UPLOAD_PAGE_ENABLED")
            .ok()
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(true);

        let upload_password =
            env::var("UPLOAD_PASSWORD").unwrap_or_else(|_| "changeme".to_string());

        let use_filename_suffix = env::var("USE_FILENAME_SUFFIX")
            .ok()
            .map(|v| !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);

        let upload_debug_logs = env::var("UPLOAD_DEBUG_LOGS")
            .ok()
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let max_upload_bytes = env::var("MAX_UPLOAD_GB")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|gb| gb.saturating_mul(1024 * 1024 * 1024))
            .unwrap_or(1024 * 1024 * 1024) as usize;

        Ok(Self {
            address: address.parse().unwrap_or_else(|err| {
                warn!(%err, "invalid ADDRESS value, falling back to default");
                SocketAddr::from(([0, 0, 0, 0], 8080))
            }),
            storage_dir: PathBuf::from(storage_dir),
            ttl,
            cleanup_interval,
            max_downloads,
            url_prefix,
            upload_page_enabled,
            upload_password,
            use_filename_suffix,
            upload_debug_logs,
            max_upload_bytes,
        })
    }

    pub fn build_download_url(&self, id: &str) -> String {
        if let Some(prefix) = &self.url_prefix {
            format!("{}/d/{}", prefix, id)
        } else {
            format!("/d/{}", id)
        }
    }
}

pub fn load_env_file() {
    if let Err(err) = dotenv() {
        if !matches!(err, dotenvy::Error::Io(ref io_err) if io_err.kind() == ErrorKind::NotFound) {
            warn!(%err, "failed to load .env file");
        }
    }
}
