//! fileshare -- anonymous, expiring file shares behind unguessable URLs,
//! with an MCP endpoint. See README.md.

#[cfg(test)]
mod http_tests;
mod mcp;
mod serve;
mod store;
mod upload;

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
};

use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};

use store::Store;

pub struct Config {
    pub bind: SocketAddr,
    pub data_dir: String,
    /// App origin (upload page, API, MCP), no trailing slash.
    pub public_url: String,
    /// Content origin serving `/s/<token>/...`, no trailing slash.
    pub content_url: String,
    pub public_host: String,
    pub content_host: String,
    pub default_expiry: Duration,
    pub max_expiry: Duration,
    pub max_upload: u64,
    pub max_zip_entries: usize,
    pub upload_token: Option<String>,
    pub mcp_api_key: Option<String>,
    pub mcp_allowed_hosts: Vec<String>,
    pub mcp_max_read: u64,
    pub mcp_max_body: usize,
    pub sweep_interval: Duration,
}

impl Config {
    /// Two hostnames configured: content and app are separate origins.
    pub fn split_hosts(&self) -> bool {
        self.public_host != self.content_host
    }
    pub fn share_url(&self, token: &str) -> String {
        format!("{}/s/{token}/", self.content_url)
    }
    pub fn file_url(&self, token: &str, path: &str) -> String {
        format!(
            "{}/s/{token}/{}",
            self.content_url,
            serve::encode_path(path)
        )
    }

    fn from_env() -> Result<Self, String> {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        let dur = |k: &str, d: &str| -> Result<Duration, String> {
            let v = var(k).unwrap_or_else(|| d.into());
            humantime::parse_duration(&v).map_err(|e| format!("{k}={v}: {e}"))
        };
        let num = |k: &str, d: u64| -> Result<u64, String> {
            match var(k) {
                None => Ok(d),
                Some(v) => parse_size(&v).ok_or_else(|| format!("{k}={v}: not a size")),
            }
        };
        let bind: SocketAddr = var("BIND")
            .unwrap_or_else(|| "0.0.0.0:8080".into())
            .parse()
            .map_err(|e| format!("BIND: {e}"))?;
        let public_url = var("PUBLIC_URL")
            .unwrap_or_else(|| format!("http://localhost:{}", bind.port()))
            .trim_end_matches('/')
            .to_string();
        let content_url = var("CONTENT_URL")
            .unwrap_or_else(|| public_url.clone())
            .trim_end_matches('/')
            .to_string();
        let public_host =
            url_authority(&public_url).ok_or("PUBLIC_URL must be http(s)://host[:port]")?;
        let content_host =
            url_authority(&content_url).ok_or("CONTENT_URL must be http(s)://host[:port]")?;
        let max_expiry = dur("MAX_EXPIRY", "30d")?;
        Ok(Config {
            bind,
            data_dir: var("DATA_DIR").unwrap_or_else(|| "/data".into()),
            public_url,
            content_url,
            public_host,
            content_host,
            default_expiry: dur("DEFAULT_EXPIRY", "24h")?.min(max_expiry),
            max_expiry,
            max_upload: num("MAX_UPLOAD_SIZE", 1 << 30)?,
            max_zip_entries: num("MAX_ZIP_ENTRIES", 10_000)? as usize,
            upload_token: secret(var("UPLOAD_TOKEN"), "UPLOAD_TOKEN")?,
            mcp_api_key: secret(var("MCP_API_KEY"), "MCP_API_KEY")?,
            mcp_allowed_hosts: var("MCP_ALLOWED_HOSTS")
                .map(|v| {
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            mcp_max_read: num("MCP_MAX_READ", 5 << 20)?,
            mcp_max_body: num("MCP_MAX_BODY", 32 << 20)? as usize,
            sweep_interval: dur("SWEEP_INTERVAL", "5m")?,
        })
    }
}

/// Placeholder value shipped in .env.sample: refuse to start with it, so a
/// copied-but-unedited .env can't run with a publicly known key.
pub const PLACEHOLDER: &str = "CHANGE_ME";

fn secret(v: Option<String>, name: &str) -> Result<Option<String>, String> {
    match v {
        Some(v) if v.contains(PLACEHOLDER) => Err(format!(
            "{name} is still the .env.sample placeholder -- set a real value \
             (e.g. `openssl rand -hex 32`) or leave it empty to disable"
        )),
        other => Ok(other),
    }
}

/// `https://Host.Example:8443/x` -> `host.example:8443`
pub fn url_authority(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let auth = rest.split('/').next()?.to_ascii_lowercase();
    (!auth.is_empty()).then_some(auth)
}

/// `1G`, `500M`, `64k`, `1048576` (binary multiples).
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mult) = match s.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        None => (s, 1u64),
        Some((i, _)) => {
            let m = match s[i..]
                .trim()
                .to_ascii_lowercase()
                .trim_end_matches("ib")
                .trim_end_matches('b')
            {
                "" => 1,
                "k" => 1 << 10,
                "m" => 1 << 20,
                "g" => 1 << 30,
                "t" => 1 << 40,
                _ => return None,
            };
            (&s[..i], m)
        }
    };
    num.parse::<u64>().ok()?.checked_mul(mult)
}

pub struct AppState {
    pub cfg: Config,
    pub store: Store,
}

pub type Shared = Arc<AppState>;

fn request_host(headers: &HeaderMap) -> String {
    headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// Route by Host: the content host serves only `/s/...`; on the app host
/// `/s/...` redirects to the content host. Single-host mode serves both.
async fn host_guard(State(st): State<Shared>, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    if path == "/healthz" || !st.cfg.split_hosts() {
        return next.run(req).await;
    }
    let is_share = path.starts_with("/s/");
    let on_content = request_host(req.headers()) == st.cfg.content_host;
    match (on_content, is_share) {
        (true, false) => (StatusCode::NOT_FOUND, "not found\n").into_response(),
        (false, true) => {
            let pq = req
                .uri()
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or(path);
            Redirect::permanent(&format!("{}{pq}", st.cfg.content_url)).into_response()
        }
        _ => next.run(req).await,
    }
}

pub fn app(state: Shared) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .merge(upload::routes(state.clone()))
        .merge(serve::routes(state.clone()))
        .merge(mcp::routes(state.clone()))
        .layer(middleware::from_fn_with_state(state.clone(), host_guard))
        .layer(tower_http::trace::TraceLayer::new_for_http())
}

/// `fileshare healthcheck`: GET /healthz on the local port (for Docker's
/// HEALTHCHECK -- the image has no curl/wget we want to rely on).
fn healthcheck() -> ! {
    let port = std::env::var("BIND")
        .ok()
        .and_then(|b| b.parse::<SocketAddr>().ok())
        .map(|a| a.port())
        .unwrap_or(8080);
    let ok = (|| -> std::io::Result<bool> {
        let mut s = TcpStream::connect(("127.0.0.1", port))?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        s.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
        let mut buf = [0u8; 32];
        let n = s.read(&mut buf)?;
        Ok(std::str::from_utf8(&buf[..n])
            .is_ok_and(|l| l.starts_with("HTTP/1.") && l[8..].trim_start().starts_with("200")))
    })()
    .unwrap_or(false);
    std::process::exit(if ok { 0 } else { 1 })
}

#[tokio::main]
async fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("healthcheck") => healthcheck(),
        Some("--version" | "-V") => {
            println!("fileshare {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Some(other) => {
            eprintln!("usage: fileshare [healthcheck|--version]  (unknown argument {other:?})");
            std::process::exit(2);
        }
        None => {}
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("LOG_LEVEL")
                .unwrap_or_else(|_| "info,tower_http=warn".into()),
        )
        .init();

    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fileshare: configuration error: {e}");
            std::process::exit(2);
        }
    };
    let store = Store::new(&cfg.data_dir).unwrap_or_else(|e| {
        eprintln!("fileshare: cannot use DATA_DIR {}: {e}", cfg.data_dir);
        std::process::exit(1);
    });
    if !cfg.split_hosts() {
        tracing::warn!(
            "PUBLIC_URL and CONTENT_URL share one host: uploaded HTML runs on the same origin as the \
             upload page and /mcp. Set CONTENT_URL to a separate hostname for public deployments."
        );
    }
    if cfg.upload_token.is_none() {
        tracing::info!("UPLOAD_TOKEN unset: anonymous uploads enabled");
    }
    if cfg.mcp_api_key.is_none() {
        tracing::info!("MCP_API_KEY unset: /mcp is unauthenticated");
    }
    tracing::info!(
        "fileshare {} listening on {} (app {}, content {})",
        env!("CARGO_PKG_VERSION"),
        cfg.bind,
        cfg.public_url,
        cfg.content_url
    );

    let state = Arc::new(AppState { cfg, store });

    // expiry sweeper
    {
        let st = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(st.cfg.sweep_interval);
            loop {
                tick.tick().await;
                let store = st.store.clone();
                if let Ok(n) = tokio::task::spawn_blocking(move || store.sweep()).await
                    && n > 0
                {
                    tracing::info!("sweep: removed {n} expired share(s)");
                }
            }
        });
    }

    let listener = tokio::net::TcpListener::bind(state.cfg.bind)
        .await
        .unwrap_or_else(|e| {
            eprintln!("fileshare: bind {}: {e}", state.cfg.bind);
            std::process::exit(1);
        });
    let app = app(state);
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = term.recv() => {},
            }
        })
        .await
        .expect("server error");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority() {
        assert_eq!(
            url_authority("https://Share.Example.de/").as_deref(),
            Some("share.example.de")
        );
        assert_eq!(url_authority("http://a:8080/x").as_deref(), Some("a:8080"));
        assert_eq!(url_authority("ftp://a"), None);
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_size("1G"), Some(1 << 30));
        assert_eq!(parse_size("500M"), Some(500 << 20));
        assert_eq!(parse_size("64KiB"), Some(64 << 10));
        assert_eq!(parse_size("123"), Some(123));
        assert_eq!(parse_size("12X"), None);
    }

    #[test]
    fn placeholder_secret_rejected() {
        assert!(secret(Some("CHANGE_ME".into()), "MCP_API_KEY").is_err());
        assert!(secret(Some("CHANGE_ME-to-a-random-key".into()), "MCP_API_KEY").is_err());
        assert_eq!(
            secret(Some("s3cret".into()), "X").unwrap().as_deref(),
            Some("s3cret")
        );
        assert_eq!(secret(None, "X").unwrap(), None);
    }
}
