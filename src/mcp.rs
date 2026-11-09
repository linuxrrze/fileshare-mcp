//! MCP endpoint (`/mcp`, streamable HTTP) so agents can create, read and
//! delete shares without shelling out to curl.
//!
//! File content travels through the model's context here, so the tools say
//! so and point at the HTTP API for anything big.

use std::sync::Arc;

use axum::{
    Router,
    extract::{Request, State},
    http::{StatusCode, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use base64::Engine;
use rmcp::{
    ErrorData, ServerHandler,
    handler::server::{router::tool::ToolRouter, tool::Extension, wrapper::Parameters},
    model::{
        CallToolResult, ContentBlock, Implementation, ResourceContents, ServerCapabilities,
        ServerConfig,
    },
    schemars, tool, tool_handler, tool_router,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use serde::Deserialize;

use crate::{
    Shared,
    access::{Access, READ_ONLY_MSG},
    store::{UploadError, sanitize_path, valid_token},
    upload::{bearer, build_response, ct_eq, ttl},
};

const INSTRUCTIONS: &str = "Temporary file sharing. create_share uploads one or more files (text or \
base64) and returns an unguessable URL that expires: links are temporary, never permanent download links, \
so tell the user when they stop working (expires_at). HTML shares render in the browser and relative \
links between files of one share work (e.g. index.html + img/logo.png). Every byte passed through \
these tools goes through your context window: for large or binary files on disk prefer the HTTP API \
(`curl -T <file> <PUBLIC_URL>/api/upload/<name>` prints the URL).";

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct McpFile {
    #[schemars(
        description = "Relative path inside the share, e.g. `index.html` or `img/logo.png`"
    )]
    pub path: String,
    #[schemars(description = "File content as UTF-8 text (use this OR base64)")]
    pub text: Option<String>,
    #[schemars(description = "File content base64-encoded, for binary files (use this OR text)")]
    pub base64: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateShareArgs {
    #[schemars(
        description = "Files of the share. Put an `index.html` at the root to make the share URL open a page."
    )]
    pub files: Vec<McpFile>,
    #[schemars(
        description = "Lifetime like `30m`, `24h`, `7d` (default: server default, capped at server maximum); the share and its URL are gone afterwards"
    )]
    pub expires: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ShareRef {
    #[schemars(description = "Share URL (`.../s/<token>/...`) or the bare token")]
    pub share: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReadFileArgs {
    #[schemars(
        description = "File URL `.../s/<token>/<path>`, or a share URL/token together with `path`"
    )]
    pub url: String,
    #[schemars(description = "Path inside the share, if `url` is only the share URL or token")]
    pub path: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DeleteArgs {
    #[schemars(description = "Share URL or token")]
    pub share: String,
    #[schemars(description = "The delete_token returned by create_share")]
    pub delete_token: String,
}

/// `https://c.example/s/<token>/img/a.png` -> (token, Some("img/a.png"));
/// a bare token -> (token, None).
pub fn parse_share_ref(s: &str) -> Option<(String, Option<String>)> {
    let s = s.trim();
    let rest = match s.find("/s/") {
        Some(i) => &s[i + 3..],
        None => s,
    };
    let rest = rest.split(['?', '#']).next().unwrap_or("");
    let (token, path) = match rest.split_once('/') {
        Some((t, p)) => (t, Some(p)),
        None => (rest, None),
    };
    if !valid_token(token) {
        return None;
    }
    let path = path.filter(|p| !p.is_empty()).map(|p| {
        percent_encoding::percent_decode_str(p)
            .decode_utf8_lossy()
            .into_owned()
    });
    Some((token.to_string(), path))
}

fn err(msg: impl Into<String>) -> ErrorData {
    ErrorData::invalid_params(msg.into(), None)
}

/// Server-side failure: details go to the log, the client gets a generic
/// message (like the HTTP API's "storage error").
fn internal(what: &str, e: impl std::fmt::Display) -> ErrorData {
    tracing::error!("mcp {what}: {e}");
    ErrorData::internal_error(format!("{what} failed on the server (see its log)"), None)
}

/// The access decision of the HTTP request carrying this tool call (set by
/// `access::layer`); missing counts as read-only.
fn access(parts: &Parts) -> Access {
    parts.extensions.get::<Access>().copied().unwrap_or(Access {
        client: None,
        write: false,
    })
}

fn require_write(parts: &Parts) -> Result<Access, ErrorData> {
    let a = access(parts);
    if a.write {
        Ok(a)
    } else {
        tracing::debug!(client = %a, "mcp write refused: read-only client");
        Err(err(READ_ONLY_MSG))
    }
}

fn json_result(v: serde_json::Value) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(&v).unwrap_or_default(),
    )])
}

#[derive(Clone)]
pub struct FileShareMcp {
    state: Shared,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl FileShareMcp {
    pub fn new(state: Shared) -> Self {
        Self {
            state,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "Create a new share from one or more files and return its URL, \
expiry and delete_token. The link is temporary: it stops working at expires_at, so tell the \
user when it expires. HTML renders inline; relative links between files of the share work. \
Content passes through your context: use the HTTP API (curl) for large files. \
Refused for clients outside the server's WRITE_ALLOWED_NETS (read-only access)."
    )]
    async fn create_share(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(args): Parameters<CreateShareArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let client = require_write(&parts)?;
        let cfg = &self.state.cfg;
        if cfg.upload_token.is_some() && cfg.mcp_api_key.is_none() {
            // Don't let an open /mcp bypass a protected upload API.
            return Err(err(
                "uploads require UPLOAD_TOKEN; set MCP_API_KEY on the server to allow MCP uploads",
            ));
        }
        if args.files.is_empty() {
            return Err(err("files must not be empty"));
        }
        let ttl = ttl(cfg, args.expires.as_deref()).map_err(err)?;
        let mut decoded = Vec::with_capacity(args.files.len());
        for f in args.files {
            let rel =
                sanitize_path(&f.path).ok_or_else(|| err(format!("invalid path {:?}", f.path)))?;
            let data = match (f.text, f.base64) {
                (Some(t), None) => t.into_bytes(),
                (None, Some(b)) => base64::engine::general_purpose::STANDARD
                    .decode(b.trim())
                    .map_err(|e| err(format!("{rel}: invalid base64: {e}")))?,
                _ => {
                    return Err(err(format!(
                        "{rel}: give exactly one of `text` or `base64`"
                    )));
                }
            };
            decoded.push((rel, data));
        }
        let store = self.state.store.clone();
        let (max, max_files) = (cfg.max_upload, cfg.max_files);
        let created = tokio::task::spawn_blocking(move || {
            let mut st = store.begin(max, max_files)?;
            for (rel, data) in &decoded {
                if let Err(e) = st.put_bytes(rel, data) {
                    store.abort(st);
                    return Err(e);
                }
            }
            store.commit(st, ttl)
        })
        .await
        .map_err(|e| internal("create_share", e))?
        .map_err(|e| match e {
            UploadError::Io(io) => internal("create_share storage", io),
            other => err(other.to_string()),
        })?;
        tracing::info!(token = %&created.token[..6], files = created.files.len(), client = %client, "share created via MCP");
        let r = build_response(cfg, &created);
        Ok(json_result(serde_json::to_value(&r).unwrap_or_default()))
    }

    #[tool(description = "List the files of a share (path, size, mime type, URL) and its expiry.")]
    async fn list_share(
        &self,
        Parameters(args): Parameters<ShareRef>,
    ) -> Result<CallToolResult, ErrorData> {
        let (token, _) =
            parse_share_ref(&args.share).ok_or_else(|| err("not a share URL or token"))?;
        let meta = self
            .state
            .store
            .load(&token)
            .ok_or_else(|| err("share not found or expired"))?;
        let cfg = &self.state.cfg;
        let files: Vec<_> = meta
            .files
            .iter()
            .map(|f| serde_json::json!({"path": f.path, "size": f.size, "mime": f.mime, "url": cfg.file_url(&token, &f.path)}))
            .collect();
        Ok(json_result(serde_json::json!({
            "share_url": cfg.share_url(&token),
            "expires_at": humantime::format_rfc3339_seconds(std::time::UNIX_EPOCH + std::time::Duration::from_secs(meta.expires_at)).to_string(),
            "files": files,
        })))
    }

    #[tool(
        description = "Read one file of a share. Text comes back as text, images as image \
content, anything else as a base64 resource. Size-capped by the server (MCP_MAX_READ)."
    )]
    async fn read_file(
        &self,
        Parameters(args): Parameters<ReadFileArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let (token, url_path) =
            parse_share_ref(&args.url).ok_or_else(|| err("not a share URL or token"))?;
        let meta = self
            .state
            .store
            .load(&token)
            .ok_or_else(|| err("share not found or expired"))?;
        let path = match args.path.or(url_path) {
            Some(p) => p,
            None if meta.files.len() == 1 => meta.files[0].path.clone(),
            None if meta.find("index.html").is_some() => "index.html".into(),
            None => return Err(err("share has several files: give `path` (see list_share)")),
        };
        let rel = sanitize_path(&path).ok_or_else(|| err("invalid path"))?;
        let entry = meta
            .find(&rel)
            .ok_or_else(|| err(format!("no file {rel:?} in this share")))?;
        if entry.size > self.state.cfg.mcp_max_read {
            return Err(err(format!(
                "{rel} is {} bytes, above MCP_MAX_READ ({}); download it with curl: {}",
                entry.size,
                self.state.cfg.mcp_max_read,
                self.state.cfg.file_url(&token, &rel)
            )));
        }
        let data = tokio::fs::read(self.state.store.file_path(&token, &rel))
            .await
            .map_err(|e| internal("read_file", e))?;
        let mime = entry
            .mime
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        let uri = self.state.cfg.file_url(&token, &rel);
        let block = if mime.starts_with("image/") && mime != "image/svg+xml" {
            ContentBlock::image(
                base64::engine::general_purpose::STANDARD.encode(&data),
                mime,
            )
        } else {
            match String::from_utf8(data) {
                Ok(text) => {
                    ContentBlock::resource(ResourceContents::text(text, uri).with_mime_type(mime))
                }
                Err(e) => ContentBlock::resource(
                    ResourceContents::blob(
                        base64::engine::general_purpose::STANDARD.encode(e.as_bytes()),
                        uri,
                    )
                    .with_mime_type(mime),
                ),
            }
        };
        Ok(CallToolResult::success(vec![block]))
    }

    #[tool(description = "Delete a share immediately (needs the delete_token from create_share).")]
    async fn delete_share(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(args): Parameters<DeleteArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        require_write(&parts)?;
        let (token, _) =
            parse_share_ref(&args.share).ok_or_else(|| err("not a share URL or token"))?;
        match self.state.store.delete(&token, args.delete_token.trim()) {
            Ok(()) => Ok(CallToolResult::success(vec![ContentBlock::text("deleted")])),
            Err(crate::store::DeleteError::NotFound) => Err(err("share not found or expired")),
            Err(crate::store::DeleteError::Forbidden) => Err(err("wrong delete_token")),
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for FileShareMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("fileshare", env!("CARGO_PKG_VERSION")))
            .with_instructions(INSTRUCTIONS)
    }
}

/// Optional API key (`Authorization: Bearer` or `X-API-Key`), same
/// convention as the repo's mcp-gateway.
async fn mcp_auth(State(st): State<Shared>, req: Request, next: Next) -> Response {
    if let Some(want) = &st.cfg.mcp_api_key {
        let h = req.headers();
        let got = bearer(h).or_else(|| h.get("x-api-key").and_then(|v| v.to_str().ok()));
        if !got.is_some_and(|g| ct_eq(g, want)) {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Bearer")],
                "unauthorized\n",
            )
                .into_response();
        }
    }
    next.run(req).await
}

/// `https://share.example.de` -> `https://share.example.de:443`
fn origin_with_port(url: &str) -> Option<String> {
    let (scheme, default_port) = if url.starts_with("https://") {
        ("https", 443)
    } else if url.starts_with("http://") {
        ("http", 80)
    } else {
        return None;
    };
    let auth = crate::url_authority(url)?;
    Some(
        if auth
            .rsplit_once(':')
            .is_some_and(|(_, p)| p.chars().all(|c| c.is_ascii_digit()))
        {
            format!("{scheme}://{auth}")
        } else {
            format!("{scheme}://{auth}:{default_port}")
        },
    )
}

pub fn routes(state: Shared) -> Router {
    let cfg = &state.cfg;
    // Host allow-list (DNS rebinding): the app host, loopback, the bare host
    // without port, plus MCP_ALLOWED_HOSTS (e.g. a compose service name).
    let mut hosts = vec![
        cfg.public_host.clone(),
        "localhost".into(),
        "127.0.0.1".into(),
        "::1".into(),
    ];
    if let Some((h, _)) = cfg.public_host.rsplit_once(':') {
        hosts.push(h.to_string());
    }
    hosts.extend(cfg.mcp_allowed_hosts.iter().cloned());
    // Browsers always send Origin on cross-origin POSTs: only the app's own
    // origin may talk to /mcp from a browser -- in particular not uploaded
    // HTML on the content host.
    let origins: Vec<String> = origin_with_port(&cfg.public_url).into_iter().collect();
    let mcp_cfg = StreamableHttpServerConfig::default()
        .with_allowed_hosts(hosts)
        .with_allowed_origins(origins)
        .enforce_origin_validation()
        .with_max_request_body_bytes(cfg.mcp_max_body);
    let st = state.clone();
    let service: StreamableHttpService<FileShareMcp, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(FileShareMcp::new(st.clone())),
            Arc::new(LocalSessionManager::default()),
            mcp_cfg,
        );
    Router::new()
        .nest_service("/mcp", service)
        .layer(middleware::from_fn_with_state(state, mcp_auth))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_refs() {
        let t = "abcdefghijklmnopqrstuvwxyz";
        assert_eq!(parse_share_ref(t), Some((t.into(), None)));
        assert_eq!(
            parse_share_ref(&format!("https://c.example/s/{t}/img/a%20b.png?download=1")),
            Some((t.into(), Some("img/a b.png".into())))
        );
        assert_eq!(
            parse_share_ref(&format!("https://c.example/s/{t}/")),
            Some((t.into(), None))
        );
        assert_eq!(parse_share_ref("https://c.example/s/short/"), None);
    }

    #[test]
    fn origins() {
        assert_eq!(
            origin_with_port("https://a.example").as_deref(),
            Some("https://a.example:443")
        );
        assert_eq!(
            origin_with_port("http://a:8080/").as_deref(),
            Some("http://a:8080")
        );
    }
}
