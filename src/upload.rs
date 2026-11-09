//! App-host endpoints: upload page, multipart/PUT upload, delete.

use std::{
    io,
    time::{Duration, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Extension, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post, put},
};
use futures_util::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncWriteExt, sync::OwnedSemaphorePermit};

use crate::{
    Config, Shared,
    access::Access,
    store::{Created, DeleteError, Staging, UploadError, sanitize_path},
};

const INDEX_HTML: &str = include_str!("assets/index.html");

pub fn routes(state: Shared) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/upload", post(upload_multipart))
        .route("/api/upload/{*name}", put(upload_put))
        .route("/api/share/{token}", delete(delete_share))
        // Size is enforced while streaming (MAX_UPLOAD_SIZE for file data,
        // multer limits for everything else) instead.
        .layer(DefaultBodyLimit::disable())
        .with_state(state)
}

/// Constant-time string comparison for secrets.
pub fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn bearer(headers: &HeaderMap) -> Option<&str> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, tok) = v.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| tok.trim())
}

#[allow(clippy::result_large_err)] // only on the cold rejection path
fn check_upload_auth(cfg: &Config, headers: &HeaderMap) -> Result<(), Response> {
    match &cfg.upload_token {
        None => Ok(()),
        Some(want) if bearer(headers).is_some_and(|t| ct_eq(t, want)) => Ok(()),
        Some(_) => Err((
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "upload token required\n",
        )
            .into_response()),
    }
}

/// Requested lifetime: default when absent, clamped to MAX_EXPIRY.
pub fn ttl(cfg: &Config, requested: Option<&str>) -> Result<Duration, String> {
    let Some(r) = requested.map(str::trim).filter(|r| !r.is_empty()) else {
        return Ok(cfg.default_expiry);
    };
    let d = humantime::parse_duration(r)
        .map_err(|e| format!("expires={r:?}: {e} (use e.g. 30m, 24h, 7d)"))?;
    if d.is_zero() {
        return Err("expires must be > 0".into());
    }
    Ok(d.min(cfg.max_expiry))
}

#[derive(Serialize)]
pub struct FileOut {
    pub path: String,
    pub size: u64,
    pub mime: String,
    pub url: String,
}

#[derive(Serialize)]
pub struct UploadResponse {
    /// Best link to hand out: the file itself for a single non-HTML-site
    /// upload, otherwise the share root.
    pub url: String,
    pub share_url: String,
    pub token: String,
    pub expires_at: String,
    pub expires_at_unix: u64,
    pub delete_url: String,
    pub delete_token: String,
    pub files: Vec<FileOut>,
}

pub fn build_response(cfg: &Config, c: &Created) -> UploadResponse {
    let share_url = cfg.share_url(&c.token);
    let url = match c.files.as_slice() {
        [only] if only.path != "index.html" => cfg.file_url(&c.token, &only.path),
        _ => share_url.clone(),
    };
    UploadResponse {
        url,
        share_url,
        token: c.token.clone(),
        expires_at: humantime::format_rfc3339_seconds(
            UNIX_EPOCH + Duration::from_secs(c.expires_at),
        )
        .to_string(),
        expires_at_unix: c.expires_at,
        delete_url: format!("{}/api/share/{}", cfg.public_url, c.token),
        delete_token: c.delete_token.clone(),
        files: c
            .files
            .iter()
            .map(|f| FileOut {
                path: f.path.clone(),
                size: f.size,
                mime: f.mime.clone(),
                url: cfg.file_url(&c.token, &f.path),
            })
            .collect(),
    }
}

fn upload_error(e: UploadError) -> Response {
    match e {
        UploadError::Rejected(m) => (StatusCode::BAD_REQUEST, format!("{m}\n")).into_response(),
        UploadError::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, format!("{e}\n")).into_response(),
        UploadError::Io(err) => {
            tracing::error!("upload storage error: {err}");
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error\n").into_response()
        }
    }
}

/// Unpack (explicit or auto: exactly one staged file and it's a .zip), then
/// commit. Runs the blocking zip/fs work off the async runtime.
async fn finish(
    state: &Shared,
    mut st: Staging,
    unpack: Option<bool>,
    ttl: Duration,
) -> Result<Created, UploadError> {
    let zips: Vec<String> = st
        .paths()
        .filter(|p| p.to_ascii_lowercase().ends_with(".zip"))
        .cloned()
        .collect();
    let unpack = unpack.unwrap_or(st.file_count() == 1 && zips.len() == 1);
    let store = state.store.clone();
    // Regular files are capped by max_files in Staging; allow as many
    // directory entries on top.
    let max_entries = state.cfg.max_files.saturating_mul(2);
    tokio::task::spawn_blocking(move || {
        if unpack {
            for z in &zips {
                if let Err(e) = st.unpack_zip(z, max_entries) {
                    store.abort(st);
                    return Err(e);
                }
            }
        }
        store.commit(st, ttl)
    })
    .await
    .map_err(|e| UploadError::Io(std::io::Error::other(e)))?
}

pub fn parse_bool(v: &str) -> Option<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Max bytes of one multipart part's header block (Content-Disposition etc.).
const MAX_PART_HEADER: u64 = 16 * 1024;
/// Max bytes of a non-file multipart field (`expires`, `unpack`, unknown).
const MAX_TEXT_FIELD: u64 = 1024;
/// Non-file parts allowed besides the files.
const EXTRA_PARTS: usize = 16;

#[allow(clippy::result_large_err)] // only on the cold rejection path
fn upload_slot(state: &Shared) -> Result<OwnedSemaphorePermit, Response> {
    state.upload_slots.clone().try_acquire_owned().map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, "10")],
            "too many uploads in progress, try again shortly\n",
        )
            .into_response()
    })
}

/// The request body as a stream that fails when no data arrives for
/// `idle` (slow-drip uploads would otherwise hold a task, a socket and a
/// staging dir forever).
fn idle_timeout(
    body: Body,
    idle: Duration,
) -> impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static {
    futures_util::stream::unfold(Some(body.into_data_stream()), move |s| async move {
        let mut s = s?;
        match tokio::time::timeout(idle, s.next()).await {
            Err(_) => Some((
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("no data for {}", humantime::format_duration(idle)),
                )),
                None,
            )),
            Ok(None) => None,
            Ok(Some(Ok(b))) => Some((Ok(b), Some(s))),
            Ok(Some(Err(e))) => Some((Err(io::Error::other(e)), None)),
        }
    })
}

/// Watches a multipart stream and fails when one part's header block grows
/// past `MAX_PART_HEADER`. multer buffers (and re-scans) a header block
/// until its terminating blank line, with no size limit of its own.
///
/// Tracks only boundaries and blank lines: after each `\r\n--<boundary>`
/// the header block runs to the next `\r\n\r\n`.
struct HeaderGuard {
    delim: memchr::memmem::Finder<'static>,
    blank: memchr::memmem::Finder<'static>,
    keep: usize,
    in_headers: bool,
    header_start: u64,
    /// Stream offset of `tail[0]`.
    offset: u64,
    /// Unscanned end of the previous chunk (a match may straddle chunks).
    tail: Vec<u8>,
}

impl HeaderGuard {
    fn new(boundary: &str) -> Self {
        let delim = format!("\r\n--{boundary}").into_bytes();
        let keep = delim.len().max(4) - 1;
        HeaderGuard {
            delim: memchr::memmem::Finder::new(&delim).into_owned(),
            blank: memchr::memmem::Finder::new(b"\r\n\r\n").into_owned(),
            keep,
            in_headers: false,
            header_start: 0,
            offset: 0,
            // The body starts with `--<boundary>`: a virtual leading CRLF
            // lets the first delimiter match like the others.
            tail: b"\r\n".to_vec(),
        }
    }

    fn feed(&mut self, chunk: &[u8]) -> Result<(), io::Error> {
        let mut buf = std::mem::take(&mut self.tail);
        buf.extend_from_slice(chunk);
        let base = self.offset;
        let too_big = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("multipart part headers exceed {MAX_PART_HEADER} bytes"),
            )
        };
        let mut pos = 0;
        loop {
            if self.in_headers {
                match self.blank.find(&buf[pos..]) {
                    Some(i) => {
                        pos += i + 4;
                        if base + pos as u64 - self.header_start > MAX_PART_HEADER {
                            return Err(too_big());
                        }
                        self.in_headers = false;
                    }
                    None => {
                        if base + buf.len() as u64 - self.header_start > MAX_PART_HEADER {
                            return Err(too_big());
                        }
                        break;
                    }
                }
            } else {
                match self.delim.find(&buf[pos..]) {
                    Some(i) => {
                        pos += i + self.delim.needle().len();
                        self.in_headers = true;
                        self.header_start = base + pos as u64;
                    }
                    None => break,
                }
            }
        }
        let from = pos.max(buf.len().saturating_sub(self.keep));
        self.offset = base + from as u64;
        self.tail = buf.split_off(from);
        Ok(())
    }
}

fn multipart_error(e: multer::Error) -> UploadError {
    use multer::Error as E;
    match e {
        E::StreamSizeExceeded { .. } => UploadError::TooLarge,
        E::FieldSizeExceeded { field_name, .. } => UploadError::Rejected(format!(
            "multipart field {:?} too large",
            field_name.unwrap_or_default()
        )),
        E::StreamReadFailed(e) => UploadError::Rejected(format!("upload interrupted: {e}")),
        other => UploadError::Rejected(format!("bad multipart body: {other}")),
    }
}

#[derive(Deserialize, Default)]
pub struct UploadQuery {
    expires: Option<String>,
    unpack: Option<String>,
    format: Option<String>,
}

fn respond(cfg: &Config, c: &Created, text: bool) -> Response {
    let r = build_response(cfg, c);
    if text {
        let mut resp = format!("{}\n", r.url).into_response();
        if let Ok(v) = HeaderValue::from_str(&r.delete_token) {
            resp.headers_mut().insert("x-delete-token", v);
        }
        if let Ok(v) = HeaderValue::from_str(&r.expires_at) {
            resp.headers_mut().insert("x-expires-at", v);
        }
        resp
    } else {
        (StatusCode::CREATED, Json(r)).into_response()
    }
}

/// `POST /api/upload` (multipart): `file` (repeatable; filename may carry a
/// relative path), optional `expires`, `unpack`. JSON reply, `?format=text`
/// for just the URL.
async fn upload_multipart(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
    Query(q): Query<UploadQuery>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Err(r) = check_upload_auth(&state.cfg, &headers) {
        return r;
    }
    let boundary = match headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(multer::parse_boundary)
    {
        Some(Ok(b)) => b,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "expected Content-Type: multipart/form-data with a boundary\n",
            )
                .into_response();
        }
    };
    let _slot = match upload_slot(&state) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let cfg = &state.cfg;
    let max_parts = cfg.max_files.saturating_add(EXTRA_PARTS);
    // File bytes are capped by the quota (charge); this bounds the rest:
    // part headers and small fields, for at most `max_parts` parts.
    let whole = cfg
        .max_upload
        .saturating_add(max_parts as u64 * (MAX_PART_HEADER + MAX_TEXT_FIELD + 64));
    let limits = multer::SizeLimit::new()
        .whole_stream(whole)
        .per_field(MAX_TEXT_FIELD)
        .for_field("file", cfg.max_upload)
        .for_field("files", cfg.max_upload)
        .for_field("file[]", cfg.max_upload);
    let mut guard = HeaderGuard::new(&boundary);
    let stream = idle_timeout(body, cfg.upload_idle_timeout).map(move |chunk| {
        let chunk = chunk?;
        guard.feed(&chunk)?;
        Ok::<_, io::Error>(chunk)
    });
    let mut mp = multer::Multipart::with_constraints(
        stream,
        boundary,
        multer::Constraints::new().size_limit(limits),
    );

    let mut st = match state.store.begin(cfg.max_upload, cfg.max_files) {
        Ok(s) => s,
        Err(e) => return upload_error(e.into()),
    };
    let mut expires = q.expires.clone();
    let mut unpack = q.unpack.as_deref().and_then(parse_bool);

    let result: Result<(), UploadError> = async {
        let mut parts = 0usize;
        while let Some(mut field) = mp.next_field().await.map_err(multipart_error)? {
            parts += 1;
            if parts > max_parts {
                return Err(UploadError::Rejected(format!(
                    "too many multipart parts (limit {max_parts})"
                )));
            }
            match field.name().unwrap_or("") {
                "expires" => expires = Some(field.text().await.map_err(multipart_error)?),
                "unpack" => unpack = parse_bool(&field.text().await.map_err(multipart_error)?),
                "file" | "files" | "file[]" => {
                    let raw = field.file_name().unwrap_or("").to_string();
                    let rel = sanitize_path(&raw).ok_or_else(|| {
                        UploadError::Rejected(format!("invalid file name {raw:?}"))
                    })?;
                    let dest = st.prepare(&rel)?;
                    let mut out = tokio::fs::File::create(&dest).await?;
                    let mut size = 0u64;
                    while let Some(chunk) = field.chunk().await.map_err(multipart_error)? {
                        st.charge(chunk.len() as u64)?;
                        out.write_all(&chunk).await?;
                        size += chunk.len() as u64;
                    }
                    out.flush().await?;
                    st.finish_file(&rel, size);
                }
                // Unknown fields are skipped (multer drains them, capped
                // at MAX_TEXT_FIELD).
                _ => {}
            }
        }
        Ok(())
    }
    .await;
    if let Err(e) = result {
        state.store.abort(st);
        return upload_error(e);
    }
    let ttl = match ttl(&state.cfg, expires.as_deref()) {
        Ok(t) => t,
        Err(m) => {
            state.store.abort(st);
            return (StatusCode::BAD_REQUEST, format!("{m}\n")).into_response();
        }
    };
    match finish(&state, st, unpack, ttl).await {
        Ok(c) => {
            tracing::info!(token = %&c.token[..6], files = c.files.len(), client = %access, "share created");
            respond(&state.cfg, &c, q.format.as_deref() == Some("text"))
        }
        Err(e) => upload_error(e),
    }
}

/// `PUT /api/upload/<name>` with the raw body (`curl -T file URL`).
/// Replies with just the URL unless `?format=json`.
async fn upload_put(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
    Path(name): Path<String>,
    Query(q): Query<UploadQuery>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Err(r) = check_upload_auth(&state.cfg, &headers) {
        return r;
    }
    let Some(rel) = sanitize_path(&name) else {
        return (StatusCode::BAD_REQUEST, "invalid file name\n").into_response();
    };
    let expires = q.expires.clone().or_else(|| {
        headers
            .get("x-expires")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    });
    let ttl = match ttl(&state.cfg, expires.as_deref()) {
        Ok(t) => t,
        Err(m) => return (StatusCode::BAD_REQUEST, format!("{m}\n")).into_response(),
    };
    let _slot = match upload_slot(&state) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let mut st = match state.store.begin(state.cfg.max_upload, state.cfg.max_files) {
        Ok(s) => s,
        Err(e) => return upload_error(e.into()),
    };
    let result: Result<(), UploadError> = async {
        let dest = st.prepare(&rel)?;
        let mut out = tokio::fs::File::create(&dest).await?;
        let mut size = 0u64;
        let mut stream = std::pin::pin!(idle_timeout(body, state.cfg.upload_idle_timeout));
        while let Some(chunk) = stream.next().await {
            let chunk =
                chunk.map_err(|e| UploadError::Rejected(format!("upload interrupted: {e}")))?;
            st.charge(chunk.len() as u64)?;
            out.write_all(&chunk).await?;
            size += chunk.len() as u64;
        }
        out.flush().await?;
        st.finish_file(&rel, size);
        Ok(())
    }
    .await;
    if let Err(e) = result {
        state.store.abort(st);
        return upload_error(e);
    }
    let unpack = q.unpack.as_deref().and_then(parse_bool);
    match finish(&state, st, unpack, ttl).await {
        Ok(c) => {
            tracing::info!(token = %&c.token[..6], files = c.files.len(), client = %access, "share created");
            respond(&state.cfg, &c, q.format.as_deref() != Some("json"))
        }
        Err(e) => upload_error(e),
    }
}

/// `DELETE /api/share/<token>` with `X-Delete-Token`.
async fn delete_share(
    State(state): State<Shared>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(dt) = headers.get("x-delete-token").and_then(|v| v.to_str().ok()) else {
        return (StatusCode::BAD_REQUEST, "X-Delete-Token header required\n").into_response();
    };
    match state.store.delete(&token, dt) {
        Ok(()) => (StatusCode::OK, "deleted\n").into_response(),
        Err(DeleteError::NotFound) => (StatusCode::NOT_FOUND, "not found\n").into_response(),
        Err(DeleteError::Forbidden) => {
            (StatusCode::FORBIDDEN, "wrong delete token\n").into_response()
        }
    }
}

async fn index(State(state): State<Shared>, Extension(access): Extension<Access>) -> Html<String> {
    let cfg = &state.cfg;
    let conf = serde_json::json!({
        "uploadAllowed": access.write,
        "tokenRequired": cfg.upload_token.is_some(),
        "defaultExpiry": cfg.default_expiry.as_secs(),
        "maxExpiry": cfg.max_expiry.as_secs(),
        "maxUpload": cfg.max_upload,
        // Single host and no sandbox: shared pages could read a stored token.
        "persistToken": cfg.split_hosts() || cfg.content_sandbox,
        "version": env!("CARGO_PKG_VERSION"),
    });
    Html(INDEX_HTML.replace("/*CONFIG*/{}", &conf.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eq() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "abcd"));
    }

    fn guard_feed(chunks: &[&[u8]]) -> Result<(), io::Error> {
        let mut g = HeaderGuard::new("B");
        chunks.iter().try_for_each(|c| g.feed(c))
    }

    #[test]
    fn header_guard() {
        let ok = b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nvalue\r\n--B--\r\n";
        assert!(guard_feed(&[ok]).is_ok());
        // byte-by-byte: matches straddling chunks are still found
        let bytes: Vec<&[u8]> = ok.chunks(1).collect();
        assert!(guard_feed(&bytes).is_ok());
        // big part *data* is fine ...
        let mut big = b"--B\r\nX: y\r\n\r\n".to_vec();
        big.extend(std::iter::repeat_n(b'x', 100_000));
        big.extend_from_slice(b"\r\n--B--\r\n");
        assert!(guard_feed(&[&big]).is_ok());
        // ... a header block that never ends is not, even in small chunks
        let mut hdr = b"--B\r\nX: ".to_vec();
        hdr.extend(std::iter::repeat_n(b'h', 20_000));
        let small: Vec<&[u8]> = hdr.chunks(100).collect();
        assert!(guard_feed(&small).is_err());
    }

    #[test]
    fn bools() {
        assert_eq!(parse_bool("Yes"), Some(true));
        assert_eq!(parse_bool("0"), Some(false));
        assert_eq!(parse_bool("maybe"), None);
    }
}
