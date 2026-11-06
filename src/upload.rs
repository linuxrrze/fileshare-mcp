//! App-host endpoints: upload page, multipart/PUT upload, delete.

use std::time::{Duration, UNIX_EPOCH};

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Multipart, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post, put},
};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

use crate::{
    Config, Shared,
    store::{Created, DeleteError, Staging, UploadError, sanitize_path},
};

const INDEX_HTML: &str = include_str!("assets/index.html");

pub fn routes(state: Shared) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/upload", post(upload_multipart))
        .route("/api/upload/{*name}", put(upload_put))
        .route("/api/share/{token}", delete(delete_share))
        // Size is enforced while streaming against MAX_UPLOAD_SIZE instead.
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
    let max_entries = state.cfg.max_zip_entries;
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

fn parse_bool(v: &str) -> Option<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
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
    Query(q): Query<UploadQuery>,
    headers: HeaderMap,
    mut mp: Multipart,
) -> Response {
    if let Err(r) = check_upload_auth(&state.cfg, &headers) {
        return r;
    }
    let mut st = match state.store.begin(state.cfg.max_upload) {
        Ok(s) => s,
        Err(e) => return upload_error(e.into()),
    };
    let mut expires = q.expires.clone();
    let mut unpack = q.unpack.as_deref().and_then(parse_bool);

    let result: Result<(), UploadError> =
        async {
            while let Some(mut field) = mp
                .next_field()
                .await
                .map_err(|e| UploadError::Rejected(format!("bad multipart body: {e}")))?
            {
                match field.name().unwrap_or("") {
                    "expires" => expires = Some(field.text().await.unwrap_or_default()),
                    "unpack" => unpack = parse_bool(&field.text().await.unwrap_or_default()),
                    "file" | "files" | "file[]" => {
                        let raw = field.file_name().unwrap_or("").to_string();
                        let rel = sanitize_path(&raw).ok_or_else(|| {
                            UploadError::Rejected(format!("invalid file name {raw:?}"))
                        })?;
                        let dest = st.prepare(&rel)?;
                        let mut out = tokio::fs::File::create(&dest).await?;
                        let mut size = 0u64;
                        while let Some(chunk) = field.chunk().await.map_err(|e| {
                            UploadError::Rejected(format!("upload interrupted: {e}"))
                        })? {
                            st.charge(chunk.len() as u64)?;
                            out.write_all(&chunk).await?;
                            size += chunk.len() as u64;
                        }
                        out.flush().await?;
                        st.finish_file(&rel, size);
                    }
                    _ => {} // ignore unknown fields
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
            tracing::info!(token = %&c.token[..6], files = c.files.len(), "share created");
            respond(&state.cfg, &c, q.format.as_deref() == Some("text"))
        }
        Err(e) => upload_error(e),
    }
}

/// `PUT /api/upload/<name>` with the raw body (`curl -T file URL`).
/// Replies with just the URL unless `?format=json`.
async fn upload_put(
    State(state): State<Shared>,
    Path(name): Path<String>,
    Query(q): Query<UploadQuery>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    use futures_util::StreamExt;
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
    let mut st = match state.store.begin(state.cfg.max_upload) {
        Ok(s) => s,
        Err(e) => return upload_error(e.into()),
    };
    let result: Result<(), UploadError> = async {
        let dest = st.prepare(&rel)?;
        let mut out = tokio::fs::File::create(&dest).await?;
        let mut size = 0u64;
        let mut stream = body.into_data_stream();
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
            tracing::info!(token = %&c.token[..6], files = c.files.len(), "share created");
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

async fn index(State(state): State<Shared>) -> Html<String> {
    let cfg = &state.cfg;
    let conf = serde_json::json!({
        "tokenRequired": cfg.upload_token.is_some(),
        "defaultExpiry": cfg.default_expiry.as_secs(),
        "maxExpiry": cfg.max_expiry.as_secs(),
        "maxUpload": cfg.max_upload,
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

    #[test]
    fn bools() {
        assert_eq!(parse_bool("Yes"), Some(true));
        assert_eq!(parse_bool("0"), Some(false));
        assert_eq!(parse_bool("maybe"), None);
    }
}
