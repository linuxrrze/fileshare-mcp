//! Content host: `/s/<token>/<path>` served inline, so HTML renders and its
//! relative links (images, css, js) resolve inside the same share.

use std::time::{Duration, UNIX_EPOCH};

use axum::{
    Router,
    body::Body,
    extract::{Path, Request, State},
    http::{HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use tower::ServiceExt;
use tower_http::services::ServeFile;

use crate::{
    Shared,
    store::{Meta, sanitize_path},
};

/// Everything but unreserved characters gets encoded inside a path segment.
const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

pub fn encode_path(p: &str) -> String {
    p.split('/')
        .map(|s| utf8_percent_encode(s, SEGMENT).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

pub fn routes(state: Shared) -> Router {
    Router::new()
        .route("/s/{token}", get(share_no_slash))
        .route("/s/{token}/", get(share_root))
        .route("/s/{token}/{*path}", get(share_file))
        .with_state(state)
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found (or expired)\n").into_response()
}

async fn share_no_slash(Path(token): Path<String>) -> Response {
    // Relative links in index.html need the trailing slash.
    Redirect::permanent(&format!("/s/{token}/")).into_response()
}

async fn share_root(State(st): State<Shared>, Path(token): Path<String>, req: Request) -> Response {
    serve(&st, &token, "", req).await
}

async fn share_file(
    State(st): State<Shared>,
    Path((token, path)): Path<(String, String)>,
    req: Request,
) -> Response {
    serve(&st, &token, &path, req).await
}

async fn serve(st: &Shared, token: &str, path: &str, req: Request) -> Response {
    let Some(meta) = st.store.load(token) else {
        return not_found();
    };
    let dir_request = path.is_empty() || path.ends_with('/');
    let rel = if dir_request {
        let index = format!("{path}index.html");
        if meta.find(&index).is_some() {
            index
        } else if path.is_empty() {
            return listing(st, token, &meta);
        } else {
            return not_found();
        }
    } else {
        let Some(rel) = sanitize_path(path) else {
            return not_found();
        };
        if meta.find(&rel).is_none() {
            // `docs` -> `docs/` when the share has docs/index.html
            if meta.find(&format!("{rel}/index.html")).is_some() {
                let last = rel.rsplit('/').next().unwrap_or(&rel);
                return Redirect::permanent(&format!("{}/", encode_path(last))).into_response();
            }
            return not_found();
        }
        rel
    };
    let entry = meta.find(&rel).expect("checked above").clone();
    let download = req.uri().query().is_some_and(|q| {
        q.split('&')
            .any(|kv| kv == "download" || kv == "download=1")
    });

    let fs_path = st.store.file_path(token, &rel);
    let mut resp = match ServeFile::new(fs_path).oneshot(req).await {
        Ok(r) => r.map(Body::new),
        Err(_) => return not_found(),
    };
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&entry.mime) {
        h.insert(header::CONTENT_TYPE, v);
    }
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    // Don't leak the share URL (= the secret) to third-party assets/links.
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        "x-robots-tag",
        HeaderValue::from_static("noindex, nofollow"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=60"),
    );
    if st.cfg.content_sandbox {
        sandbox(h);
        // A sandboxed page has an opaque origin, so its own module scripts,
        // fetch()es and web fonts are cross-origin requests. Anyone who can
        // send them already holds the URL (= the secret); no credentials.
        h.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
    }
    if download {
        let name = rel.rsplit('/').next().unwrap_or(&rel);
        let v = format!(
            "attachment; filename*=UTF-8''{}",
            utf8_percent_encode(name, SEGMENT)
        );
        if let Ok(v) = HeaderValue::from_str(&v) {
            h.insert(header::CONTENT_DISPOSITION, v);
        }
    }
    resp
}

/// Every shared page runs in its own opaque origin: scripts work, but it
/// can't read other shares' storage or set cookies for sibling hosts, and
/// its requests aren't same-site to them.
const SANDBOX_CSP: &str = "sandbox allow-scripts allow-forms allow-popups \
allow-popups-to-escape-sandbox allow-modals allow-downloads";

fn sandbox(h: &mut axum::http::HeaderMap) {
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(SANDBOX_CSP),
    );
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn human(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

/// Listing of a share without index.html. The token is the secret, so
/// listing a share's own files to whoever holds it is fine.
fn listing(st: &Shared, _token: &str, meta: &Meta) -> Response {
    let expires =
        humantime::format_rfc3339_seconds(UNIX_EPOCH + Duration::from_secs(meta.expires_at));
    let mut rows = String::new();
    for f in &meta.files {
        let href = encode_path(&f.path);
        rows.push_str(&format!(
            "<tr><td><a href=\"{href}\">{name}</a></td><td class=n>{size}</td><td><a href=\"{href}?download=1\">download</a></td></tr>\n",
            name = esc(&f.path),
            size = human(f.size),
        ));
    }
    let body = format!(
        r#"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<meta name=robots content="noindex,nofollow"><title>Shared files</title>
<style>
:root{{color-scheme:light dark;--fg:#1d1d1f;--bg:#fff;--muted:#6e6e73;--line:#d2d2d7;--link:#0b63c5}}
@media (prefers-color-scheme:dark){{:root{{--fg:#f5f5f7;--bg:#161617;--muted:#a1a1a6;--line:#3a3a3c;--link:#5aa9ff}}}}
body{{font:15px/1.5 system-ui,sans-serif;color:var(--fg);background:var(--bg);margin:0 auto;max-width:860px;padding:24px 16px}}
h1{{font-size:20px;margin:0 0 4px}}p{{color:var(--muted);margin:0 0 20px}}
table{{width:100%;border-collapse:collapse}}td{{padding:8px 6px;border-bottom:1px solid var(--line);word-break:break-all}}
td.n{{white-space:nowrap;color:var(--muted);text-align:right}}a{{color:var(--link)}}
</style></head><body><h1>Shared files</h1><p>{count} file(s) &middot; expires {expires} UTC</p>
<table>{rows}</table></body></html>"#,
        count = meta.files.len(),
    );
    let mut r = Html(body).into_response();
    let h = r.headers_mut();
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        "x-robots-tag",
        HeaderValue::from_static("noindex, nofollow"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-cache"),
    );
    if st.cfg.content_sandbox {
        sandbox(h);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode() {
        assert_eq!(encode_path("a b/ü?.png"), "a%20b/%C3%BC%3F.png");
        assert_eq!(encode_path("img/a-b_c.~x"), "img/a-b_c.~x");
    }

    #[test]
    fn sizes() {
        assert_eq!(human(10), "10 B");
        assert_eq!(human(1536), "1.5 KiB");
    }
}
