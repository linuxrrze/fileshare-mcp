//! HTTP-level tests: requests go through the full router (Host routing,
//! upload API, content serving, MCP incl. auth) without opening a socket.

use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::{AppState, Config, Shared, app, store::Store, upload};

const APP: &str = "app.example";
const CONTENT: &str = "content.example";

pub fn state_with(dir: &std::path::Path, tweak: impl FnOnce(&mut Config)) -> Shared {
    let mut cfg = Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.to_string_lossy().into(),
        public_url: format!("https://{APP}"),
        content_url: format!("https://{CONTENT}"),
        public_host: APP.into(),
        content_host: CONTENT.into(),
        default_expiry: Duration::from_secs(3600),
        max_expiry: Duration::from_secs(86400),
        max_upload: 1 << 20,
        max_zip_entries: 100,
        upload_token: None,
        mcp_api_key: None,
        mcp_allowed_hosts: vec![],
        mcp_max_read: 1 << 20,
        mcp_max_body: 1 << 20,
        sweep_interval: Duration::from_secs(60),
    };
    tweak(&mut cfg);
    Arc::new(AppState {
        store: Store::new(dir).unwrap(),
        cfg,
    })
}

async fn send(app: &Router, req: Request<Body>) -> Response {
    app.clone().oneshot(req).await.unwrap()
}

async fn body_string(r: Response) -> String {
    String::from_utf8(to_bytes(r.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap()
}

fn get(host: &str, path: &str) -> Request<Body> {
    Request::get(path)
        .header(header::HOST, host)
        .body(Body::empty())
        .unwrap()
}

/// Absolute share/file URL -> path on the content host.
fn content_path(url: &str) -> String {
    url.strip_prefix(&format!("https://{CONTENT}"))
        .expect("content URL")
        .to_string()
}

fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut w = zip::ZipWriter::new(&mut buf);
        for (name, data) in entries {
            w.start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap();
    }
    buf.into_inner()
}

const BOUNDARY: &str = "fileshareTESTboundary";

/// multipart/form-data body from (field, filename, data) parts.
fn multipart(parts: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
    let mut b = Vec::new();
    for (name, filename, data) in parts {
        b.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
        match filename {
            Some(f) => b.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"{name}\"; filename=\"{f}\"\r\n\
                     Content-Type: application/octet-stream\r\n\r\n"
                )
                .as_bytes(),
            ),
            None => b.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
            ),
        }
        b.extend_from_slice(data);
        b.extend_from_slice(b"\r\n");
    }
    b.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    b
}

fn post_multipart(body: Vec<u8>, auth: Option<&str>) -> Request<Body> {
    let mut r = Request::post("/api/upload")
        .header(header::HOST, APP)
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        );
    if let Some(a) = auth {
        r = r.header(header::AUTHORIZATION, a);
    }
    r.body(Body::from(body)).unwrap()
}

fn put(name: &str, query: &str, data: &[u8]) -> Request<Body> {
    Request::put(format!("/api/upload/{name}{query}"))
        .header(header::HOST, APP)
        .body(Body::from(data.to_vec()))
        .unwrap()
}

// ---------------------------------------------------------------- routing

#[tokio::test]
async fn host_routing() {
    let tmp = tempfile::tempdir().unwrap();
    let st = state_with(tmp.path(), |_| {});
    let mut stg = st.store.begin(100).unwrap();
    stg.put_bytes("index.html", b"<h1>x</h1>").unwrap();
    let c = st.store.commit(stg, Duration::from_secs(60)).unwrap();
    let app = app(st);
    let share = format!("/s/{}/", c.token);

    let r = send(&app, get(CONTENT, &share)).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert!(
        r.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );

    let r = send(&app, get(APP, &share)).await;
    assert_eq!(r.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(
        r.headers()[header::LOCATION],
        format!("https://{CONTENT}{share}").as_str()
    );

    assert_eq!(
        send(&app, get(CONTENT, "/")).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(&app, get(CONTENT, "/mcp")).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(send(&app, get(APP, "/")).await.status(), StatusCode::OK);
    assert_eq!(
        send(&app, get(CONTENT, "/healthz")).await.status(),
        StatusCode::OK
    );
    let bogus = "/s/aaaaaaaaaaaaaaaaaaaaaaaaaa/";
    assert_eq!(
        send(&app, get(CONTENT, bogus)).await.status(),
        StatusCode::NOT_FOUND
    );
}

#[test]
fn ttl_clamped() {
    let tmp = tempfile::tempdir().unwrap();
    let st = state_with(tmp.path(), |_| {});
    assert_eq!(
        upload::ttl(&st.cfg, None).unwrap(),
        Duration::from_secs(3600)
    );
    assert_eq!(
        upload::ttl(&st.cfg, Some("30m")).unwrap(),
        Duration::from_secs(1800)
    );
    assert_eq!(
        upload::ttl(&st.cfg, Some("90d")).unwrap(),
        Duration::from_secs(86400)
    );
    assert!(upload::ttl(&st.cfg, Some("soon")).is_err());
    assert!(upload::ttl(&st.cfg, Some("0s")).is_err());
}

// ----------------------------------------------------------------- upload

#[tokio::test]
async fn put_upload_serve_and_delete() {
    let tmp = tempfile::tempdir().unwrap();
    let app = app(state_with(tmp.path(), |_| {}));

    let r = send(&app, put("note.txt", "?expires=1h", b"hallo")).await;
    assert_eq!(r.status(), StatusCode::OK);
    let delete_token = r.headers()["x-delete-token"].to_str().unwrap().to_string();
    let url = body_string(r).await.trim().to_string();
    assert!(url.ends_with("/note.txt"), "{url}");

    // served inline with the hardening headers
    let r = send(&app, get(CONTENT, &content_path(&url))).await;
    assert_eq!(r.status(), StatusCode::OK);
    let h = r.headers().clone();
    assert_eq!(h[header::CONTENT_TYPE], "text/plain; charset=utf-8");
    assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(h[header::REFERRER_POLICY], "no-referrer");
    assert!(h.get(header::CONTENT_DISPOSITION).is_none());
    assert_eq!(body_string(r).await, "hallo");

    // ?download=1 -> attachment
    let r = send(
        &app,
        get(CONTENT, &format!("{}?download=1", content_path(&url))),
    )
    .await;
    assert!(
        r.headers()[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .starts_with("attachment")
    );

    // delete: header required, wrong token refused, right token works
    let token = url.split("/s/").nth(1).unwrap().split('/').next().unwrap();
    let del = |t: Option<&str>| {
        let mut r = Request::delete(format!("/api/share/{token}")).header(header::HOST, APP);
        if let Some(t) = t {
            r = r.header("x-delete-token", t);
        }
        r.body(Body::empty()).unwrap()
    };
    assert_eq!(
        send(&app, del(None)).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        send(&app, del(Some("wrong"))).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(&app, del(Some(&delete_token))).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        send(&app, get(CONTENT, &content_path(&url))).await.status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn multipart_upload_with_paths_and_json_reply() {
    let tmp = tempfile::tempdir().unwrap();
    let app = app(state_with(tmp.path(), |_| {}));
    let body = multipart(&[
        ("expires", None, b"2h"),
        ("file", Some("index.html"), b"<img src=\"img/a.png\">"),
        ("file", Some("img/a.png"), b"PNG"),
    ]);
    let r = send(&app, post_multipart(body, None)).await;
    assert_eq!(r.status(), StatusCode::CREATED);
    let j: Value = serde_json::from_str(&body_string(r).await).unwrap();
    assert_eq!(
        j["url"], j["share_url"],
        "index.html share links to the root"
    );
    assert_eq!(j["files"].as_array().unwrap().len(), 2);
    let ttl = j["expires_at_unix"].as_u64().unwrap() - crate::store::now_secs();
    assert!((7100..=7200).contains(&ttl), "{ttl}");

    let root = content_path(j["share_url"].as_str().unwrap());
    let r = send(&app, get(CONTENT, &root)).await;
    assert_eq!(body_string(r).await, "<img src=\"img/a.png\">");
    let r = send(&app, get(CONTENT, &format!("{root}img/a.png"))).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()[header::CONTENT_TYPE], "image/png");
}

#[tokio::test]
async fn zip_site_is_unpacked_and_unsafe_names_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let app = app(state_with(tmp.path(), |_| {}));

    let z = zip_bytes(&[
        ("site/index.html", b"<h1>hi</h1>"),
        ("site/img/a.png", b"PNG"),
    ]);
    let r = send(&app, put("site.zip", "?format=json", &z)).await;
    assert_eq!(r.status(), StatusCode::CREATED);
    let j: Value = serde_json::from_str(&body_string(r).await).unwrap();
    let mut paths: Vec<_> = j["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap().to_string())
        .collect();
    paths.sort();
    assert_eq!(paths, ["img/a.png", "index.html"]);

    // unpack=0 keeps the archive as is
    let r = send(&app, put("site.zip", "?format=json&unpack=0", &z)).await;
    let j: Value = serde_json::from_str(&body_string(r).await).unwrap();
    assert_eq!(j["files"][0]["path"], "site.zip");

    let evil = zip_bytes(&[("../evil.txt", b"x")]);
    let r = send(&app, put("evil.zip", "", &evil)).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(!tmp.path().join("evil.txt").exists());

    // nothing half-written left behind by the failed upload
    let leftovers = std::fs::read_dir(tmp.path())
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp-"))
        .count();
    assert_eq!(leftovers, 0);
}

#[tokio::test]
async fn upload_size_limit() {
    let tmp = tempfile::tempdir().unwrap();
    let app = app(state_with(tmp.path(), |c| c.max_upload = 10));
    let r = send(&app, put("big.bin", "", &[0u8; 11])).await;
    assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let r = send(&app, put("ok.bin", "", &[0u8; 10])).await;
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
async fn upload_token_required_when_set() {
    let tmp = tempfile::tempdir().unwrap();
    let app = app(state_with(tmp.path(), |c| {
        c.upload_token = Some("up-secret".into())
    }));
    let body = || multipart(&[("file", Some("a.txt"), b"x")]);

    let r = send(&app, post_multipart(body(), None)).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let r = send(&app, post_multipart(body(), Some("Bearer wrong"))).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let r = send(&app, put("a.txt", "", b"x")).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let r = send(&app, post_multipart(body(), Some("Bearer up-secret"))).await;
    assert_eq!(r.status(), StatusCode::CREATED);

    // the page tells the browser to ask for the token
    let page = body_string(send(&app, get(APP, "/")).await).await;
    assert!(page.contains("\"tokenRequired\":true"));
}

// -------------------------------------------------------------------- MCP

/// Minimal streamable-HTTP MCP client over the in-process router.
struct Mcp {
    app: Router,
    auth: Vec<(&'static str, String)>,
    session: Option<String>,
    id: u64,
}

impl Mcp {
    fn new(app: &Router, auth: &[(&'static str, &str)]) -> Self {
        Self {
            app: app.clone(),
            auth: auth.iter().map(|(k, v)| (*k, v.to_string())).collect(),
            session: None,
            id: 0,
        }
    }

    fn request(&self, body: &Value, origin: Option<&str>) -> Request<Body> {
        let mut r = Request::post("/mcp")
            .header(header::HOST, APP)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("mcp-protocol-version", "2025-06-18");
        for (k, v) in &self.auth {
            r = r.header(*k, v);
        }
        if let Some(s) = &self.session {
            r = r.header("mcp-session-id", s);
        }
        if let Some(o) = origin {
            r = r.header(header::ORIGIN, o);
        }
        r.body(Body::from(body.to_string())).unwrap()
    }

    async fn raw(&self, body: &Value, origin: Option<&str>) -> Response {
        send(&self.app, self.request(body, origin)).await
    }

    /// JSON-RPC result/error object out of a JSON or SSE response.
    async fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.id += 1;
        let body = json!({"jsonrpc": "2.0", "id": self.id, "method": method, "params": params});
        let r = self.raw(&body, None).await;
        assert_eq!(r.status(), StatusCode::OK, "{method}");
        if let Some(s) = r.headers().get("mcp-session-id") {
            self.session = Some(s.to_str().unwrap().to_string());
        }
        let text = body_string(r).await;
        text.lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(str::trim)
            .chain(std::iter::once(text.trim()))
            .filter_map(|d| serde_json::from_str::<Value>(d).ok())
            .find(|v| v.get("id") == Some(&json!(self.id)))
            .unwrap_or_else(|| panic!("no JSON-RPC reply in {text:?}"))
    }

    async fn init(&mut self) {
        let r = self
            .rpc(
                "initialize",
                json!({"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "test", "version": "1"}}),
            )
            .await;
        assert_eq!(r["result"]["serverInfo"]["name"], "fileshare");
        let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        assert!(self.raw(&note, None).await.status().is_success());
    }

    async fn call(&mut self, tool: &str, args: Value) -> Value {
        self.rpc("tools/call", json!({"name": tool, "arguments": args}))
            .await
    }
}

fn tool_json(reply: &Value) -> Value {
    let text = reply["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no text content in {reply}"));
    serde_json::from_str(text).unwrap()
}

#[tokio::test]
async fn mcp_requires_api_key_when_set() {
    let tmp = tempfile::tempdir().unwrap();
    let app = app(state_with(tmp.path(), |c| {
        c.mcp_api_key = Some("k3y".into())
    }));
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "t", "version": "1"}}});

    for auth in [
        vec![],
        vec![("authorization", "Bearer wrong")],
        vec![("x-api-key", "wrong")],
        vec![("authorization", "k3y")], // scheme missing
    ] {
        let r = Mcp::new(&app, &auth).raw(&init, None).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{auth:?}");
        assert_eq!(r.headers()[header::WWW_AUTHENTICATE], "Bearer");
    }
    for auth in [
        [("authorization", "Bearer k3y")],
        [("authorization", "bearer k3y")],
        [("x-api-key", "k3y")],
    ] {
        let mut c = Mcp::new(&app, &auth);
        c.init().await;
        let tools = c.rpc("tools/list", json!({})).await;
        let mut names: Vec<_> = tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        names.sort();
        assert_eq!(
            names,
            ["create_share", "delete_share", "list_share", "read_file"]
        );
    }
}

#[tokio::test]
async fn mcp_rejects_foreign_origin_and_host() {
    let tmp = tempfile::tempdir().unwrap();
    let app = app(state_with(tmp.path(), |_| {}));
    let c = Mcp::new(&app, &[]);
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "t", "version": "1"}}});

    // uploaded HTML on the content host must not drive /mcp
    let r = c.raw(&init, Some(&format!("https://{CONTENT}"))).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = c.raw(&init, Some("https://evil.example")).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = c.raw(&init, Some(&format!("https://{APP}"))).await;
    assert_eq!(r.status(), StatusCode::OK);

    // DNS rebinding: unknown Host
    let mut req = c.request(&init, None);
    req.headers_mut()
        .insert(header::HOST, "attacker.example".parse().unwrap());
    assert_ne!(send(&app, req).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn mcp_create_read_list_delete_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let app = app(state_with(tmp.path(), |_| {}));
    let mut c = Mcp::new(&app, &[]);
    c.init().await;

    let created = tool_json(
        &c.call(
            "create_share",
            json!({"expires": "1h", "files": [
                {"path": "index.html", "text": "<h1>MCP</h1><img src=\"p.png\">"},
                {"path": "p.png", "base64": "iVBORw0KGgo="}
            ]}),
        )
        .await,
    );
    let share_url = created["share_url"].as_str().unwrap().to_string();
    let delete_token = created["delete_token"].as_str().unwrap().to_string();

    // the share is reachable over plain HTTP on the content host
    let r = send(&app, get(CONTENT, &content_path(&share_url))).await;
    assert_eq!(body_string(r).await, "<h1>MCP</h1><img src=\"p.png\">");

    // read_file: share URL alone resolves to index.html; images as image content
    let r = c.call("read_file", json!({"url": share_url})).await;
    assert_eq!(
        r["result"]["content"][0]["resource"]["text"],
        "<h1>MCP</h1><img src=\"p.png\">"
    );
    let r = c
        .call("read_file", json!({"url": format!("{share_url}p.png")}))
        .await;
    assert_eq!(r["result"]["content"][0]["type"], "image");
    assert_eq!(r["result"]["content"][0]["data"], "iVBORw0KGgo=");

    let listed = tool_json(&c.call("list_share", json!({"share": share_url})).await);
    assert_eq!(listed["files"].as_array().unwrap().len(), 2);

    // bad input is an error, not a crash
    let r = c
        .call(
            "create_share",
            json!({"files": [{"path": "../x", "text": "x"}]}),
        )
        .await;
    assert!(
        r.get("error").is_some() || r["result"]["isError"] == true,
        "{r}"
    );

    let r = c
        .call(
            "delete_share",
            json!({"share": share_url, "delete_token": "wrong"}),
        )
        .await;
    assert!(
        r.get("error").is_some() || r["result"]["isError"] == true,
        "{r}"
    );
    let r = c
        .call(
            "delete_share",
            json!({"share": share_url, "delete_token": delete_token}),
        )
        .await;
    assert_eq!(r["result"]["content"][0]["text"], "deleted");
    let r = send(&app, get(CONTENT, &content_path(&share_url))).await;
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mcp_upload_refused_when_upload_token_but_no_mcp_key() {
    let tmp = tempfile::tempdir().unwrap();
    let app = app(state_with(tmp.path(), |c| {
        c.upload_token = Some("up".into())
    }));
    let mut c = Mcp::new(&app, &[]);
    c.init().await;
    let r = c
        .call(
            "create_share",
            json!({"files": [{"path": "a.txt", "text": "x"}]}),
        )
        .await;
    assert!(
        r.get("error").is_some() || r["result"]["isError"] == true,
        "{r}"
    );
}
