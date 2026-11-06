# fileshare

Anonymous, temporary file sharing behind unguessable URLs. It's a single
static Rust binary with an upload page, a curl-friendly HTTP API and an MCP
endpoint for agents.

- **Anonymous upload** (optionally gated by `UPLOAD_TOKEN`).
- **Unguessable links.** Each share gets a 128-bit random token,
  `https://share-content.example.de/s/<26 chars>/`. Shares are never listed
  anywhere, so the token is the only way in.
- **Expiry.** Each upload asks for a lifetime (`30m` … `MAX_EXPIRY`). Expired
  shares return 404 right away and are deleted by a sweeper every
  `SWEEP_INTERVAL`.
- **HTML renders in the browser, and relative links work.** Upload a folder
  or a `.zip` with `index.html` + `img/logo.png`, and the share URL opens the
  page with its images. A single top-level folder in the zip is stripped.
- **MCP** (`/mcp`, streamable HTTP): `create_share`, `list_share`,
  `read_file`, `delete_share`.

Why not an existing tool: MicroBin's IDs come from a counter (guessable),
PsiTransfer always sends files as downloads, Firefox-Send forks are
download-only, and Gokapi, PicoShare and Zipline need a login to upload.

## Two hostnames

| Variable | Serves | Example |
| --- | --- | --- |
| `PUBLIC_URL` | upload page `/`, `/api/*`, `/mcp` | `https://share.example.de` |
| `CONTENT_URL` | only `/s/<token>/…` (the shared files) | `https://share-content.example.de` |

Anyone can upload HTML and JavaScript, and it runs in the visitor's browser.
On a separate origin it can't reach the upload page or `/mcp`. `/mcp` also
rejects any browser request whose `Origin` isn't `PUBLIC_URL`. The binary
routes on the `Host` header:

- `/s/…` on the app host redirects (308) to the content host.
- Everything except `/s/…` and `/healthz` returns 404 on the content host.

If both variables are set to the same URL, it runs in single-host mode and
logs a warning at startup. That's fine on a LAN, but not for a public
deployment.

Every shared file is also sent with `Content-Security-Policy: sandbox …`
(without `allow-same-origin`), so each page runs in its own opaque origin.
Scripts still work, but a malicious share can't:

- read another share's localStorage or IndexedDB
- set cookies for sibling hosts
- make requests that count as same-site to your other apps

Pages that rely on localStorage or cookies break under the sandbox. Set
`CONTENT_SANDBOX=false` only if you need them and trust the uploaders.
Because of the sandbox, the shared files also carry
`Access-Control-Allow-Origin: *`, so a page's own module scripts, `fetch()`es
and fonts load. Anyone who can send those requests already has the URL.

Ideally put `CONTENT_URL` on its own registrable domain, not a subdomain of
your homelab domain. With the sandbox on this matters much less.

## Usage

### Web
Open `PUBLIC_URL`, drop files or a folder, choose how long the link lasts,
then copy the link. The page can also delete the share again.

### curl
```sh
# one file -> prints the URL (delete token in the X-Delete-Token response header)
curl -T report.pdf https://share.example.de/api/upload/report.pdf
curl -T report.pdf "https://share.example.de/api/upload/report.pdf?expires=7d"

# multipart, several files / relative paths, JSON reply
curl -F file=@index.html -F "file=@logo.png;filename=img/logo.png" -F expires=24h \
     https://share.example.de/api/upload

# a whole HTML site: zip it, upload, open the printed share URL
(cd site && zip -r ../site.zip .) && curl -T site.zip https://share.example.de/api/upload/site.zip

# download / delete
curl -O https://share-content.example.de/s/<token>/report.pdf
curl -X DELETE -H "X-Delete-Token: <delete token>" https://share.example.de/api/share/<token>
```

| Endpoint | Notes |
| --- | --- |
| `POST /api/upload` | multipart. `file` (repeatable; the filename may contain `dir/x.png`), `expires`, `unpack`. Replies with JSON (`url`, `share_url`, `token`, `expires_at`, `delete_url`, `delete_token`, `files`); `?format=text` gives just the URL. |
| `PUT /api/upload/<name>` | Raw body. `?expires=` or `X-Expires:` header. Replies with the URL; `?format=json` gives the JSON. |
| `DELETE /api/share/<token>` | Header `X-Delete-Token`. |
| `GET /s/<token>/[path]` | Served inline, with the content type from the extension. `index.html` is served for directory URLs; a share without one shows a file list. `?download=1` forces a download. |
| `GET /healthz` | Liveness. |

`unpack` defaults to true when the upload is exactly one `.zip`. Pass
`unpack=0` to share the zip itself. Zip extraction:

- rejects `..` and absolute paths
- skips symlinks
- caps the entry count before the archive is parsed (at most 2 × `MAX_FILES`
  central-directory entries, so directory entries fit too)
- counts the *unpacked* size against `MAX_UPLOAD_SIZE`, so zip bombs stop at the limit

Every shared file is sent with `X-Content-Type-Options: nosniff`,
`X-Robots-Tag: noindex` and `Referrer-Policy: no-referrer`. The last one
stops the secret URL from leaking to third-party assets that an uploaded
page loads.

### Claude Code: MCP
```sh
claude mcp add --transport http fileshare https://share.example.de/mcp \
  --header "Authorization: Bearer <MCP_API_KEY>"     # omit if MCP_API_KEY is empty
# from a container on codingenv's network (MCP_ALLOWED_HOSTS=fileshare):
claude mcp add --transport http fileshare http://fileshare:8080/mcp
```
| Tool | Does |
| --- | --- |
| `create_share {files:[{path, text \| base64}], expires?}` | Creates a share and returns `url`, `share_url`, `delete_token` and `expires_at`. |
| `list_share {share}` | Lists the files (path, size, mime, URL) and the expiry. |
| `read_file {url, path?}` | Returns text as text, images as image content, and anything else as a base64 resource. Capped by `MCP_MAX_READ`. |
| `delete_share {share, delete_token}` | Deletes the share immediately. |

Everything sent through MCP passes through the model's context. For big or
binary files, have the agent use curl instead. A snippet for
`~/.claude/CLAUDE.md`:

```markdown
## Sharing files
To share a file, run `curl -sS -T <file> https://share.example.de/api/upload/<name>?expires=24h`;
it prints the URL. For an HTML page with assets, zip the folder and upload the .zip.
Small text/HTML can also go through the `fileshare` MCP tools.
```

If `UPLOAD_TOKEN` is set and `MCP_API_KEY` isn't, `create_share` refuses to
work, so an open `/mcp` can't get around the protected upload API.

### Limits against abuse

Uploads are anonymous by default, so every upload path is bounded:

- **Size:** file bytes count against `MAX_UPLOAD_SIZE` as they stream in,
  with zips counted unpacked.
- **Multipart:** text fields such as `expires` and `unpack`, and any unknown
  fields, are capped at 1 KiB. One part's header block is capped at 16 KiB.
  The number of parts is capped at `MAX_FILES` + 16.
- **File count and depth:** a share can hold at most `MAX_FILES` files on any
  upload path, and a path at most 32 directories deep.
- **Stalled uploads:** an upload that sends nothing for `UPLOAD_IDLE_TIMEOUT`
  is aborted and its staging directory removed.
- **Concurrency:** at most `MAX_CONCURRENT_UPLOADS` uploads run at once. The
  rest get `503` with `Retry-After`.

There is **no global disk quota and no per-client rate limit**. A public,
anonymous instance can be filled up with repeated uploads that last up to
`MAX_EXPIRY`. For anything reachable from the internet, either set
`UPLOAD_TOKEN`, or rate-limit `/api/upload` and `/mcp` at the proxy, and keep
`/data` on a filesystem whose filling up doesn't hurt other services.

## Reverse proxy

Route both hostnames to `fileshare:8080` (or `127.0.0.1:8080`). The proxy
must:

- **Pass the original `Host` header**, because routing depends on it (nginx:
  `proxy_set_header Host $host;`; Traefik does this by default).
- **Not limit the upload size** (`client_max_body_size 0;`). The binary
  enforces `MAX_UPLOAD_SIZE` while the upload streams in.
- **Turn request buffering off** (`proxy_request_buffering off;`), so large
  uploads stream instead of being spooled to the proxy's disk.
- **Leave `/mcp` unbuffered** (`proxy_buffering off;`). It uses SSE.

## Configuration

All settings are environment variables; see `.env.sample`.

| Variable | Default | Notes |
| --- | --- | --- |
| `PUBLIC_URL` / `CONTENT_URL` | `http://localhost:8080` / = `PUBLIC_URL` | See "Two hostnames". |
| `DEFAULT_EXPIRY` / `MAX_EXPIRY` | `24h` / `30d` | Longer requested lifetimes are clamped to `MAX_EXPIRY`. |
| `MAX_UPLOAD_SIZE` | `1G` | Per upload, after unpacking. |
| `MAX_FILES` | `10000` | Files per share, on every upload path. `MAX_ZIP_ENTRIES`, the 0.1.0 name, is still read. |
| `UPLOAD_IDLE_TIMEOUT` | `60s` | Aborts an upload that sends no data for this long. |
| `MAX_CONCURRENT_UPLOADS` | `16` | Further uploads get `503`. |
| `CONTENT_SANDBOX` | `true` | Serves shares with a CSP sandbox (see "Two hostnames"). |
| `SWEEP_INTERVAL` | `5m` | |
| `UPLOAD_TOKEN` | empty (anonymous) | If set, uploads need `Authorization: Bearer …`. The web page then asks for it. |
| `MCP_API_KEY` | empty (open) | If set, `/mcp` needs `Authorization: Bearer …` or `X-API-Key`. `.env.sample` ships the placeholder `CHANGE_ME`; fileshare refuses to start while any secret still contains it (in any letter case). |
| `MCP_ALLOWED_HOSTS` | | Extra `Host` values accepted on `/mcp`. The `PUBLIC_URL` host and loopback are always allowed. |
| `MCP_MAX_READ` / `MCP_MAX_BODY` | `5M` / `32M` | |
| `BIND` / `DATA_DIR` | `0.0.0.0:8080` / `/data` | |
| `LOG_LEVEL` | `info` | `tracing` env-filter syntax. |

Storage is one directory per share in `/data`:

- `meta.json` holds the expiry, the file list and a sha256 of the delete token.
- `files/` holds the shared files.

An upload is staged in `.tmp-<token>/` and renamed only once it's complete.
There's no database, so a backup is just the directory.

## Development

`cargo test` runs the unit tests and HTTP-level tests (`src/http_tests.rs`),
which drive the full router in-process:

- Host routing and redirects
- PUT, multipart and zip uploads
- size limit, upload token, delete
- MCP: 401 without the key; Bearer and `X-API-Key` accepted; foreign
  `Origin`/`Host` refused; a `create_share` → `read_file` → `delete_share`
  round trip
- abuse limits: oversized text fields and part headers, file count on
  every path, zip entry pre-count, stalled uploads, concurrent uploads
- content sandbox headers

The Docker build runs the same suite before compiling the release binary,
so a failing test stops CI before anything is pushed.

```sh
cd fileshare
cargo test
PUBLIC_URL=http://app.localhost:8080 CONTENT_URL=http://content.localhost:8080 \
  DATA_DIR=/tmp/fs-data cargo run
```

## Files

| File | Used by CI? | Purpose |
| --- | --- | --- |
| `Cargo.toml` / `Cargo.lock` | yes | Crate and pinned dependencies. `version` is the image tag. Run `cargo update` to pick up crate fixes, then commit the lock file. |
| `src/` | yes | `main.rs` (config, Host routing, sweeper, `healthcheck` subcommand), `http_tests.rs` (HTTP-level tests), `store.rs` (tokens, staging, zip, expiry), `upload.rs` (app-host API and page), `serve.rs` (content host), `mcp.rs` (MCP tools), `assets/index.html`. |
| `Dockerfile` | yes | `rust:alpine` runs `cargo test`, then `cargo auditable` builds a static musl binary, which goes onto `busybox:musl`. busybox rather than scratch because the startup banner needs `/bin/sh`. |
| `.fileshare-base-digest` | yes | Registry digest of the busybox base the last build used. Updated automatically by CI. |
| `.env.sample` | no | Runtime settings template. Real tokens go only in the local, gitignored `.env`. |
| `docker-compose.yml.sample` | no | Template for the gitignored `docker-compose.yml`. |

## Build & version tracking

`.gitea/workflows/fileshare-rebuild.yml` is the repo's first workflow that
builds source living in this repo (Flavor 2 plus the base-digest check).

- **Triggers:** a push touching `src/`, `Cargo.*`, `Dockerfile` or the
  workflow rebuilds. A daily check rebuilds only when the busybox base is
  re-published.
- **Tags:** `:<Cargo version>`, `:<version>-<YYYYMMDD>` (for rollback) and
  `:latest`.
- **Trivy:** scans the crates that `cargo auditable` embeds in the binary.
  Accept findings in `.trivyignore`, with a reason for each.
