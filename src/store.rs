//! On-disk share storage.
//!
//! Layout under the data directory:
//!   <token>/meta.json        share metadata (expiry, file list, delete-token hash)
//!   <token>/files/<path>     the shared files
//!   .tmp-<token>/            a share being uploaded; renamed to <token> on commit,
//!                            so a half-written share is never reachable
//!
//! The token is the only secret protecting a share: 128 random bits from a
//! CSPRNG, base32 (lowercase, no padding) = 26 characters.

use std::{
    collections::BTreeMap,
    fs, io,
    io::{Read, Write},
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const TOKEN_LEN: usize = 26;
const TMP_PREFIX: &str = ".tmp-";
/// Max length of one stored path (bytes) and of one path component.
const MAX_PATH_LEN: usize = 1024;
const MAX_COMPONENT_LEN: usize = 255;
/// Max directory depth of one stored path (`a/b/c` = 3).
const MAX_DEPTH: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub mime: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub created: u64,
    pub expires_at: u64,
    pub delete_token_hash: String,
    pub files: Vec<FileEntry>,
}

impl Meta {
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }
    pub fn find(&self, path: &str) -> Option<&FileEntry> {
        self.files.iter().find(|f| f.path == path)
    }
}

/// Result of a committed upload, returned to the uploader only.
#[derive(Debug, Clone)]
pub struct Created {
    pub token: String,
    pub delete_token: String,
    pub expires_at: u64,
    pub files: Vec<FileEntry>,
}

#[derive(Debug)]
pub enum UploadError {
    /// Client error (bad path, too large, broken zip ...) -> HTTP 400/413.
    Rejected(String),
    TooLarge,
    Io(io::Error),
}

impl From<io::Error> for UploadError {
    fn from(e: io::Error) -> Self {
        UploadError::Io(e)
    }
}

impl std::fmt::Display for UploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UploadError::Rejected(m) => write!(f, "{m}"),
            UploadError::TooLarge => write!(f, "upload exceeds the size limit"),
            UploadError::Io(e) => write!(f, "storage error: {e}"),
        }
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random_token() -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    data_encoding::BASE32_NOPAD
        .encode(&bytes)
        .to_ascii_lowercase()
}

pub fn valid_token(s: &str) -> bool {
    s.len() == TOKEN_LEN && s.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
}

fn hash_hex(s: &str) -> String {
    let d = Sha256::digest(s.as_bytes());
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Normalise a client-supplied relative path (`dir/sub/x.png`).
///
/// Empty and `.` components are dropped; `..`, backslashes, NUL/control
/// characters and over-long names are rejected. A leading `/` is rejected
/// rather than silently stripped, so absolute paths never sneak through.
pub fn sanitize_path(p: &str) -> Option<String> {
    if p.is_empty() || p.starts_with('/') || p.contains('\\') || p.len() > MAX_PATH_LEN {
        return None;
    }
    if p.chars().any(|c| c.is_control()) {
        return None;
    }
    let mut parts = Vec::new();
    for c in p.split('/') {
        match c {
            "" | "." => continue,
            ".." => return None,
            c if c.len() > MAX_COMPONENT_LEN => return None,
            c => parts.push(c),
        }
    }
    if parts.is_empty() || parts.len() > MAX_DEPTH {
        return None;
    }
    Some(parts.join("/"))
}

pub fn mime_for(path: &str) -> String {
    let m = mime_guess::from_path(path).first_or_octet_stream();
    let essence = m.essence_str().to_string();
    let texty = m.type_() == mime_guess::mime::TEXT
        || matches!(
            essence.as_str(),
            "application/javascript" | "application/json" | "application/xml" | "image/svg+xml"
        );
    if texty {
        format!("{essence}; charset=utf-8")
    } else {
        essence
    }
}

/// A share being uploaded (lives in `.tmp-<token>/` until committed).
pub struct Staging {
    pub token: String,
    dir: PathBuf,
    /// path -> size; later uploads of the same path replace earlier ones.
    files: BTreeMap<String, u64>,
    total: u64,
    max_total: u64,
    /// Max number of files in the share (every upload path, incl. zips).
    max_files: usize,
}

impl Staging {
    pub fn total(&self) -> u64 {
        self.total
    }
    pub fn file_count(&self) -> usize {
        self.files.len()
    }
    pub fn paths(&self) -> impl Iterator<Item = &String> {
        self.files.keys()
    }
    /// Path inside the staging dir for `rel` (already sanitised); creates parents.
    /// Fails once the share would hold more than `max_files` files.
    pub fn prepare(&mut self, rel: &str) -> Result<PathBuf, UploadError> {
        if !self.files.contains_key(rel) && self.files.len() >= self.max_files {
            return Err(UploadError::Rejected(format!(
                "too many files (limit {})",
                self.max_files
            )));
        }
        let dest = self.dir.join("files").join(rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        // Replacing an already-staged file frees its quota.
        if let Some(old) = self.files.remove(rel) {
            self.total -= old;
        }
        Ok(dest)
    }
    /// Account for `n` more bytes; errors once the total limit is exceeded.
    pub fn charge(&mut self, n: u64) -> Result<(), UploadError> {
        self.total += n;
        if self.total > self.max_total {
            Err(UploadError::TooLarge)
        } else {
            Ok(())
        }
    }
    pub fn finish_file(&mut self, rel: &str, size: u64) {
        self.files.insert(rel.to_string(), size);
    }
    /// Write a whole in-memory file (MCP uploads).
    pub fn put_bytes(&mut self, rel: &str, data: &[u8]) -> Result<(), UploadError> {
        let dest = self.prepare(rel)?;
        self.charge(data.len() as u64)?;
        fs::write(&dest, data)?;
        self.finish_file(rel, data.len() as u64);
        Ok(())
    }

    /// Replace the staged zip `rel` by its extracted contents.
    ///
    /// Guards: zip-slip (absolute / `..` names via `sanitize_path`), symlinks
    /// skipped, entry count capped, total *uncompressed* bytes counted against
    /// the same quota as the upload (zip bombs stop at the limit). If every
    /// file sits under one common top-level directory (`site/index.html`,
    /// `site/img/a.png`), that directory is stripped so the share root is the
    /// site root.
    pub fn unpack_zip(&mut self, rel: &str, max_entries: usize) -> Result<(), UploadError> {
        let zip_path = self.dir.join("files").join(rel);
        let zip_size = self.files.remove(rel).unwrap_or(0);
        self.total -= zip_size;

        // ZipArchive::new parses the whole central directory into memory, so
        // the entry cap has to hold *before* that: count the central-directory
        // header signatures in the file (each parsed entry needs one; stray
        // matches in compressed data only make this stricter).
        let headers = count_central_headers(&zip_path, max_entries)?;
        if headers > max_entries {
            return Err(UploadError::Rejected(format!(
                "{rel}: zip has more than {max_entries} entries"
            )));
        }

        let file = fs::File::open(&zip_path)?;
        let mut archive = zip::ZipArchive::new(io::BufReader::new(file))
            .map_err(|e| UploadError::Rejected(format!("{rel}: not a valid zip file ({e})")))?;
        if archive.len() > max_entries {
            return Err(UploadError::Rejected(format!(
                "{rel}: zip has {} entries (limit {max_entries})",
                archive.len()
            )));
        }

        // Pass 1: collect the names of regular files.
        let mut names: Vec<(usize, String)> = Vec::new();
        for i in 0..archive.len() {
            let entry = archive
                .by_index(i)
                .map_err(|e| UploadError::Rejected(format!("{rel}: {e}")))?;
            if entry.is_dir() || entry.is_symlink() {
                continue;
            }
            let raw = entry
                .name()
                .map_err(|e| UploadError::Rejected(format!("{rel}: bad entry name ({e})")))?
                .to_string();
            if raw.starts_with("__MACOSX/") || raw.ends_with("/.DS_Store") || raw == ".DS_Store" {
                continue;
            }
            let Some(clean) = sanitize_path(&raw) else {
                return Err(UploadError::Rejected(format!(
                    "{rel}: unsafe path in zip: {raw:?}"
                )));
            };
            names.push((i, clean));
        }
        if names.is_empty() {
            return Err(UploadError::Rejected(format!(
                "{rel}: zip contains no files"
            )));
        }
        let strip = common_top_dir(names.iter().map(|(_, n)| n.as_str()));

        // The zip itself is removed before extracting, so a member with the
        // same name as the archive can't collide with it.
        fs::remove_file(&zip_path)?;

        // Pass 2: extract with a hard byte limit.
        for (i, name) in names {
            let name = match &strip {
                Some(prefix) => name[prefix.len() + 1..].to_string(),
                None => name,
            };
            let mut entry = archive
                .by_index(i)
                .map_err(|e| UploadError::Rejected(format!("{rel}: {e}")))?;
            let dest = self.prepare(&name)?;
            let mut out = fs::File::create(&dest)?;
            let mut written = 0u64;
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = entry
                    .read(&mut buf)
                    .map_err(|e| UploadError::Rejected(format!("{rel}: {name}: {e}")))?;
                if n == 0 {
                    break;
                }
                self.charge(n as u64)?;
                out.write_all(&buf[..n])?;
                written += n as u64;
            }
            self.finish_file(&name, written);
        }
        Ok(())
    }
}

/// Number of zip central-directory header signatures (`PK\x01\x02`) in the
/// file, streaming with constant memory; stops counting past `stop_after`.
fn count_central_headers(path: &std::path::Path, stop_after: usize) -> io::Result<usize> {
    const SIG: &[u8; 4] = b"PK\x01\x02";
    let finder = memchr::memmem::Finder::new(SIG);
    let mut f = fs::File::open(path)?;
    let mut buf = vec![0u8; 1 << 20];
    let mut carry = 0usize; // bytes kept from the previous read (< SIG.len())
    let mut count = 0usize;
    loop {
        let n = f.read(&mut buf[carry..])?;
        if n == 0 {
            return Ok(count);
        }
        let end = carry + n;
        count += finder.find_iter(&buf[..end]).count();
        if count > stop_after {
            return Ok(count);
        }
        // Keep the last SIG.len()-1 bytes: a signature split across reads
        // is found next time, a complete one is never counted twice.
        let keep = end.min(SIG.len() - 1);
        buf.copy_within(end - keep..end, 0);
        carry = keep;
    }
}

/// `Some("site")` if every path is `site/...`, else None.
fn common_top_dir<'a>(mut names: impl Iterator<Item = &'a str>) -> Option<String> {
    let first = names.next()?;
    let (top, _) = first.split_once('/')?;
    for n in names {
        match n.split_once('/') {
            Some((t, _)) if t == top => {}
            _ => return None,
        }
    }
    Some(top.to_string())
}

#[derive(Debug, PartialEq)]
pub enum DeleteError {
    NotFound,
    Forbidden,
}

#[derive(Clone)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn begin(&self, max_total: u64, max_files: usize) -> io::Result<Staging> {
        let token = random_token();
        let dir = self.root.join(format!("{TMP_PREFIX}{token}"));
        fs::create_dir_all(dir.join("files"))?;
        Ok(Staging {
            token,
            dir,
            files: BTreeMap::new(),
            total: 0,
            max_total,
            max_files,
        })
    }

    pub fn abort(&self, st: Staging) {
        let _ = fs::remove_dir_all(&st.dir);
    }

    pub fn commit(&self, st: Staging, ttl: Duration) -> Result<Created, UploadError> {
        if st.files.is_empty() {
            self.abort(st);
            return Err(UploadError::Rejected("no files uploaded".into()));
        }
        let delete_token = random_token();
        let now = now_secs();
        let files: Vec<FileEntry> = st
            .files
            .iter()
            .map(|(path, size)| FileEntry {
                path: path.clone(),
                size: *size,
                mime: mime_for(path),
            })
            .collect();
        let meta = Meta {
            created: now,
            expires_at: now + ttl.as_secs().max(1),
            delete_token_hash: hash_hex(&delete_token),
            files: files.clone(),
        };
        let write = (|| -> io::Result<()> {
            fs::write(st.dir.join("meta.json"), serde_json::to_vec_pretty(&meta)?)?;
            fs::rename(&st.dir, self.root.join(&st.token))
        })();
        if let Err(e) = write {
            let _ = fs::remove_dir_all(&st.dir);
            return Err(e.into());
        }
        Ok(Created {
            token: st.token,
            delete_token,
            expires_at: meta.expires_at,
            files,
        })
    }

    /// Metadata of a live share; None for malformed, unknown or expired tokens
    /// (all indistinguishable to the caller).
    pub fn load(&self, token: &str) -> Option<Meta> {
        if !valid_token(token) {
            return None;
        }
        let raw = fs::read(self.root.join(token).join("meta.json")).ok()?;
        let meta: Meta = serde_json::from_slice(&raw).ok()?;
        (!meta.is_expired(now_secs())).then_some(meta)
    }

    /// Filesystem path of `rel` in share `token`. Callers must have checked
    /// that `rel` is listed in the share's metadata.
    pub fn file_path(&self, token: &str, rel: &str) -> PathBuf {
        self.root.join(token).join("files").join(rel)
    }

    pub fn delete(&self, token: &str, delete_token: &str) -> Result<(), DeleteError> {
        let meta = self.load(token).ok_or(DeleteError::NotFound)?;
        if hash_hex(delete_token) != meta.delete_token_hash {
            return Err(DeleteError::Forbidden);
        }
        fs::remove_dir_all(self.root.join(token)).map_err(|_| DeleteError::NotFound)
    }

    /// Remove expired shares and abandoned uploads. Returns the number removed.
    pub fn sweep(&self) -> usize {
        let now = now_secs();
        let Ok(rd) = fs::read_dir(&self.root) else {
            return 0;
        };
        let mut removed = 0;
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let path = e.path();
            let age = e
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| SystemTime::now().duration_since(t).ok())
                .unwrap_or_default();
            let stale = if let Some(t) = name.strip_prefix(TMP_PREFIX) {
                // an upload still running for a day is abandoned
                valid_token(t) && age > Duration::from_secs(24 * 3600)
            } else if valid_token(&name) {
                match fs::read(path.join("meta.json"))
                    .ok()
                    .and_then(|r| serde_json::from_slice::<Meta>(&r).ok())
                {
                    Some(m) => m.is_expired(now),
                    // unreadable/missing meta: broken share, drop after an hour
                    None => age > Duration::from_secs(3600),
                }
            } else {
                false // never touch anything we didn't create
            };
            if stale && fs::remove_dir_all(&path).is_ok() {
                removed += 1;
            }
        }
        removed
    }
}

#[cfg(test)]
fn path_exists(p: &std::path::Path) -> bool {
    p.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_format_and_uniqueness() {
        let a = random_token();
        let b = random_token();
        assert_eq!(a.len(), TOKEN_LEN);
        assert!(valid_token(&a));
        assert_ne!(a, b);
        assert!(!valid_token("../etc"));
        assert!(!valid_token(&a.to_uppercase()));
        assert!(!valid_token(&a[..25]));
    }

    #[test]
    fn sanitize() {
        assert_eq!(sanitize_path("a.txt").as_deref(), Some("a.txt"));
        assert_eq!(
            sanitize_path("dir//sub/./x.png").as_deref(),
            Some("dir/sub/x.png")
        );
        assert_eq!(sanitize_path("dir/"), Some("dir".into()));
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../../x",
            "a\\b",
            "a\u{0}b",
            "./",
            "a/\n",
        ] {
            assert_eq!(sanitize_path(bad), None, "{bad:?}");
        }
        assert_eq!(sanitize_path(&"x".repeat(256)), None);
    }

    #[test]
    fn mime() {
        assert_eq!(mime_for("index.html"), "text/html; charset=utf-8");
        assert_eq!(mime_for("a.png"), "image/png");
        assert_eq!(mime_for("noext"), "application/octet-stream");
    }

    #[test]
    fn common_top() {
        assert_eq!(
            common_top_dir(["s/a", "s/b/c"].into_iter()),
            Some("s".into())
        );
        assert_eq!(common_top_dir(["s/a", "t/b"].into_iter()), None);
        assert_eq!(common_top_dir(["a", "s/b"].into_iter()), None);
    }

    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = io::Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut buf);
            let opts: zip::write::SimpleFileOptions = Default::default();
            for (name, data) in entries {
                w.start_file(*name, opts).unwrap();
                w.write_all(data).unwrap();
            }
            w.finish().unwrap();
        }
        buf.into_inner()
    }

    #[test]
    fn commit_load_delete() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path()).unwrap();
        let mut st = store.begin(1000, 100).unwrap();
        st.put_bytes("a/b.txt", b"hello").unwrap();
        let c = store.commit(st, Duration::from_secs(60)).unwrap();
        let meta = store.load(&c.token).unwrap();
        assert_eq!(meta.files[0].path, "a/b.txt");
        assert!(path_exists(&store.file_path(&c.token, "a/b.txt")));
        assert_eq!(store.delete(&c.token, "wrong"), Err(DeleteError::Forbidden));
        assert_eq!(store.delete(&c.token, &c.delete_token), Ok(()));
        assert!(store.load(&c.token).is_none());
    }

    #[test]
    fn quota_enforced() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path()).unwrap();
        let mut st = store.begin(4, 100).unwrap();
        assert!(matches!(
            st.put_bytes("a", b"hello"),
            Err(UploadError::TooLarge)
        ));
    }

    #[test]
    fn expired_share_hidden_and_swept() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path()).unwrap();
        let mut st = store.begin(100, 100).unwrap();
        st.put_bytes("x", b"1").unwrap();
        let c = store.commit(st, Duration::from_secs(60)).unwrap();
        // backdate expiry
        let mp = tmp.path().join(&c.token).join("meta.json");
        let mut m: Meta = serde_json::from_slice(&fs::read(&mp).unwrap()).unwrap();
        m.expires_at = now_secs() - 1;
        fs::write(&mp, serde_json::to_vec(&m).unwrap()).unwrap();
        assert!(store.load(&c.token).is_none());
        fs::create_dir(tmp.path().join("unrelated")).unwrap();
        assert_eq!(store.sweep(), 1);
        assert!(!tmp.path().join(&c.token).exists());
        assert!(tmp.path().join("unrelated").exists());
    }

    #[test]
    fn zip_unpack_strips_top_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path()).unwrap();
        let mut st = store.begin(10_000, 100).unwrap();
        let z = make_zip(&[
            ("site/index.html", b"<img src=img/a.png>"),
            ("site/img/a.png", b"PNG"),
        ]);
        st.put_bytes("site.zip", &z).unwrap();
        st.unpack_zip("site.zip", 100).unwrap();
        let mut paths: Vec<_> = st.paths().cloned().collect();
        paths.sort();
        assert_eq!(paths, ["img/a.png", "index.html"]);
        assert_eq!(st.total(), 22);
    }

    #[test]
    fn zip_slip_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path()).unwrap();
        let mut st = store.begin(10_000, 100).unwrap();
        let z = make_zip(&[("ok.txt", b"1"), ("../evil.txt", b"2")]);
        st.put_bytes("x.zip", &z).unwrap();
        assert!(matches!(
            st.unpack_zip("x.zip", 100),
            Err(UploadError::Rejected(_))
        ));
        assert!(!tmp.path().join("evil.txt").exists());
    }

    #[test]
    fn zip_bomb_and_entry_limits() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path()).unwrap();
        // 1 MiB of zeros compresses to ~1 KiB, quota is 64 KiB
        let big = vec![0u8; 1 << 20];
        let z = make_zip(&[("zeros.bin", &big)]);
        let mut st = store.begin(64 * 1024, 100).unwrap();
        st.put_bytes("b.zip", &z).unwrap();
        assert!(matches!(
            st.unpack_zip("b.zip", 100),
            Err(UploadError::TooLarge)
        ));

        let z = make_zip(&[("a", b"1"), ("b", b"2"), ("c", b"3")]);
        let mut st = store.begin(64 * 1024, 100).unwrap();
        st.put_bytes("c.zip", &z).unwrap();
        assert!(matches!(
            st.unpack_zip("c.zip", 2),
            Err(UploadError::Rejected(_))
        ));
    }

    #[test]
    fn central_headers_counted_across_reads() {
        let tmp = tempfile::tempdir().unwrap();
        let entries: Vec<(String, Vec<u8>)> = (0..50)
            .map(|i| (format!("f{i}"), vec![i as u8; 40_000]))
            .collect();
        let refs: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(n, d)| (n.as_str(), d.as_slice()))
            .collect();
        let p = tmp.path().join("z.zip");
        fs::write(&p, make_zip(&refs)).unwrap();
        assert_eq!(count_central_headers(&p, usize::MAX).unwrap(), 50);
        assert!(count_central_headers(&p, 10).unwrap() > 10);
        // a signature split across two reads is still found exactly once
        let mut data = vec![b'x'; (1 << 20) - 2];
        data.extend_from_slice(b"PK\x01\x02tail");
        fs::write(&p, &data).unwrap();
        assert_eq!(count_central_headers(&p, usize::MAX).unwrap(), 1);
    }

    #[test]
    fn file_count_and_depth_limits() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path()).unwrap();
        let mut st = store.begin(1000, 2).unwrap();
        st.put_bytes("a", b"").unwrap();
        st.put_bytes("b", b"").unwrap();
        st.put_bytes("a", b"again").unwrap(); // replacing doesn't count
        assert!(matches!(
            st.put_bytes("c", b""),
            Err(UploadError::Rejected(_))
        ));

        // extracted zip members count too
        let z = make_zip(&[("x", b"1"), ("y", b"2"), ("z", b"3")]);
        let mut st = store.begin(64 * 1024, 2).unwrap();
        st.put_bytes("m.zip", &z).unwrap();
        assert!(matches!(
            st.unpack_zip("m.zip", 100),
            Err(UploadError::Rejected(_))
        ));

        assert!(sanitize_path(&vec!["d"; 32].join("/")).is_some());
        assert!(sanitize_path(&vec!["d"; 33].join("/")).is_none());
    }
}
