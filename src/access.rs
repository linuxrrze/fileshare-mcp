//! Network-based access: clients in `WRITE_ALLOWED_NETS` may upload and
//! delete, everyone else gets read-only access. Behind a reverse proxy the
//! client address comes from `X-Forwarded-For`, believed only when the TCP
//! peer is in `TRUSTED_PROXIES`.

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::Shared;

/// An IPv4 or IPv6 network (`10.0.0.0/8`, `fd00::/8`, or a single address).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Net {
    addr: IpAddr,
    prefix: u8,
}

impl Net {
    pub fn parse(s: &str) -> Option<Net> {
        let s = s.trim();
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = a.trim().parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            None => max,
            Some(p) => p.trim().parse::<u8>().ok().filter(|&p| p <= max)?,
        };
        // Clients are matched in canonical form (`::ffff:10.1.2.3` ->
        // `10.1.2.3`), so an IPv4-mapped network becomes an IPv4 one.
        if let IpAddr::V6(v6) = addr
            && let Some(v4) = v6.to_ipv4_mapped()
            && prefix >= 96
        {
            return Some(Net {
                addr: IpAddr::V4(v4),
                prefix: prefix - 96,
            });
        }
        Some(Net { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip.to_canonical()) {
            (IpAddr::V4(n), IpAddr::V4(i)) => {
                let mask = u32::MAX.checked_shl(32 - self.prefix as u32).unwrap_or(0);
                u32::from(n) & mask == u32::from(i) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(i)) => {
                let mask = u128::MAX.checked_shl(128 - self.prefix as u32).unwrap_or(0);
                u128::from(n) & mask == u128::from(i) & mask
            }
            _ => false,
        }
    }
}

impl fmt::Display for Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// Comma-separated list of networks; empty or unset is an empty list.
pub fn parse_nets(name: &str, v: Option<&str>) -> Result<Vec<Net>, String> {
    v.unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| Net::parse(s).ok_or_else(|| format!("{name}: {s:?} is not an IP address or CIDR")))
        .collect()
}

fn in_any(nets: &[Net], ip: IpAddr) -> bool {
    nets.iter().any(|n| n.contains(ip))
}

/// One `X-Forwarded-For` entry: a bare address, or `1.2.3.4:port` /
/// `[::1]:port` as some proxies write it.
fn parse_hop(s: &str) -> Option<IpAddr> {
    s.parse::<IpAddr>()
        .ok()
        .or_else(|| s.parse::<SocketAddr>().ok().map(|a| a.ip()))
        .map(|ip| ip.to_canonical())
}

/// The client's address. `X-Forwarded-For` counts only when the TCP peer is a
/// trusted proxy; it is read right to left (each proxy appends the address
/// it got the request from) and the first entry that is not itself a trusted
/// proxy is the client. Anything left of that may be client-forged and is
/// ignored. `None` (unknown, never allowed to write): no peer address, or an
/// unparseable entry where the client should be.
pub fn client_ip(peer: Option<IpAddr>, headers: &HeaderMap, trusted: &[Net]) -> Option<IpAddr> {
    let peer = peer?.to_canonical();
    if !in_any(trusted, peer) {
        return Some(peer);
    }
    let mut hops = Vec::new();
    for v in headers.get_all("x-forwarded-for") {
        let v = v.to_str().ok()?;
        hops.extend(v.split(',').map(str::trim).filter(|s| !s.is_empty()));
    }
    // A trusted peer that forwarded nothing is the client itself (e.g. a
    // container on the proxy's network talking to fileshare directly).
    let mut client = peer;
    for hop in hops.iter().rev() {
        client = parse_hop(hop)?;
        if !in_any(trusted, client) {
            break;
        }
    }
    Some(client)
}

/// Per-request access decision, set by [`layer`] as a request extension.
#[derive(Clone, Copy, Debug)]
pub struct Access {
    pub client: Option<IpAddr>,
    /// May upload and delete shares.
    pub write: bool,
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.client {
            Some(ip) => write!(f, "{ip}"),
            None => f.write_str("unknown"),
        }
    }
}

pub const READ_ONLY_MSG: &str =
    "read-only access: uploads and deletes are only allowed from WRITE_ALLOWED_NETS";

/// Works out [`Access`] for every request and refuses writes to `/api/*`
/// (uploads, deletes) from read-only clients. `/mcp` checks it per tool,
/// since its read tools stay available.
pub async fn layer(State(st): State<Shared>, mut req: Request, next: Next) -> Response {
    let cfg = &st.cfg;
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    let client = client_ip(peer, req.headers(), &cfg.trusted_proxies);
    let write = cfg.write_nets.is_empty() || client.is_some_and(|ip| in_any(&cfg.write_nets, ip));
    let access = Access { client, write };
    if !write
        && req.uri().path().starts_with("/api/")
        && ![Method::GET, Method::HEAD, Method::OPTIONS].contains(req.method())
    {
        tracing::debug!(client = %access, path = req.uri().path(), "write refused: read-only client");
        return (StatusCode::FORBIDDEN, format!("{READ_ONLY_MSG}\n")).into_response();
    }
    req.extensions_mut().insert(access);
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn nets(s: &str) -> Vec<Net> {
        parse_nets("T", Some(s)).unwrap()
    }

    #[test]
    fn nets_parse_and_match() {
        let n = nets("10.0.0.0/8, 192.168.1.5, fd00::/8, 0.0.0.0/0");
        assert!(n[0].contains(ip("10.255.0.1")));
        assert!(!n[0].contains(ip("11.0.0.1")));
        assert!(n[0].contains(ip("::ffff:10.1.2.3")), "IPv4-mapped IPv6");
        assert!(n[1].contains(ip("192.168.1.5")));
        assert!(!n[1].contains(ip("192.168.1.6")));
        assert!(n[2].contains(ip("fd12::1")));
        assert!(!n[2].contains(ip("10.0.0.1")));
        assert!(n[3].contains(ip("203.0.113.9")));
        // IPv4-mapped notation is an IPv4 network
        let m = nets("::ffff:10.0.0.0/104, ::ffff:192.168.1.5");
        assert_eq!(m, nets("10.0.0.0/8, 192.168.1.5"));
        assert!(m[0].contains(ip("10.1.2.3")));
        assert!(m[0].contains(ip("::ffff:10.1.2.3")));
        assert!(parse_nets("T", Some("10.0.0.0/33")).is_err());
        assert!(parse_nets("T", Some("fd00::/129")).is_err());
        assert!(parse_nets("T", Some("intranet")).is_err());
        assert!(parse_nets("T", Some(" , ")).unwrap().is_empty());
    }

    fn xff(v: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in v {
            h.append("x-forwarded-for", v.parse().unwrap());
        }
        h
    }

    #[test]
    fn client_address() {
        let proxies = nets("172.20.0.2, 10.9.9.9");
        let ext = Some(ip("203.0.113.7"));
        let proxy = Some(ip("172.20.0.2"));
        // untrusted peer: header ignored (forgeable)
        assert_eq!(client_ip(ext, &xff(&["10.0.0.1"]), &proxies), ext);
        assert_eq!(client_ip(ext, &xff(&["10.0.0.1"]), &[]), ext);
        // trusted proxy: rightmost untrusted entry, forged entries left of it ignored
        assert_eq!(
            client_ip(proxy, &xff(&["10.0.0.1, 198.51.100.4"]), &proxies),
            Some(ip("198.51.100.4"))
        );
        // chained trusted proxies are skipped; several header lines are one list
        assert_eq!(
            client_ip(proxy, &xff(&["192.168.1.20", "10.9.9.9"]), &proxies),
            Some(ip("192.168.1.20"))
        );
        assert_eq!(
            client_ip(proxy, &xff(&["[2001:db8::1]:4711"]), &proxies),
            Some(ip("2001:db8::1"))
        );
        // trusted peer without the header is the client itself
        assert_eq!(client_ip(proxy, &HeaderMap::new(), &proxies), proxy);
        // garbage where the client should be, or no peer: unknown
        assert_eq!(client_ip(proxy, &xff(&["unknown"]), &proxies), None);
        assert_eq!(client_ip(None, &xff(&["10.0.0.1"]), &proxies), None);
        // garbage left of the client doesn't matter
        assert_eq!(
            client_ip(proxy, &xff(&["junk, 198.51.100.4"]), &proxies),
            Some(ip("198.51.100.4"))
        );
    }
}
