//! Fetching a manifest and a binary over a line that censors the download.
//!
//! Two halves, split the way everything in this project is split. The **pure** half — URLs,
//! response heads, redirects, the host allowlist — decides everything and is tested on Linux. The
//! **I/O** half opens a socket and does what it is told.
//!
//! ## Why not an HTTP crate
//!
//! `ureq` was measured at nine new crates, and the count is not the real objection: pointing it at
//! vigil's own resolver and its own first-flight transform means reaching inside it either way. And
//! the client this needs is genuinely tiny, because the design made it tiny — one `GET`, no
//! compression, no cookies, no authentication, no chunked bodies. `api.github.com` is the only host
//! in this family that answers chunked and it is never called, which also sidesteps its
//! sixty-requests-an-hour-per-IP limit that Turkish CGNAT would share across a neighbourhood.
//!
//! ## Why the transform
//!
//! GitHub is not blocked on Türk Telekom — measured 2026-08-08, five hostnames, 6/6 with no
//! strategy at all. That is today, on one ISP. The whole premise of this project is that the line
//! decides, and the line changes: the same development line began poisoning DNS for five hostnames
//! overnight with no warning. So the download goes through the same resolver and the same transform
//! as every other connection vigil makes, and falls back to plain when that fails rather than the
//! other way round.

use vigil_core::strategy::Strategy;

/// The most redirects that will be followed. GitHub's release-asset path is
/// `github.com` → `release-assets.githubusercontent.com`, so two is the real number; five leaves
/// room without letting a loop run.
pub const MAX_REDIRECTS: usize = 5;
/// The largest response body that will be read. A manifest is a few hundred bytes and a binary is
/// a few megabytes; this is the ceiling on both, and it exists because the bytes arrive before
/// anything has verified them.
pub const MAX_BODY: u64 = 64 * 1024 * 1024;
/// The largest response head. Anything longer is a server misbehaving or a middlebox talking.
pub const MAX_HEAD: usize = 16 * 1024;

/// A URL, only as much of one as this client can speak.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub host: String,
    pub port: u16,
    /// Everything from the leading slash onward, query included.
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    /// Not an `https://` URL, or one this client cannot parse.
    BadUrl(String),
    /// The host is not on the allowlist. Checked on the first URL and again after every redirect,
    /// because a redirect is exactly how a URL that reads as one host resolves as another.
    HostNotAllowed(String),
    /// A response head that is not HTTP/1.x, or has no status, or is too long.
    BadResponse(String),
    /// A status this client does not act on.
    Status(u16),
    /// A redirect with no usable `Location`.
    RedirectWithoutLocation,
    TooManyRedirects,
    /// No `Content-Length`. Refused rather than read-until-close: a body whose length is not
    /// declared cannot be distinguished from one that was truncated by a censor mid-transfer, and
    /// "truncated" and "complete" must never look the same here.
    LengthRequired,
    BodyTooLarge(u64),
    /// The body was shorter than `Content-Length` said. The failure this whole design is careful
    /// about: on a silently-dropping line, a short read is the normal shape of censorship.
    ShortBody {
        want: u64,
        got: u64,
    },
    Io(String),
    Tls(String),
    /// The name resolved to nothing usable, or to the censor's block page.
    Resolve(String),
}

impl core::fmt::Display for HttpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use HttpError::*;
        match self {
            BadUrl(u) => write!(f, "cannot parse URL {u:?}"),
            HostNotAllowed(h) => write!(f, "host {h:?} is not on the allowlist"),
            BadResponse(w) => write!(f, "bad response: {w}"),
            Status(c) => write!(f, "HTTP {c}"),
            RedirectWithoutLocation => f.write_str("redirect without a Location"),
            TooManyRedirects => f.write_str("too many redirects"),
            LengthRequired => f.write_str("response had no Content-Length"),
            BodyTooLarge(n) => write!(f, "body of {n} bytes is over the limit"),
            ShortBody { want, got } => write!(f, "body stopped at {got} of {want} bytes"),
            Io(e) => write!(f, "io: {e}"),
            Tls(e) => write!(f, "tls: {e}"),
            Resolve(e) => write!(f, "resolve: {e}"),
        }
    }
}

impl Url {
    /// Parse an `https://` URL. Nothing else: no scheme-relative, no http, no credentials, no
    /// fragment. This is not a general URL parser and must not become one — every shape it accepts
    /// is a shape an attacker can write into a `Location` header.
    pub fn parse(s: &str) -> Result<Url, HttpError> {
        let bad = || HttpError::BadUrl(s.to_string());
        let rest = s.strip_prefix("https://").ok_or_else(bad)?;
        if rest.is_empty() || rest.contains('@') || rest.contains('#') || rest.contains(' ') {
            return Err(bad());
        }
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/".to_string()),
        };
        if authority.is_empty() {
            return Err(bad());
        }
        // An explicit port is accepted but must be a port. `host:` and `host:0` are not.
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => {
                let n: u16 = p.parse().map_err(|_| bad())?;
                if n == 0 || h.is_empty() {
                    return Err(bad());
                }
                (h.to_string(), n)
            }
            None => (authority.to_string(), 443),
        };
        // Hostnames only. An address literal would bypass the point of pinning hostnames.
        if host.contains('[')
            || !host
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-')
            || host.starts_with('.')
            || host.ends_with('.')
            || host.contains("..")
        {
            return Err(bad());
        }
        Ok(Url { host, port, path })
    }

    pub fn to_string_https(&self) -> String {
        if self.port == 443 {
            format!("https://{}{}", self.host, self.path)
        } else {
            format!("https://{}:{}{}", self.host, self.port, self.path)
        }
    }
}

/// Is this host one we are willing to fetch from?
///
/// Exact match, case-sensitively, against the manifest module's list. Case-sensitive on purpose:
/// `gitHub.com` resolves the same as `github.com` but is not a string anybody in this project
/// writes, so seeing it means something generated it, and that is worth refusing over.
pub fn host_allowed(host: &str) -> bool {
    crate::manifest::ALLOWED_HOSTS.contains(&host)
}

/// A parsed response head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub status: u16,
    pub content_length: Option<u64>,
    pub location: Option<String>,
    /// How many bytes of the buffer the head occupied, so the caller knows where the body starts.
    pub head_len: usize,
}

/// Parse a response head out of `buf`, if all of it has arrived.
///
/// `Ok(None)` means "not yet" — keep reading. `Err` means the response is not one we will act on.
pub fn parse_head(buf: &[u8]) -> Result<Option<Head>, HttpError> {
    if buf.len() > MAX_HEAD {
        return Err(HttpError::BadResponse("head too long".into()));
    }
    let Some(end) = find_head_end(buf) else {
        return Ok(None);
    };
    let text = core::str::from_utf8(&buf[..end])
        .map_err(|_| HttpError::BadResponse("head is not UTF-8".into()))?;
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| HttpError::BadResponse("no status line".into()))?;

    // `HTTP/1.1 200 OK` — and `HTTP/1.0`, which GitHub does not send but a middlebox might.
    let mut parts = status_line.split(' ');
    let version = parts
        .next()
        .ok_or_else(|| HttpError::BadResponse("no version".into()))?;
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(HttpError::BadResponse(format!("version {version:?}")));
    }
    let code = parts
        .next()
        .ok_or_else(|| HttpError::BadResponse("no status code".into()))?;
    if code.len() != 3 || !code.bytes().all(|c| c.is_ascii_digit()) {
        return Err(HttpError::BadResponse(format!("status {code:?}")));
    }
    let status: u16 = code
        .parse()
        .map_err(|_| HttpError::BadResponse(format!("status {code:?}")))?;

    let mut content_length = None;
    let mut location = None;
    let mut transfer_encoding = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(HttpError::BadResponse(format!("header {line:?}")));
        };
        let value = value.trim();
        // Header names are case-insensitive; only these three are read at all.
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "content-length" => {
                let n: u64 = value
                    .parse()
                    .map_err(|_| HttpError::BadResponse(format!("Content-Length {value:?}")))?;
                // Two different Content-Lengths is a request-smuggling shape, not a quirk.
                if content_length.is_some_and(|prev| prev != n) {
                    return Err(HttpError::BadResponse("two Content-Lengths".into()));
                }
                content_length = Some(n);
            }
            "location" => location = Some(value.to_string()),
            "transfer-encoding" => transfer_encoding = Some(value.to_ascii_lowercase()),
            _ => {}
        }
    }
    // No chunked decoder, and no silent fallback into one either.
    if let Some(te) = transfer_encoding {
        if te != "identity" {
            return Err(HttpError::BadResponse(format!("Transfer-Encoding {te:?}")));
        }
    }

    Ok(Some(Head {
        status,
        content_length,
        location,
        head_len: end + 4,
    }))
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Where a redirect points, resolved against the URL it came from and checked against the
/// allowlist.
///
/// Only absolute `https://` targets and absolute paths. A scheme-relative `//host/x` is refused:
/// it is the shape that looks like a path and is a host.
pub fn resolve_redirect(from: &Url, location: &str) -> Result<Url, HttpError> {
    let loc = location.trim();
    if loc.is_empty() {
        return Err(HttpError::RedirectWithoutLocation);
    }
    let next = if loc.starts_with("https://") {
        Url::parse(loc)?
    } else if loc.starts_with("//") {
        return Err(HttpError::BadUrl(loc.to_string()));
    } else if loc.starts_with('/') {
        Url {
            host: from.host.clone(),
            port: from.port,
            path: loc.to_string(),
        }
    } else {
        // No relative paths. GitHub does not send them and resolving them correctly is a whole
        // algorithm with its own dot-segment rules.
        return Err(HttpError::BadUrl(loc.to_string()));
    };
    if !host_allowed(&next.host) {
        return Err(HttpError::HostNotAllowed(next.host));
    }
    Ok(next)
}

/// Is this status one we follow, act on, or refuse?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Body,
    Redirect,
}

pub fn action_for(status: u16) -> Result<Action, HttpError> {
    match status {
        200 => Ok(Action::Body),
        // 301/302/303 rewrite the method in some clients; this only ever issues GET, so all five
        // are the same thing here.
        301 | 302 | 303 | 307 | 308 => Ok(Action::Redirect),
        other => Err(HttpError::Status(other)),
    }
}

/// The request line and headers for a GET. No `Accept-Encoding`, so nothing arrives compressed
/// and there is no decompressor to be wrong about.
pub fn request_for(url: &Url) -> String {
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: */*\r\nUser-Agent: vigil-update/{}\r\n\r\n",
        url.path,
        url.host,
        env!("CARGO_PKG_VERSION")
    )
}

/// The strategies a fetch tries, in order: the measured default first, then no transform at all.
///
/// Both, and in this order, because either can be the one that works. On Superonline every
/// `split:*` is 0/10 and `tlsrec` is what gets through; on a line where nothing is blocked the
/// transform is harmless but pointless, and if a future middlebox objects to *being* transformed
/// the plain attempt is the one that succeeds.
pub fn strategies() -> [Strategy; 2] {
    [Strategy::measured_default(), Strategy::passthrough()]
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------ URLs

    #[test]
    fn an_ordinary_https_url_parses() {
        let u = Url::parse("https://github.com/resul-e/vigil/releases/latest/download/x.txt")
            .expect("parses");
        assert_eq!(u.host, "github.com");
        assert_eq!(u.port, 443);
        assert_eq!(u.path, "/resul-e/vigil/releases/latest/download/x.txt");
        assert_eq!(
            u.to_string_https(),
            "https://github.com/resul-e/vigil/releases/latest/download/x.txt"
        );
    }

    #[test]
    fn a_url_with_no_path_gets_a_slash() {
        let u = Url::parse("https://github.com").expect("parses");
        assert_eq!(u.path, "/");
        assert_eq!(u.to_string_https(), "https://github.com/");
    }

    #[test]
    fn a_query_string_survives_because_signed_urls_have_one() {
        let u = Url::parse("https://release-assets.githubusercontent.com/x?token=abc&y=1")
            .expect("parses");
        assert_eq!(u.path, "/x?token=abc&y=1");
    }

    #[test]
    fn an_explicit_port_is_kept_and_printed_back() {
        let u = Url::parse("https://github.com:8443/x").expect("parses");
        assert_eq!(u.port, 8443);
        assert_eq!(u.to_string_https(), "https://github.com:8443/x");
    }

    /// Every shape this refuses is a shape somebody could put in a `Location` header.
    #[test]
    fn everything_that_is_not_a_plain_https_url_is_refused() {
        for bad in [
            "",
            "github.com/x",
            "http://github.com/x",
            "HTTPS://github.com/x",
            "https://",
            "https://user:pw@github.com/x",
            "https://github.com/x#frag",
            "https://github.com/ x",
            "https://github.com:/x",
            "https://github.com:0/x",
            "https://github.com:99999/x",
            "https://:443/x",
            "https://[::1]/x",
            "https://.github.com/x",
            "https://github.com./x",
            "https://git..hub.com/x",
            "https://git hub.com/x",
            "https://git_hub.com/x",
        ] {
            assert!(Url::parse(bad).is_err(), "{bad:?} should not parse");
        }
    }

    // ------------------------------------------------------------------ allowlist

    #[test]
    fn only_the_listed_hosts_are_allowed_and_case_matters() {
        assert!(host_allowed("github.com"));
        assert!(host_allowed("release-assets.githubusercontent.com"));
        for no in [
            "gitHub.com",
            "github.com.evil.net",
            "evil.github.com.co",
            "notgithub.com",
            "",
            "githubusercontent.com",
        ] {
            assert!(!host_allowed(no), "{no:?} must not be allowed");
        }
    }

    // ------------------------------------------------------------------ response heads

    fn head(s: &str) -> Result<Option<Head>, HttpError> {
        parse_head(s.as_bytes())
    }

    #[test]
    fn a_complete_head_parses_and_reports_where_the_body_starts() {
        let raw =
            "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nContent-Type: text/plain\r\n\r\nhello world!";
        let h = head(raw).expect("ok").expect("complete");
        assert_eq!(h.status, 200);
        assert_eq!(h.content_length, Some(12));
        assert_eq!(h.location, None);
        assert_eq!(&raw[h.head_len..], "hello world!");
    }

    /// A head that has not fully arrived is "not yet", never a guess. Every prefix of a real head
    /// must say so, because that is what a slow line delivers.
    #[test]
    fn an_incomplete_head_is_not_yet_rather_than_an_error() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n";
        for n in 0..raw.len() {
            let got = parse_head(&raw.as_bytes()[..n]);
            assert!(
                matches!(got, Ok(None)),
                "prefix of {n} bytes gave {got:?}, expected not-yet"
            );
        }
        assert!(matches!(parse_head(raw.as_bytes()), Ok(Some(_))));
    }

    #[test]
    fn header_names_are_case_insensitive() {
        let h = head("HTTP/1.1 200 OK\r\ncOnTeNt-LeNgTh: 5\r\n\r\n")
            .expect("ok")
            .expect("complete");
        assert_eq!(h.content_length, Some(5));
    }

    #[test]
    fn a_redirect_carries_its_location() {
        let h = head("HTTP/1.1 302 Found\r\nLocation: https://release-assets.githubusercontent.com/x\r\nContent-Length: 0\r\n\r\n")
            .expect("ok")
            .expect("complete");
        assert_eq!(h.status, 302);
        assert_eq!(
            h.location.as_deref(),
            Some("https://release-assets.githubusercontent.com/x")
        );
    }

    /// Two `Content-Length` headers that disagree is a request-smuggling shape. A client that
    /// picks one is a client that can be told a different length than the server sent.
    #[test]
    fn contradictory_content_lengths_are_refused() {
        assert!(head("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 9\r\n\r\n").is_err());
        // The same value twice is a server being redundant, not an attack.
        assert!(head("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n").is_ok());
    }

    /// There is no chunked decoder, and there must be no silent fallback into pretending.
    #[test]
    fn a_chunked_response_is_refused_rather_than_misread() {
        assert!(head("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").is_err());
        assert!(head("HTTP/1.1 200 OK\r\nTransfer-Encoding: CHUNKED\r\n\r\n").is_err());
        assert!(head(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: identity\r\nContent-Length: 1\r\n\r\n"
        )
        .is_ok());
    }

    #[test]
    fn a_malformed_status_line_is_refused() {
        for raw in [
            "\r\n\r\n",
            "HTTP/2 200 OK\r\n\r\n",
            "HTTP/1.1\r\n\r\n",
            "HTTP/1.1 20 OK\r\n\r\n",
            "HTTP/1.1 2000 OK\r\n\r\n",
            "HTTP/1.1 abc OK\r\n\r\n",
            "200 OK\r\n\r\n",
            "hello\r\n\r\n",
        ] {
            assert!(head(raw).is_err(), "{raw:?} should be refused");
        }
    }

    #[test]
    fn a_header_line_without_a_colon_is_refused() {
        assert!(head("HTTP/1.1 200 OK\r\nnonsense\r\n\r\n").is_err());
    }

    #[test]
    fn an_absurdly_long_head_is_refused_before_it_is_parsed() {
        let raw = format!("HTTP/1.1 200 OK\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEAD));
        assert!(matches!(
            parse_head(raw.as_bytes()),
            Err(HttpError::BadResponse(_))
        ));
    }

    #[test]
    fn head_parsing_never_panics_on_arbitrary_bytes() {
        let base = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nhello world!";
        for i in 0..base.len() {
            for b in [0u8, b'\r', b'\n', b':', b' ', 0xff, b'9'] {
                let mut m = base.to_vec();
                m[i] = b;
                let _ = parse_head(&m);
            }
        }
        for junk in [vec![], vec![0u8; 100], vec![b'\r'; 100], vec![0xff; 100]] {
            let _ = parse_head(&junk);
        }
    }

    // ------------------------------------------------------------------ statuses and redirects

    #[test]
    fn only_two_hundred_delivers_a_body_and_only_redirects_redirect() {
        assert_eq!(action_for(200), Ok(Action::Body));
        for r in [301, 302, 303, 307, 308] {
            assert_eq!(action_for(r), Ok(Action::Redirect), "{r}");
        }
        for bad in [100, 201, 204, 206, 304, 400, 401, 403, 404, 429, 500, 503] {
            assert_eq!(action_for(bad), Err(HttpError::Status(bad)), "{bad}");
        }
    }

    #[test]
    fn a_redirect_to_an_allowed_host_is_followed() {
        let from = Url::parse("https://github.com/a/b").expect("parses");
        let to = resolve_redirect(&from, "https://release-assets.githubusercontent.com/x?t=1")
            .expect("allowed");
        assert_eq!(to.host, "release-assets.githubusercontent.com");
        assert_eq!(to.path, "/x?t=1");
    }

    #[test]
    fn an_absolute_path_redirect_stays_on_the_same_host() {
        let from = Url::parse("https://github.com:8443/a/b").expect("parses");
        let to = resolve_redirect(&from, "/c/d").expect("allowed");
        assert_eq!(to.host, "github.com");
        assert_eq!(to.port, 8443, "the port must survive a path-only redirect");
        assert_eq!(to.path, "/c/d");
    }

    /// The check that matters: a redirect is exactly how a URL that reads as one host resolves as
    /// another, so the allowlist is applied again on every hop.
    #[test]
    fn a_redirect_off_the_allowlist_is_refused() {
        let from = Url::parse("https://github.com/a").expect("parses");
        for loc in [
            "https://evil.net/x",
            "https://github.com.evil.net/x",
            "https://gitHub.com/x",
        ] {
            assert!(
                matches!(
                    resolve_redirect(&from, loc),
                    Err(HttpError::HostNotAllowed(_))
                ),
                "{loc:?} must be refused"
            );
        }
    }

    /// `//host/x` looks like a path and is a host. The one redirect shape most likely to slip past
    /// a hand-written client.
    #[test]
    fn a_scheme_relative_redirect_is_refused_because_it_looks_like_a_path() {
        let from = Url::parse("https://github.com/a").expect("parses");
        assert!(matches!(
            resolve_redirect(&from, "//evil.net/x"),
            Err(HttpError::BadUrl(_))
        ));
    }

    #[test]
    fn relative_and_empty_and_downgrading_redirects_are_refused() {
        let from = Url::parse("https://github.com/a/b").expect("parses");
        for loc in [
            "",
            "   ",
            "c/d",
            "../c",
            "http://github.com/x",
            "javascript:x",
        ] {
            assert!(resolve_redirect(&from, loc).is_err(), "{loc:?}");
        }
    }

    // ------------------------------------------------------------------ the request

    #[test]
    fn the_request_asks_for_nothing_it_cannot_handle() {
        let u = Url::parse("https://github.com/a?b=c").expect("parses");
        let r = request_for(&u);
        assert!(r.starts_with("GET /a?b=c HTTP/1.1\r\n"));
        assert!(r.contains("Host: github.com\r\n"));
        assert!(r.contains("Connection: close\r\n"));
        assert!(r.ends_with("\r\n\r\n"));
        // No compression, so there is no decompressor to be wrong about.
        assert!(!r.to_ascii_lowercase().contains("accept-encoding"));
        // And it names itself, so a server log can tell an updater from a browser.
        assert!(r.contains(&format!("vigil-update/{}", env!("CARGO_PKG_VERSION"))));
    }

    #[test]
    fn the_transform_is_tried_before_plain() {
        let s = strategies();
        assert_eq!(s[0].to_string(), "tlsrec:64+split:1");
        assert_eq!(s[1].to_string(), "none");
    }
}
