//! `wirelog` — a measurement instrument, not a product.
//!
//! It listens where vigil listens and writes down what actually arrives: which SOCKS dialect
//! the client speaks, which source port it came from (so the connection can be attributed to
//! a process from outside), what target it asked for, and how big its ClientHello is.
//!
//! It exists to answer one question that no amount of reading can settle — *does the Discord
//! desktop application honour the Windows system proxy, and if so, what does it speak?* — and
//! it answers it by accepting **every** dialect, so the application under test keeps working
//! and keeps talking instead of failing at the first handshake and telling us nothing more.
//!
//! Usage:  wirelog [listen-addr] [--log PATH] [--strategy SPEC]

use std::fmt::Write as _;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vigil_core::strategy::Strategy;
use vigil_proxy::{socks4, socks5, Resolver};

/// What the first byte on the wire says the client is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dialect {
    Socks4,
    Socks5,
    HttpConnect,
    /// A raw TLS record: the client ignored the proxy and something else routed us the bytes.
    RawTls,
    Unknown,
}

impl Dialect {
    fn of(first: u8, buf: &[u8]) -> Dialect {
        match first {
            0x04 => Dialect::Socks4,
            0x05 => Dialect::Socks5,
            0x16 => Dialect::RawTls,
            _ if buf.starts_with(b"CONNECT ") => Dialect::HttpConnect,
            _ => Dialect::Unknown,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Dialect::Socks4 => "socks4",
            Dialect::Socks5 => "socks5",
            Dialect::HttpConnect => "http-connect",
            Dialect::RawTls => "raw-tls",
            Dialect::Unknown => "unknown",
        }
    }
}

struct Log {
    file: Mutex<Option<std::fs::File>>,
}

impl Log {
    fn line(&self, s: &str) {
        eprintln!("{s}");
        if let Ok(mut f) = self.file.lock() {
            if let Some(f) = f.as_mut() {
                let _ = writeln!(f, "{s}");
                let _ = f.flush();
            }
        }
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn main() -> std::process::ExitCode {
    let mut listen: SocketAddr = "127.0.0.1:1080".parse().expect("literal");
    let mut log_path: Option<String> = None;
    let mut dump_path: Option<String> = None;
    let mut strategy = Strategy::passthrough();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].clone();
        i += 1;
        match a.as_str() {
            "--log" => {
                let Some(p) = args.get(i) else {
                    eprintln!("--log needs a PATH");
                    return std::process::ExitCode::from(2);
                };
                i += 1;
                log_path = Some(p.clone());
            }
            "--dump" => {
                let Some(p) = args.get(i) else {
                    eprintln!("--dump needs a PATH");
                    return std::process::ExitCode::from(2);
                };
                i += 1;
                dump_path = Some(p.clone());
            }
            "--strategy" => {
                let Some(spec) = args.get(i) else {
                    eprintln!("--strategy needs a SPEC");
                    return std::process::ExitCode::from(2);
                };
                i += 1;
                match Strategy::parse(spec) {
                    Ok(s) => strategy = s,
                    Err(e) => {
                        eprintln!("bad --strategy {spec:?}: {e}");
                        return std::process::ExitCode::from(2);
                    }
                }
            }
            other => match other.parse() {
                Ok(x) => listen = x,
                Err(_) => {
                    eprintln!("not an address and not a known flag: {other}");
                    return std::process::ExitCode::from(2);
                }
            },
        }
    }

    let log = Arc::new(Log {
        file: Mutex::new(log_path.as_ref().and_then(|p| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .ok()
        })),
    });

    let listener = match TcpListener::bind(listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind {listen}: {e}");
            return std::process::ExitCode::from(1);
        }
    };
    log.line(&format!(
        "# wirelog listening on {listen} strategy={strategy} t={}",
        now_ms()
    ));

    // Shared, so its cache is shared: a second connection to the same host must not pay for
    // another lookup, which is also what makes a cold-first-connection effect visible here.
    let resolver = Arc::new(Resolver::default());

    let n = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        let Ok(client) = conn else { continue };
        let id = n.fetch_add(1, Ordering::Relaxed);
        let log = Arc::clone(&log);
        let strategy = strategy.clone();
        let dump = dump_path.clone();
        let resolver = Arc::clone(&resolver);
        std::thread::spawn(move || handle(id, client, &log, &strategy, dump.as_deref(), &resolver));
    }
    std::process::ExitCode::SUCCESS
}

/// Read until `f` accepts the buffer or the peer goes away.
fn read_until<T, E>(
    s: &mut TcpStream,
    buf: &mut Vec<u8>,
    incomplete: E,
    f: impl Fn(&[u8]) -> Result<(T, usize), E>,
) -> Result<(T, usize), E>
where
    E: PartialEq + Copy,
{
    let mut tmp = [0u8; 1024];
    loop {
        match f(buf) {
            Err(e) if e == incomplete => {}
            other => return other,
        }
        match s.read(&mut tmp) {
            Ok(0) => return Err(incomplete),
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err(incomplete),
        }
    }
}

/// Split `host:port` the way a proxy request carries it, defaulting to 443.
///
/// A bare host is kept whole rather than guessed at, and an IPv6 literal in brackets keeps its
/// colons — splitting on the first colon would have turned `[::1]:443` into a hostname of `[`.
fn split_target(target: &str) -> (&str, u16) {
    if let Some(end) = target.rfind(']') {
        let host = target[..=end].trim_start_matches('[').trim_end_matches(']');
        let port = target[end + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(443);
        return (host, port);
    }
    match target.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().unwrap_or(443)),
        None => (target, 443),
    }
}

fn handle(
    id: usize,
    mut client: TcpStream,
    log: &Log,
    strategy: &Strategy,
    dump: Option<&str>,
    resolver: &Resolver,
) {
    let _ = client.set_nodelay(true);
    let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = client.set_write_timeout(Some(Duration::from_secs(30)));
    let src = client
        .peer_addr()
        .map(|a| a.port())
        .map(|p| p.to_string())
        .unwrap_or_else(|_| "?".into());

    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    let first = match client.read(&mut tmp) {
        Ok(0) | Err(_) => {
            log.line(&format!(
                "t={} conn={id} src={src} dialect=none note=closed-without-sending",
                now_ms()
            ));
            return;
        }
        Ok(n) => {
            buf.extend_from_slice(&tmp[..n]);
            buf[0]
        }
    };
    let dialect = Dialect::of(first, &buf);
    log.line(&format!(
        "t={} conn={id} src={src} dialect={} first={}",
        now_ms(),
        dialect.name(),
        hex(&buf[..buf.len().min(24)])
    ));

    // --- complete whichever handshake this is, and learn the target ---
    let target = match dialect {
        Dialect::Socks5 => {
            let Ok((methods, used)) = read_until(
                &mut client,
                &mut buf,
                socks5::Error::Incomplete,
                socks5::parse_greeting,
            ) else {
                log.line(&format!(
                    "t={} conn={id} src={src} err=bad-greeting",
                    now_ms()
                ));
                return;
            };
            buf.drain(..used);
            let m = socks5::select_method(&methods);
            if client.write_all(&socks5::method_reply(m)).is_err() || m != socks5::METHOD_NO_AUTH {
                log.line(&format!(
                    "t={} conn={id} src={src} err=no-acceptable-method",
                    now_ms()
                ));
                return;
            }
            match read_until(
                &mut client,
                &mut buf,
                socks5::Error::Incomplete,
                socks5::parse_request,
            ) {
                Ok((r, used)) => {
                    buf.drain(..used);
                    r.target()
                }
                Err(e) => {
                    log.line(&format!(
                        "t={} conn={id} src={src} err=bad-request({e})",
                        now_ms()
                    ));
                    let _ = client.write_all(&socks5::reply(socks5::Rep::GeneralFailure));
                    return;
                }
            }
        }
        Dialect::Socks4 => {
            match read_until(
                &mut client,
                &mut buf,
                socks4::Error::Incomplete,
                socks4::parse_request,
            ) {
                Ok((r, used)) => {
                    buf.drain(..used);
                    let t = r.target();
                    log.line(&format!(
                        "t={} conn={id} src={src} socks4_user={:?} socks4a={}",
                        now_ms(),
                        String::from_utf8_lossy(&r.user),
                        matches!(r.addr, socks4::Addr::Domain(_))
                    ));
                    t
                }
                Err(e) => {
                    log.line(&format!(
                        "t={} conn={id} src={src} err=bad-socks4({e})",
                        now_ms()
                    ));
                    let _ = client.write_all(&socks4::reply(socks4::REJECTED));
                    return;
                }
            }
        }
        Dialect::HttpConnect => {
            // Read to the end of the request head, then take the authority form.
            loop {
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 8192 {
                    break;
                }
                match client.read(&mut tmp) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
            }
            let head = String::from_utf8_lossy(&buf).to_string();
            let target = head
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_string();
            let end = buf
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|p| p + 4)
                .unwrap_or(buf.len());
            buf.drain(..end);
            if client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .is_err()
            {
                return;
            }
            target
        }
        Dialect::RawTls | Dialect::Unknown => {
            log.line(&format!(
                "t={} conn={id} src={src} note=not-a-proxy-protocol bytes={}",
                now_ms(),
                hex(&buf[..buf.len().min(64)])
            ));
            return;
        }
    };

    log.line(&format!(
        "t={} conn={id} src={src} dialect={} target={target}",
        now_ms(),
        dialect.name()
    ));

    // --- upstream ---
    // Through vigil's own resolver, not the system's, and the answer is logged. This line was
    // measured answering `updates.discord.com` with the block page `195.175.254.2` while the
    // instrument was still asking the OS — a capture taken then would have recorded the block
    // page's behaviour under the name of the real server, which is worse than no capture.
    let (host, port) = split_target(&target);
    let addrs: Vec<SocketAddr> = resolver.resolve(host, port);
    if addrs.is_empty() {
        log.line(&format!("t={} conn={id} err=resolve({target})", now_ms()));
        return;
    }
    log.line(&format!(
        "t={} conn={id} resolved={}",
        now_ms(),
        addrs
            .iter()
            .map(|a| a.ip().to_string())
            .collect::<Vec<_>>()
            .join(",")
    ));
    let mut upstream = None;
    for a in &addrs {
        if let Ok(s) = TcpStream::connect_timeout(a, Duration::from_secs(10)) {
            upstream = Some(s);
            break;
        }
    }
    let Some(mut upstream) = upstream else {
        log.line(&format!("t={} conn={id} err=connect-failed", now_ms()));
        match dialect {
            Dialect::Socks4 => {
                let _ = client.write_all(&socks4::reply(socks4::REJECTED));
            }
            Dialect::Socks5 => {
                let _ = client.write_all(&socks5::reply(socks5::Rep::HostUnreachable));
            }
            _ => {}
        }
        return;
    };
    let _ = upstream.set_nodelay(true);
    let _ = upstream.set_read_timeout(Some(Duration::from_secs(60)));
    let _ = upstream.set_write_timeout(Some(Duration::from_secs(60)));

    let ok = match dialect {
        Dialect::Socks4 => client.write_all(&socks4::reply(socks4::GRANTED)).is_ok(),
        Dialect::Socks5 => client
            .write_all(&socks5::reply(socks5::Rep::Succeeded))
            .is_ok(),
        _ => true,
    };
    if !ok {
        return;
    }

    // --- the first flight: the whole reason this tool exists ---
    if buf.is_empty() {
        let mut big = [0u8; 8192];
        match client.read(&mut big) {
            Ok(0) | Err(_) => {
                let _ = upstream.shutdown(Shutdown::Both);
                return;
            }
            Ok(n) => buf.extend_from_slice(&big[..n]),
        }
    }
    let (sni, truncated) = match vigil_core::clienthello::parse(&buf) {
        Ok(ch) => (
            ch.host_str().unwrap_or("-").to_string(),
            ch.is_record_truncated(),
        ),
        Err(e) => (format!("<{e:?}>"), false),
    };
    log.line(&format!(
        "t={} conn={id} src={src} target={target} flight_len={} sni={sni} ch_truncated={truncated}",
        now_ms(),
        buf.len()
    ));

    // The captured first flight, byte for byte. Used to replay a real client's ClientHello
    // through the measurement tool, which is the only way to tell "my synthetic hello differs"
    // from "the network differs".
    if let Some(path) = dump {
        let _ = std::fs::write(format!("{path}.{sni}.bin"), &buf);
    }

    let plan = strategy.plan(&buf);
    for chunk in &plan.writes {
        if chunk.delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(chunk.delay_ms as u64));
        }
        if upstream.write_all(&chunk.bytes).is_err() {
            let _ = client.shutdown(Shutdown::Both);
            return;
        }
    }

    // --- did it survive? the answer is the measurement ---
    let mut early = Vec::new();
    let _ = upstream.set_read_timeout(Some(Duration::from_millis(4000)));
    let mut peek = [0u8; 8192];
    let outcome = match upstream.read(&mut peek) {
        Ok(0) => "eof".to_string(),
        Ok(n) => {
            early.extend_from_slice(&peek[..n]);
            format!("reply({n}B)")
        }
        Err(e) => match e.kind() {
            ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted => "rst".to_string(),
            ErrorKind::WouldBlock | ErrorKind::TimedOut => "timeout".to_string(),
            other => format!("err({other:?})"),
        },
    };
    log.line(&format!(
        "t={} conn={id} src={src} target={target} sni={sni} outcome={outcome}",
        now_ms()
    ));
    let _ = upstream.set_read_timeout(Some(Duration::from_secs(60)));
    if !early.is_empty() && client.write_all(&early).is_err() {
        return;
    }

    let (mut c2, mut u2) = match (client.try_clone(), upstream.try_clone()) {
        (Ok(c), Ok(u)) => (c, u),
        _ => return,
    };
    let up = std::thread::spawn(move || {
        let _ = copy(&mut c2, &mut u2);
        let _ = u2.shutdown(Shutdown::Write);
    });
    let _ = copy(&mut upstream, &mut client);
    let _ = client.shutdown(Shutdown::Write);
    let _ = up.join();
}

fn copy(from: &mut TcpStream, to: &mut TcpStream) -> std::io::Result<u64> {
    let mut buf = vec![0u8; 32 * 1024];
    let mut total = 0u64;
    loop {
        match from.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => {
                to.write_all(&buf[..n])?;
                total += n as u64;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Ok(total),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The target string is what decides which name the resolver is asked for. Get it wrong
    /// and the instrument connects somewhere the log does not name.
    #[test]
    fn a_target_splits_into_the_name_the_resolver_is_asked_for() {
        assert_eq!(
            split_target("updates.discord.com:443"),
            ("updates.discord.com", 443)
        );
        assert_eq!(split_target("example.com:8443"), ("example.com", 8443));
        assert_eq!(split_target("example.com"), ("example.com", 443));
        assert_eq!(
            split_target("162.159.136.232:443"),
            ("162.159.136.232", 443)
        );
        assert_eq!(split_target("[::1]:443"), ("::1", 443));
        assert_eq!(
            split_target("[2606:4700::1111]:8443"),
            ("2606:4700::1111", 8443)
        );
        // a port that is not a number must not become part of the hostname
        assert_eq!(split_target("example.com:https"), ("example.com", 443));
    }
}
