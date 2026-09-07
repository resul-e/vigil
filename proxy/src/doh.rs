//! The DoH instrument: one exchange with one resolver, addressed by IP literal.
//!
//! This exists to answer the question that can kill the whole DoH plan cheaply, before a line of
//! resolver code is written: **does this line carry an SNI-less TLS flight to a resolver's address
//! on :443, and does a DNS answer come back through it?**
//!
//! Two things shape the file.
//!
//! **An endpoint is an address, not a name.** [`Endpoint`] holds an `IpAddr` and there is no
//! constructor taking a string. DoH needs HTTPS, HTTPS needs a name, a name needs DNS — so a DoH
//! client that could be handed a hostname is one that can deadlock on its own first query. Here
//! that is not a rule to remember, it is a type that cannot express the mistake.
//!
//! **The verdict distinguishes silence from refusal.** [`Phase::Hello`] means the flight went out
//! and *not one byte* ever came back; [`Phase::Answered`] means the peer spoke, whatever it said.
//! A fatal alert and a certificate failure are the server's policy and say nothing about the line;
//! a reset at 2 ms and a timeout are the line. Collapsing those into "it failed" is how a
//! measurement produces a number that means two different things.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::plan_first_write;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use vigil_core::doh;
use vigil_core::strategy::Strategy;

/// Where a DoH resolver is, as an address. **No hostname field, and no constructor from a string.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
    pub path: &'static str,
}

impl Endpoint {
    pub fn new(ip: IpAddr) -> Self {
        Endpoint {
            ip,
            port: 443,
            path: "/dns-query",
        }
    }

    pub fn addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }
}

/// What the peer said, once it said anything at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// A fatal TLS alert. The server's policy — most often "this connection carried no SNI and I
    /// am a name-based virtual host". Not a finding about the line.
    Alert(String),
    /// The certificate did not validate. For an IP literal that usually means the certificate
    /// carries no matching iPAddress SAN, which is a fact about that resolver.
    Cert(String),
    /// The handshake completed.
    Handshake,
}

/// How far the exchange got, and why it stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    /// No TCP connection.
    Connect(String),
    /// The flight was written and nothing ever came back. **This is the censorship shape**, and
    /// the two flags separate its two forms — a reset arriving in milliseconds is an injector, a
    /// timeout is a silent drop. Both false means the peer closed cleanly without speaking.
    Hello { reset: bool, timeout: bool },
    /// The peer sent bytes. Whatever happened next is above the line, not on it.
    Answered(Answer),
    /// The HTTP head was refused. Carries the reason, because a 200 `text/html` is a sinkhole and
    /// a 403 is a resolver declining, and those are different findings.
    Http(String),
    /// The body arrived and would not read as a DNS answer.
    Body(String),
    /// A complete answer. The end state.
    Addresses(Vec<Ipv4Addr>),
}

impl Phase {
    /// Did the peer ever speak? The gate for "the line carried it" is this, not success.
    pub fn peer_spoke(&self) -> bool {
        !matches!(self, Phase::Connect(_) | Phase::Hello { .. })
    }
}

/// One exchange, with everything a report needs to be read honestly.
#[derive(Debug, Clone)]
pub struct Exchange {
    pub phase: Phase,
    pub connect_ms: u128,
    /// **From the last byte of the first flight to the first byte back**, not from the start of the
    /// attempt. On the measured line the injector answers in 2 ms and the far end in 4 ms, and this
    /// project has twice spent a day on a reset whose latency nobody read.
    pub reply_ms: Option<u128>,
    pub client_hello_len: usize,
    /// What the transform **actually did**, from the plan — never the strategy that was asked for.
    /// A transform that cannot apply writes the flight whole and records the truth only here.
    pub applied: Vec<&'static str>,
    pub writes: Vec<usize>,
    pub status: Option<u16>,
    pub content_type: Option<String>,
}

/// How long each part of one exchange may take.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub connect: Duration,
    pub stall: Duration,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            connect: Duration::from_secs(5),
            stall: Duration::from_secs(5),
        }
    }
}

/// Why a DoH query produced no answer.
///
/// Every variant maps to [`crate::resolver::Reply::Silent`] — a transport failure teaches nothing
/// about the name — but they are kept apart because *which* one fired is the difference between
/// "the line ate it", "the resolver refused us" and "our own client is wrong", and a counter that
/// cannot tell those apart is a counter nobody can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DohError {
    /// The budget ran out. **One budget for the whole exchange**, never one per stage.
    Timeout,
    Io(String),
    Tls(String),
    /// The server refused the protocol we offered.
    Alpn,
    Http(u16),
    ContentType(String),
    Chunked,
    HeadTooLong,
    LengthRequired,
    TooLarge(u64),
    /// The head promised more body than arrived before the connection closed.
    Short {
        want: usize,
        got: usize,
    },
    /// **Never followed.** A redirect is how a middlebox steers a query somewhere else, and there
    /// is no allowlist here to re-check the new destination against.
    Redirect,
    Malformed(String),
}

impl core::fmt::Display for DohError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DohError::Timeout => f.write_str("timed out"),
            DohError::Io(e) => write!(f, "io: {e}"),
            DohError::Tls(e) => write!(f, "tls: {e}"),
            DohError::Alpn => f.write_str("the server refused http/1.1"),
            DohError::Http(s) => write!(f, "HTTP {s}"),
            DohError::ContentType(t) => write!(f, "content-type {t:?}"),
            DohError::Chunked => f.write_str("chunked framing, not implemented"),
            DohError::HeadTooLong => f.write_str("response head too long"),
            DohError::LengthRequired => f.write_str("no Content-Length"),
            DohError::TooLarge(n) => write!(f, "body {n} B, over the limit"),
            DohError::Short { want, got } => write!(f, "body {got} of {want} B"),
            DohError::Redirect => f.write_str("redirect, which is never followed"),
            DohError::Malformed(w) => write!(f, "malformed: {w}"),
        }
    }
}

/// A line a person can act on, as a **value** rather than an `eprintln!`.
///
/// libtest cannot read back its own standard error, so a diagnostic that only prints is a
/// diagnostic no test can assert. This carries rustls' own `expected`/`presented` lists through,
/// which is the difference between "TLS failed" and "that certificate has no address in it".
pub fn describe(e: &DohError) -> String {
    format!("doh: {e}")
}

impl From<vigil_core::doh::Error> for DohError {
    fn from(e: vigil_core::doh::Error) -> Self {
        use vigil_core::doh::Error as E;
        match e {
            E::Malformed(w) => DohError::Malformed(w),
            E::Chunked(_) => DohError::Chunked,
            E::HeadTooLong => DohError::HeadTooLong,
            // 3xx is refused before it is anything else: a redirect is a steer, not a status.
            E::Status(s) if (300..400).contains(&s) => DohError::Redirect,
            E::Status(s) => DohError::Http(s),
            E::NotDnsMessage(t) => DohError::ContentType(t),
            E::LengthRequired => DohError::LengthRequired,
            E::BodyTooLarge(n) => DohError::TooLarge(n),
        }
    }
}

/// Point every socket timeout at **the one deadline**, and refuse when there is nothing left.
///
/// The `?` is load-bearing and the model this was copied from throws it away
/// (`let _ = sock.set_read_timeout(...)`). `set_read_timeout` errors on a zero duration, and on
/// Windows on anything rounding to 0 ms — so a discarded result at the end of the budget leaves the
/// last read running with the *previous*, longer timeout. On the thread behind `127.0.0.1:53`, for
/// the whole machine, that is an unbounded blocking read.
fn arm(sock: &TcpStream, deadline: Instant) -> Result<Duration, DohError> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left < Duration::from_millis(1) {
        return Err(DohError::Timeout);
    }
    sock.set_read_timeout(Some(left))
        .map_err(|e| DohError::Io(e.to_string()))?;
    sock.set_write_timeout(Some(left))
        .map_err(|e| DohError::Io(e.to_string()))?;
    Ok(left)
}

/// The request, the head and the body — over anything that reads and writes.
///
/// Knows nothing of TLS, which is what lets every HTTP failure shape be tested over a plain socket
/// in milliseconds. **Bounded in bytes as well as in time**: a server that streams without ever
/// ending its head, or that promises 70 000 bytes, is refused at the head rather than at the
/// deadline. Time-bounded and byte-unbounded is a real hole — 1.5 s of whatever the link delivers,
/// times the workers the DNS server allows at once.
pub fn exchange_over<S: Read + Write>(
    io: &mut S,
    host_header: &str,
    path: &str,
    query: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, DohError> {
    let req = doh::request(host_header, path, query);
    io.write_all(&req)
        .map_err(|e| DohError::Io(e.to_string()))?;
    io.flush().map_err(|e| DohError::Io(e.to_string()))?;

    let mut buf: Vec<u8> = Vec::new();
    let mut head: Option<doh::Head> = None;
    let mut want = 0usize;
    loop {
        if Instant::now() >= deadline {
            return Err(DohError::Timeout);
        }
        // Never read past what the head promised.
        let room = match &head {
            Some(h) => (h.head_len + want).saturating_sub(buf.len()),
            None => doh::MAX_HEAD + 1 - buf.len().min(doh::MAX_HEAD),
        };
        if room == 0 {
            break;
        }
        let mut chunk = vec![0u8; room.min(4096)];
        let n = match io.read(&mut chunk) {
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(DohError::Timeout)
            }
            Err(e) => return Err(DohError::Io(e.to_string())),
        };
        if n == 0 {
            let got = head.as_ref().map_or(buf.len(), |h| buf.len() - h.head_len);
            return Err(DohError::Short { want, got });
        }
        buf.extend_from_slice(&chunk[..n]);

        if head.is_none() {
            match doh::parse_head(&buf) {
                Ok(None) => {
                    if buf.len() > doh::MAX_HEAD {
                        return Err(DohError::HeadTooLong);
                    }
                    continue;
                }
                Ok(Some(h)) => {
                    // Accepted or refused the instant the head is complete, before another byte is
                    // read. A body we will not parse must not be read at all.
                    want = doh::accept(&h)?;
                    head = Some(h);
                }
                Err(e) => return Err(e.into()),
            }
        }
        if let Some(h) = &head {
            if buf.len() >= h.head_len + want {
                break;
            }
        }
    }
    let h = head.ok_or(DohError::HeadTooLong)?;
    doh::body_of(&buf, &h)
        .map(<[u8]>::to_vec)
        .ok_or(DohError::Short {
            want,
            got: buf.len().saturating_sub(h.head_len),
        })
}

/// The TLS configuration for a DoH exchange.
///
/// One classical key-exchange group and no post-quantum share, for the reason the updater's client
/// records: rustls' default ClientHello is about 1730 B, the kernel splits it before it reaches the
/// wire, and our own transform is then meaningless. A test asserts the resulting flight fits one
/// segment, so this is not a comment anybody has to remember.
pub fn tls_config(alpn: bool) -> Arc<ClientConfig> {
    client_config(
        RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        },
        alpn,
    )
}

/// **The one builder**, used by production and by every test.
///
/// A test that assembles its own config — to swap in a fixture root, say — is a test that proves
/// something about a configuration nothing ships. So the roots are a parameter and everything else
/// is fixed here, where one change reaches both.
pub fn client_config(roots: RootCertStore, alpn: bool) -> Arc<ClientConfig> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("default protocol versions are always valid")
        .with_root_certificates(roots)
        .with_no_client_auth();
    // No session resumption: a resumed handshake sends a different ClientHello, and the second
    // trial of a run would then be a different experiment from the first.
    cfg.resumption = rustls::client::Resumption::disabled();
    if alpn {
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    }
    Arc::new(cfg)
}

/// The only place in this file that builds a connection, and the only place that names a peer.
///
/// Building it from an `IpAddr` is what omits SNI: rustls writes the server-name extension only
/// for the DNS-name form, and RFC 6066 §3 forbids a literal address there. A test reads this
/// file's own text to assert there is exactly one such call, so a second one cannot appear
/// somewhere else and quietly send a name.
pub fn client(ep: &Endpoint, alpn: bool) -> Result<ClientConnection, rustls::Error> {
    client_with(&tls_config(alpn), ep)
}

/// The same door, with a configuration the caller already holds.
///
/// The production path needs this — the resolver builds its two configurations once and keeps
/// them — and it must not be a *second* door: a place that builds its own connection could pass a
/// name, and the test that reads this file's text would still be green because it only knows about
/// the door it was told about.
pub fn client_with(
    cfg: &Arc<ClientConfig>,
    ep: &Endpoint,
) -> Result<ClientConnection, rustls::Error> {
    ClientConnection::new(cfg.clone(), ep.ip.into())
}

/// The bytes rustls wants to send first, captured rather than written.
pub fn first_flight(conn: &mut ClientConnection) -> Vec<u8> {
    let mut flight = Vec::new();
    while conn.wants_write() {
        if conn.write_tls(&mut flight).is_err() {
            break;
        }
    }
    flight
}

/// The plaintext channel of a hand-driven TLS connection, as something that reads and writes.
///
/// `rustls::Stream`, `StreamOwned` and `complete_io` are **not** used, and that is the point: they
/// loop internally until a *socket* timeout, which a server dribbling one byte every 100 ms never
/// trips. Every operation here re-points the socket timeout at the one deadline first, so a
/// trickler is refused at the budget rather than at the end of time.
struct TlsIo<'a> {
    conn: &'a mut ClientConnection,
    sock: &'a mut TcpStream,
    deadline: Instant,
}

fn as_io(e: DohError) -> std::io::Error {
    match e {
        DohError::Timeout => std::io::Error::new(std::io::ErrorKind::TimedOut, "budget"),
        other => std::io::Error::other(other.to_string()),
    }
}

impl Read for TlsIo<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        loop {
            match self.conn.reader().read(out) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
            arm(self.sock, self.deadline).map_err(as_io)?;
            if self.conn.read_tls(self.sock)? == 0 {
                return Ok(0);
            }
            self.conn
                .process_new_packets()
                .map_err(|e| std::io::Error::other(e.to_string()))?;
        }
    }
}

impl Write for TlsIo<'_> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.conn.writer().write(data)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        while self.conn.wants_write() {
            arm(self.sock, self.deadline).map_err(as_io)?;
            self.conn.write_tls(self.sock)?;
        }
        Ok(())
    }
}

/// **The production path**: one question to one DoH endpoint, inside one budget.
///
/// The budget is the resolver's own per-upstream timeout and covers *everything* — connect,
/// handshake, request, response. Never the updater's deadlines, which are seconds apiece: inside a
/// DNS worker that is a fifteen-second slot hold per dark query, and the server behind
/// `127.0.0.1:53` allows a hundred and twenty-eight of those at once.
///
/// The first flight is written whole, with no transform. On the measured line an SNI-less flight
/// is carried 96/96 with and without one, and there is no server name here for an SNI matcher to
/// read — so a transform would add a moving part to the hot path and buy nothing measured.
pub fn query(
    ep: &Endpoint,
    cfg: &Arc<ClientConfig>,
    question: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, DohError> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left < Duration::from_millis(1) {
        return Err(DohError::Timeout);
    }
    let mut conn = client_with(cfg, ep).map_err(|e| DohError::Tls(e.to_string()))?;
    let mut sock =
        TcpStream::connect_timeout(&ep.addr(), left).map_err(|e| DohError::Io(e.to_string()))?;
    let _ = sock.set_nodelay(true);

    // The handshake, with the deadline checked every time round rather than trusted to a socket.
    while conn.is_handshaking() {
        if Instant::now() >= deadline {
            return Err(DohError::Timeout);
        }
        if conn.wants_write() {
            arm(&sock, deadline)?;
            conn.write_tls(&mut sock)
                .map_err(|e| DohError::Io(e.to_string()))?;
            continue;
        }
        arm(&sock, deadline)?;
        match conn.read_tls(&mut sock) {
            Ok(0) => return Err(DohError::Tls("closed during the handshake".into())),
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(DohError::Timeout)
            }
            Err(e) => return Err(DohError::Io(e.to_string())),
        }
        conn.process_new_packets().map_err(|e| classify_tls(&e))?;
    }

    let host = doh::host_header(ep.ip);
    let mut io = TlsIo {
        conn: &mut conn,
        sock: &mut sock,
        deadline,
    };
    exchange_over(&mut io, &host, ep.path, question, deadline)
}

/// rustls' own error, kept apart where the distinction matters.
fn classify_tls(e: &rustls::Error) -> DohError {
    match e {
        // The server has protocols configured and none of them is ours.
        rustls::Error::NoApplicationProtocol => DohError::Alpn,
        other => DohError::Tls(format!("{other:?}")),
    }
}

/// One exchange. `query` of `None` stops after the handshake.
pub fn exchange(
    ep: &Endpoint,
    query: Option<&[u8]>,
    strategy: &Strategy,
    alpn: bool,
    budget: Budget,
) -> Exchange {
    let mut out = Exchange {
        phase: Phase::Connect(String::new()),
        connect_ms: 0,
        reply_ms: None,
        client_hello_len: 0,
        applied: Vec::new(),
        writes: Vec::new(),
        status: None,
        content_type: None,
    };

    let mut conn = match client(ep, alpn) {
        Ok(c) => c,
        Err(e) => {
            out.phase = Phase::Connect(format!("tls init: {e}"));
            return out;
        }
    };

    let started = Instant::now();
    let mut sock = match TcpStream::connect_timeout(&ep.addr(), budget.connect) {
        Ok(s) => s,
        Err(e) => {
            out.phase = Phase::Connect(e.to_string());
            out.connect_ms = started.elapsed().as_millis();
            return out;
        }
    };
    out.connect_ms = started.elapsed().as_millis();
    let _ = sock.set_nodelay(true);
    let _ = sock.set_read_timeout(Some(budget.stall));
    let _ = sock.set_write_timeout(Some(budget.stall));

    // The first flight, captured and then written our way. This is the whole technique.
    let flight = first_flight(&mut conn);
    out.client_hello_len = flight.len();
    let plan = plan_first_write(&flight, strategy);
    out.applied = plan.applied.clone();
    out.writes = plan.writes.iter().map(|w| w.bytes.len()).collect();
    for w in &plan.writes {
        if sock.write_all(&w.bytes).is_err() {
            out.phase = Phase::Hello {
                reset: true,
                timeout: false,
            };
            return out;
        }
        if w.delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(w.delay_ms as u64));
        }
    }
    let wrote_at = Instant::now();

    // --- the handshake, byte by byte, so silence and refusal stay distinguishable ---
    let mut heard = false;
    loop {
        if conn.wants_write() {
            // Everything after the first flight goes out normally.
            if conn.write_tls(&mut sock).is_err() {
                out.phase = Phase::Hello {
                    reset: true,
                    timeout: false,
                };
                return out;
            }
            continue;
        }
        match conn.read_tls(&mut sock) {
            Ok(0) => {
                if !heard {
                    // A clean close with nothing said. Neither a reset nor a timeout.
                    out.phase = Phase::Hello {
                        reset: false,
                        timeout: false,
                    };
                    return out;
                }
                out.phase = Phase::Answered(Answer::Alert("closed mid-handshake".into()));
                return out;
            }
            Ok(_) => {
                if !heard {
                    heard = true;
                    out.reply_ms = Some(wrote_at.elapsed().as_millis());
                }
            }
            Err(e) => {
                if !heard {
                    let reset = e.kind() == std::io::ErrorKind::ConnectionReset;
                    let timeout = matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    );
                    out.phase = Phase::Hello { reset, timeout };
                    return out;
                }
                out.phase = Phase::Answered(Answer::Alert(format!("read: {e}")));
                return out;
            }
        }
        if let Err(e) = conn.process_new_packets() {
            out.phase = Phase::Answered(match &e {
                rustls::Error::InvalidCertificate(c) => Answer::Cert(format!("{c:?}")),
                other => Answer::Alert(other.to_string()),
            });
            return out;
        }
        if !conn.is_handshaking() {
            break;
        }
    }

    let Some(q) = query else {
        out.phase = Phase::Answered(Answer::Handshake);
        return out;
    };

    // --- the request ---
    let req = doh::request(&doh::host_header(ep.ip), ep.path, q);
    if conn.writer().write_all(&req).is_err() {
        out.phase = Phase::Http("could not write the request".into());
        return out;
    }
    while conn.wants_write() {
        if conn.write_tls(&mut sock).is_err() {
            out.phase = Phase::Http("could not flush the request".into());
            return out;
        }
    }

    // --- the response ---
    let mut plain = Vec::new();
    let mut head: Option<doh::Head> = None;
    let mut want = 0usize;
    loop {
        match conn.read_tls(&mut sock) {
            Ok(0) => {
                out.phase = Phase::Body("closed before the body arrived".into());
                return out;
            }
            Ok(_) => {}
            Err(e) => {
                out.phase = Phase::Body(format!("read: {e}"));
                return out;
            }
        }
        if let Err(e) = conn.process_new_packets() {
            out.phase = Phase::Body(format!("tls: {e}"));
            return out;
        }
        let mut chunk = [0u8; 4096];
        loop {
            match conn.reader().read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => plain.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }

        if head.is_none() {
            match doh::parse_head(&plain) {
                Ok(None) => continue,
                Ok(Some(h)) => {
                    out.status = Some(h.status);
                    out.content_type = h.content_type.clone();
                    // Accepted or refused the instant the head is complete, before another byte is
                    // read. A body we are not going to parse must not be read at all.
                    match doh::accept(&h) {
                        Ok(n) => want = n,
                        Err(e) => {
                            out.phase = Phase::Http(e.to_string());
                            return out;
                        }
                    }
                    head = Some(h);
                }
                Err(e) => {
                    out.phase = Phase::Http(e.to_string());
                    return out;
                }
            }
        }

        if let Some(h) = &head {
            if plain.len() >= h.head_len + want {
                let Some(body) = doh::body_of(&plain, h) else {
                    out.phase = Phase::Body("body did not arrive".into());
                    return out;
                };
                out.phase = match vigil_core::dnsmsg::decode_answers(body, 0) {
                    Ok(addrs) => Phase::Addresses(addrs),
                    Err(e) => Phase::Body(format!("{e:?}")),
                };
                return out;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_pki_types::ServerName;

    fn ep() -> Endpoint {
        Endpoint::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
    }

    use std::net::TcpListener;

    /// A stub that writes one canned response and closes.
    fn http_stub(response: Vec<u8>) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        let at = l.local_addr().expect("addr");
        std::thread::spawn(move || {
            for stream in l.incoming().take(1) {
                let Ok(mut s) = stream else { continue };
                let mut junk = [0u8; 2048];
                let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
                let _ = s.read(&mut junk);
                let _ = s.write_all(&response);
                let _ = s.flush();
            }
        });
        at
    }

    /// A listener that **accepts and holds** and never writes a byte.
    ///
    /// It has to accept: a listener that never calls `accept` has a backlog, and on Windows the
    /// connection is refused instantly once it fills — which turns a timeout test into a
    /// connection-refused test that passes for the wrong reason.
    fn tcp_hole() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        let at = l.local_addr().expect("addr");
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in l.incoming() {
                match stream {
                    Ok(s) => held.push(s),
                    Err(_) => break,
                }
            }
        });
        at
    }

    fn over_tcp(at: SocketAddr, budget: Duration) -> Result<Vec<u8>, DohError> {
        let mut sock = TcpStream::connect(at).expect("connect");
        sock.set_read_timeout(Some(budget)).expect("timeout");
        sock.set_write_timeout(Some(budget)).expect("timeout");
        exchange_over(
            &mut sock,
            "127.0.0.1",
            "/dns-query",
            b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01",
            Instant::now() + budget,
        )
    }

    /// **Every HTTP failure shape, by variant, over a plain socket in milliseconds.**
    ///
    /// This is what splitting the HTTP layer off from TLS buys. Asserting the variant and not
    /// `is_err()` is what stops a neighbouring check covering for a deleted one.
    #[test]
    fn each_http_failure_shape_is_refused_as_itself() {
        let two = Duration::from_secs(2);

        let five_hundred = http_stub(
            b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/dns-message\r\nContent-Length: 0\r\n\r\n".to_vec(),
        );
        assert_eq!(over_tcp(five_hundred, two), Err(DohError::Http(500)));

        let html = http_stub(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 3\r\n\r\nabc".to_vec(),
        );
        assert_eq!(
            over_tcp(html, two),
            Err(DohError::ContentType("text/html".into())),
            "a 200 carrying a block page is the sinkhole shape"
        );

        let chunked = http_stub(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
        );
        assert_eq!(over_tcp(chunked, two), Err(DohError::Chunked));

        let short = http_stub(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 100\r\n\r\n0123456789".to_vec(),
        );
        assert_eq!(
            over_tcp(short, two),
            Err(DohError::Short { want: 100, got: 10 })
        );

        let no_len =
            http_stub(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n\r\n".to_vec());
        assert_eq!(over_tcp(no_len, two), Err(DohError::LengthRequired));

        let redirect = http_stub(
            b"HTTP/1.1 302 Found\r\nLocation: https://elsewhere.invalid/dns-query\r\nContent-Length: 0\r\n\r\n".to_vec(),
        );
        assert_eq!(
            over_tcp(redirect, two),
            Err(DohError::Redirect),
            "a redirect is how a middlebox steers a query, and there is no allowlist to re-check"
        );
    }

    /// **Refused at the head, not at the deadline.** A body larger than RFC 8484 permits must cost
    /// nothing: the head says so before a byte of it is read.
    #[test]
    fn an_oversized_body_is_refused_before_it_is_read() {
        let big = http_stub(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 70000\r\n\r\n".to_vec(),
        );
        let started = Instant::now();
        assert_eq!(
            over_tcp(big, Duration::from_secs(2)),
            Err(DohError::TooLarge(70000))
        );
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "refused at the head, not waited out: {:?}",
            started.elapsed()
        );
    }

    /// A head that never ends is refused by **bytes**, not by time. Time-bounded and
    /// byte-unbounded is a real hole: whatever the link delivers inside the budget, times every
    /// worker the DNS server allows at once.
    #[test]
    fn a_head_that_never_ends_is_refused_by_bytes() {
        let mut forever = b"HTTP/1.1 200 OK\r\n".to_vec();
        forever.extend(std::iter::repeat_n(b'x', vigil_core::doh::MAX_HEAD + 64));
        let at = http_stub(forever);
        assert_eq!(
            over_tcp(at, Duration::from_secs(5)),
            Err(DohError::HeadTooLong)
        );
    }

    /// **The deadline is the whole exchange, and it is asserted on `query`.**
    ///
    /// Never on `lookup`: `ask_all` returns at its own deadline whatever a detached worker is
    /// doing, so a bound measured there is green even with the deadline removed. Run on a thread
    /// and collected with a timeout, so a hang is a red test rather than a hung suite.
    #[test]
    fn a_black_hole_costs_exactly_the_budget_and_no_more() {
        let at = tcp_hole();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let ep = Endpoint {
                ip: at.ip(),
                port: at.port(),
                path: "/dns-query",
            };
            let started = Instant::now();
            let r = query(
                &ep,
                &tls_config(true),
                b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01",
                Instant::now() + Duration::from_millis(300),
            );
            let _ = tx.send((r, started.elapsed()));
        });
        let (r, took) = rx
            .recv_timeout(Duration::from_secs(3))
            .expect("query hung past its budget");
        assert_eq!(r, Err(DohError::Timeout));
        assert!(
            took >= Duration::from_millis(300) && took < Duration::from_millis(900),
            "one budget for the whole exchange, not one per stage: {took:?}"
        );
    }

    /// **The flight has to fit one segment**, or the kernel splits it before our transform does and
    /// every measurement made with it is about the kernel.
    ///
    /// The 200 B of headroom is the record and TCP overhead the flight is measured against in the
    /// same way the updater's client measures its own.
    #[test]
    fn the_doh_first_flight_fits_one_segment() {
        let mut c = client(&ep(), true).expect("builds");
        let f = first_flight(&mut c);
        assert!(!f.is_empty());
        assert!(
            f.len() + 200 <= vigil_core::TYPICAL_MSS,
            "flight is {} B; over one segment the kernel splits it for us",
            f.len()
        );
    }

    /// **No SNI, and the parser can tell.**
    ///
    /// The negative arm alone is worthless: a parser that returns `None` for everything passes it.
    /// The positive arm in the same test is what makes the negative one mean something.
    #[test]
    fn the_doh_flight_carries_no_sni_and_the_parser_can_tell() {
        let mut c = client(&ep(), true).expect("builds");
        let f = first_flight(&mut c);
        let hello = vigil_core::clienthello::parse(&f).expect("a ClientHello");
        assert!(
            hello.sni().is_none(),
            "an IP literal must send no server name"
        );

        let name = ServerName::try_from("dns.example".to_string()).expect("a name");
        let mut named = ClientConnection::new(tls_config(true), name).expect("builds");
        let nf = first_flight(&mut named);
        let named_hello = vigil_core::clienthello::parse(&nf).expect("a ClientHello");
        assert!(
            named_hello.sni().is_some(),
            "the parser must find a name when there is one, or the arm above proves nothing"
        );
    }

    /// **One door.** If a second place built a connection it could quietly pass a name, and the
    /// test above would still be green because it only looks at the door it knows about.
    #[test]
    fn client_is_the_only_place_a_connection_is_built() {
        let src = include_str!("doh.rs");
        let production = src.split("#[cfg(test)]").next().expect("source");
        assert_eq!(
            production.matches("ClientConnection::new(").count(),
            1,
            "exactly one connection is built, in `client_with` — every other path goes through it"
        );
        assert_eq!(
            production.matches("ServerName").count(),
            0,
            "no name type is ever named outside the tests"
        );
    }

    #[test]
    fn the_doh_tls_config_does_not_resume() {
        let cfg = tls_config(true);
        // Compared by its own Debug rendering, which is what the updater's equivalent test does:
        // `Resumption` exposes no public variants to match on. The updater records why its own
        // version of this test was rewritten: it used to assert `Arc::strong_count(&cfg) >= 1`,
        // which is true of every Arc ever created, so the line it claimed to guard could have
        // been deleted freely.
        assert_eq!(
            format!("{:?}", cfg.resumption),
            format!("{:?}", rustls::client::Resumption::disabled()),
            "a resumed handshake is a different ClientHello and a different experiment"
        );
    }

    /// The measured default must apply to an SNI-less hello too — a transform that quietly needs a
    /// server name would make the live strategy column a lie.
    #[test]
    fn the_measured_default_applies_to_an_sni_less_hello() {
        let mut c = client(&ep(), true).expect("builds");
        let f = first_flight(&mut c);
        let plan = plan_first_write(&f, &Strategy::measured_default());
        assert_eq!(plan.applied, vec!["tlsrec", "split"], "{:?}", plan.applied);
        assert_eq!(
            plan.writes[0].bytes.len(),
            1,
            "the first segment is one byte"
        );
        // **Two writes, not more, and that is the design.** `tlsrec` reframes the record layer
        // *inside* the byte stream and `split` cuts the stream once. Measured here rather than
        // assumed: the first draft of this test asserted three or more and was simply wrong.
        assert_eq!(
            plan.writes.len(),
            2,
            "one byte, then the rest: {:?}",
            plan.writes
                .iter()
                .map(|w| w.bytes.len())
                .collect::<Vec<_>>()
        );
        // The evidence that `tlsrec` really ran: every record it inserts costs a five-byte header,
        // so the bytes on the wire outnumber the bytes rustls produced. A `tlsrec` that silently
        // did nothing would leave these equal with `applied` still claiming it had.
        let total: usize = plan.writes.iter().map(|w| w.bytes.len()).sum();
        assert!(
            total > f.len(),
            "tlsrec inserts record headers: {total} on the wire against {} from rustls",
            f.len()
        );
    }

    /// ALPN is a run parameter, not a constant: a resolver that has retired HTTP/1.1 answers
    /// differently, and telling that apart from the line requires both arms in the same sweep.
    #[test]
    fn alpn_is_offered_only_when_asked() {
        assert_eq!(tls_config(true).alpn_protocols, vec![b"http/1.1".to_vec()]);
        assert!(tls_config(false).alpn_protocols.is_empty());
    }

    #[test]
    fn an_endpoint_defaults_to_the_rfc_path_on_443() {
        let e = ep();
        assert_eq!(e.port, 443);
        assert_eq!(e.path, "/dns-query");
        assert_eq!(e.addr().to_string(), "1.1.1.1:443");
    }

    /// Silence and refusal are different verdicts, and the type must keep them apart.
    #[test]
    fn only_a_flight_that_drew_nothing_counts_as_the_line() {
        assert!(!Phase::Hello {
            reset: true,
            timeout: false
        }
        .peer_spoke());
        assert!(!Phase::Connect("x".into()).peer_spoke());
        assert!(Phase::Answered(Answer::Alert("handshake_failure".into())).peer_spoke());
        assert!(Phase::Answered(Answer::Handshake).peer_spoke());
        assert!(Phase::Addresses(vec![]).peer_spoke());
    }
}
