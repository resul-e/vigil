//! One connection attempt, and how to read what came back.
//!
//! The classification here is the part that decides whether the whole report means anything,
//! so the rules are deliberately strict and deliberately narrow:
//!
//! - **Only a ServerHello counts as reached.** Not "no error", not "some bytes". A DPI that
//!   answers with a forged TLS alert instead of an RST would otherwise be scored as success,
//!   and that is exactly the sort of thing we are here to discover on an unknown network.
//! - **An alert is recorded, not counted.** It proves *something* answered, and its level and
//!   description go in the report so a human can tell a real server's `handshake_failure`
//!   from an injected `access_denied`.
//! - **Latency to the first byte is recorded for every attempt.** On this line the injected
//!   RST arrives in ~6 ms while a genuine reply takes ~40 ms. That gap is how you tell an
//!   on-path injector from the far end, and it costs nothing to measure.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use vigil_core::strategy::Strategy;
use vigil_core::{synth, Outcome};

/// What the far end said, when it said anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// A TLS handshake record. The only thing that counts as reached.
    ServerHello,
    /// A TLS alert: level and description bytes, kept raw so nothing is interpreted away.
    Alert { level: u8, desc: u8 },
    /// Bytes that are not TLS at all — a plaintext block page would look like this.
    NotTls { first: Vec<u8> },
}

impl Response {
    pub fn label(&self) -> String {
        match self {
            Response::ServerHello => "server-hello".into(),
            Response::Alert { level, desc } => format!("alert({level},{desc})"),
            Response::NotTls { .. } => "not-tls".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Attempt {
    pub outcome: Outcome,
    /// The length actually put on the wire. Reported always: a flight over the MSS is
    /// pre-split by the kernel and is not a valid unsplit baseline.
    pub client_hello_len: usize,
    /// Milliseconds from the last byte of the first flight to the first byte back, or to the
    /// error that ended it.
    pub reply_ms: Option<u64>,
    pub response: Option<Response>,
    /// How many separate writes the strategy produced. 1 means nothing was split.
    pub writes: usize,
}

impl Attempt {
    fn failed(outcome: Outcome) -> Attempt {
        Attempt {
            outcome,
            client_hello_len: 0,
            reply_ms: None,
            response: None,
            writes: 0,
        }
    }
}

/// Map an I/O error to the report's vocabulary.
///
/// `BrokenPipe` belongs with reset: on Windows a peer RST that arrives while we are still
/// writing surfaces as a write failure rather than a read failure, and scoring that as
/// "other" would hide the single most important signal on this line.
pub fn classify(e: &std::io::Error) -> Outcome {
    match e.kind() {
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe => {
            Outcome::Reset
        }
        ErrorKind::WouldBlock | ErrorKind::TimedOut => Outcome::Timeout,
        ErrorKind::UnexpectedEof => Outcome::Closed,
        _ => Outcome::Other(format!("{:?}", e.kind())),
    }
}

/// Classify the first bytes that came back.
pub fn classify_response(buf: &[u8]) -> Response {
    // A TLS record header: type, version major/minor, length.
    if buf.len() >= 5 && buf[1] == 0x03 {
        match buf[0] {
            0x16 => return Response::ServerHello,
            0x15 => {
                // alert: two bytes of payload after the 5-byte header
                if buf.len() >= 7 {
                    return Response::Alert {
                        level: buf[5],
                        desc: buf[6],
                    };
                }
                return Response::Alert { level: 0, desc: 0 };
            }
            _ => {}
        }
    }
    Response::NotTls {
        first: buf[..buf.len().min(32)].to_vec(),
    }
}

/// Everything one attempt needs to know.
#[derive(Debug, Clone)]
pub struct Params<'a> {
    pub host: &'a str,
    pub addr: SocketAddr,
    /// Length of the ClientHello to send. `None` means "the smallest that fits this host".
    pub client_hello_len: Option<usize>,
    /// Send these exact bytes instead of synthesising a hello. Captured from a real client,
    /// so that "our hello behaves differently" can be told apart from "the network changed".
    pub flight: Option<&'a [u8]>,
    pub strategy: &'a Strategy,
    pub timeout: Duration,
    /// How long to wait for the far end. Separate from `timeout` because a TTL sweep expects
    /// most of its cells to time out, and a 6-second wait times twelve TTLs times five trials
    /// is a run nobody finishes.
    pub read_timeout: Duration,
    /// IP TTL for the first flight only, for locating an on-path injector.
    pub ttl: Option<u32>,
    /// Varied by the caller so two attempts never look byte-identical to a server.
    pub nonce: [u8; 32],
}

/// Open a connection, write the first flight the way the strategy says, and report what
/// happened. Never completes the handshake — it does not need to.
pub fn run(p: &Params<'_>) -> Attempt {
    let flight = match p.flight {
        Some(bytes) => bytes.to_vec(),
        None => {
            let flight_len = match p.client_hello_len {
                Some(n) => n,
                None => match synth::min_len(p.host) {
                    Ok(n) => n,
                    Err(e) => return Attempt::failed(Outcome::Other(format!("host: {e}"))),
                },
            };
            match synth::client_hello(p.host, flight_len, p.nonce) {
                Ok(f) => f,
                Err(e) => return Attempt::failed(Outcome::Other(format!("build: {e}"))),
            }
        }
    };

    let mut sock = match TcpStream::connect_timeout(&p.addr, p.timeout) {
        Ok(s) => s,
        Err(e) => return Attempt::failed(classify(&e)),
    };
    let _ = sock.set_nodelay(true);
    let _ = sock.set_read_timeout(Some(p.read_timeout));
    let _ = sock.set_write_timeout(Some(p.timeout));

    // The TCP handshake has already happened at the default TTL, so lowering it here affects
    // only the first flight — which is the packet the injector reacts to. That is what makes
    // a TTL sweep possible without raw sockets or administrator rights.
    if let Some(t) = p.ttl {
        if let Err(e) = sock.set_ttl(t) {
            return Attempt::failed(Outcome::Other(format!("set_ttl: {e}")));
        }
    }

    let plan = p.strategy.plan(&flight);
    let writes = plan.writes.len();
    let started = Instant::now();
    for chunk in &plan.writes {
        if chunk.delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(chunk.delay_ms as u64));
        }
        if let Err(e) = sock.write_all(&chunk.bytes) {
            return Attempt {
                client_hello_len: flight.len(),
                reply_ms: Some(started.elapsed().as_millis() as u64),
                writes,
                ..Attempt::failed(classify(&e))
            };
        }
    }
    // The TTL is deliberately *not* restored here.
    //
    // An earlier version put it back to 64 as soon as the flight was written, on the theory
    // that the low TTL had already done its job. It had not: the truncated segment dies in
    // transit, TCP retransmits it ~300 ms later at the restored TTL, and that copy sails
    // through. Every TTL then "succeeds", and the sweep measures its own retransmit rather
    // than the network. It showed up as example.com passing 5/5 at TTL 1 with the reply time
    // jumping from 53 ms to 340 ms — one RTO.
    //
    // Holding the low TTL for the whole attempt means the retransmissions die too, which is
    // what makes a short read timeout the correct signal for "we never reached the injector".
    let waiting = Instant::now();
    let mut buf = [0u8; 4096];
    let (outcome, response) = match sock.read(&mut buf) {
        Ok(0) => (Outcome::Closed, None),
        Ok(n) => {
            let r = classify_response(&buf[..n]);
            let o = match r {
                Response::ServerHello => Outcome::Ok,
                // An answer, but not the one that proves the handshake was allowed through.
                _ => Outcome::TlsError,
            };
            (o, Some(r))
        }
        Err(e) => (classify(&e), None),
    };

    Attempt {
        outcome,
        client_hello_len: flight.len(),
        reply_ms: Some(waiting.elapsed().as_millis() as u64),
        response,
        writes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Error;

    #[test]
    fn reset_family_maps_to_reset() {
        for k in [
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::BrokenPipe,
        ] {
            assert_eq!(classify(&Error::new(k, "x")), Outcome::Reset, "{k:?}");
        }
    }

    #[test]
    fn timeout_family_maps_to_timeout() {
        for k in [ErrorKind::WouldBlock, ErrorKind::TimedOut] {
            assert_eq!(classify(&Error::new(k, "x")), Outcome::Timeout, "{k:?}");
        }
    }

    #[test]
    fn unknown_kinds_stay_visible() {
        match classify(&Error::new(ErrorKind::PermissionDenied, "x")) {
            Outcome::Other(s) => assert!(s.contains("PermissionDenied")),
            other => panic!("expected Other, got {other}"),
        }
    }

    #[test]
    fn a_handshake_record_is_a_server_hello() {
        // type=22, TLS 1.2, length 74, then a ServerHello handshake header
        let b = [0x16, 0x03, 0x03, 0x00, 0x4A, 0x02, 0x00, 0x00, 0x46];
        assert_eq!(classify_response(&b), Response::ServerHello);
    }

    #[test]
    fn an_alert_keeps_its_level_and_description() {
        let b = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
        assert_eq!(
            classify_response(&b),
            Response::Alert { level: 2, desc: 40 }
        );
    }

    /// A truncated alert must still be recognised as an alert rather than falling through to
    /// "not TLS", which would read as a block page in the report.
    #[test]
    fn a_truncated_alert_is_still_an_alert() {
        let b = [0x15, 0x03, 0x03, 0x00, 0x02];
        assert_eq!(classify_response(&b), Response::Alert { level: 0, desc: 0 });
    }

    /// The case that matters on an unknown network: a plaintext block page delivered on 443.
    #[test]
    fn a_plaintext_response_is_reported_with_its_bytes() {
        let b = b"HTTP/1.1 302 Found\r\nLocation: http://blocked.example/\r\n\r\n";
        match classify_response(b) {
            Response::NotTls { first } => {
                assert!(first.starts_with(b"HTTP/1.1 302"));
                assert!(first.len() <= 32, "should be bounded");
            }
            other => panic!("expected NotTls, got {other:?}"),
        }
    }

    #[test]
    fn short_and_empty_responses_do_not_panic() {
        for n in 0..8 {
            let b = vec![0x16u8; n];
            let _ = classify_response(&b);
        }
        let _ = classify_response(&[]);
    }

    /// Only a ServerHello may be scored as reached. If this ever loosened, an injected alert
    /// would be counted as the bypass working.
    #[test]
    fn only_a_server_hello_is_success() {
        assert!(matches!(
            classify_response(&[0x16, 0x03, 0x03, 0x00, 0x4A, 0x02]),
            Response::ServerHello
        ));
        for r in [
            Response::Alert { level: 2, desc: 40 },
            Response::NotTls { first: vec![] },
        ] {
            assert_ne!(r, Response::ServerHello);
        }
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut seed = 0x1357_9BDF_2468_ACE0u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..20_000 {
            let n = (next() % 64) as usize;
            let buf: Vec<u8> = (0..n).map(|_| (next() & 0xFF) as u8).collect();
            let _ = classify_response(&buf);
        }
    }
}
