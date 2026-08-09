//! DNS for the whole machine, not only for what goes through the proxy.
//!
//! The proxy resolves honestly for the connections it carries. Everything else on the machine
//! still asks the operating system, and on this line the operating system is answering
//! `roblox.com` with the censor's block page. Measured 2026-08-05: the Roblox client ignores
//! the system proxy setting entirely, so it was being sent to `195.175.254.2` before a single
//! TLS byte was written — and no amount of ClientHello splitting can help a connection that
//! reached the wrong server.
//!
//! So vigil can be the machine's resolver: a UDP server on loopback that answers from
//! [`crate::resolver`], which asks an off-port upstream the interception does not cover.
//!
//! # What this fixes, and what it does not
//!
//! It fixes **names**. A program that bypasses the proxy still sends its ClientHello directly
//! and still meets the SNI reset, so an honest address turns "never works" into "works when
//! the hello happens to span segments". That is an improvement and not a cure, and the
//! interface must not claim otherwise — the cure for those programs is a packet-level
//! datapath.
//!
//! # Why loopback only, always
//!
//! A resolver that answers the network is an open resolver, and an open resolver is a UDP
//! amplifier: a spoofed 30-byte question yields a 100-byte answer aimed at the victim. Binding
//! to loopback is the structural fix, and the source address is checked as well, because
//! "structural" is worth having twice in the one place on this machine that parses packets
//! from anybody.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use vigil_core::dnsmsg::{self, Question, RCODE_NOERROR, RCODE_SERVFAIL, TYPE_A};

use crate::resolver::Resolver;

/// How many queries may be in flight at once.
///
/// Generous, because each one is a thread doing a single blocking read, and a burst is exactly what
/// a program starting up produces — Roblox asks for about fifty names at once. Past the cap queries
/// are dropped, not queued: the client retries, and dropping is how a resolver stays responsive
/// under a flood instead of answering everything far too late.
const IN_FLIGHT: usize = 128;

/// Is this receive error about the last datagram rather than about the socket?
///
/// Two of them, both routine on Windows and both produced by this server's own behaviour:
///
/// - **`ConnectionReset`** — an ICMP port-unreachable from a client that closed its socket before
///   our answer arrived. Every query that times out and every query dropped past [`IN_FLIGHT`] is a
///   candidate, so a burst manufactures these by the dozen.
/// - **`WSAEMSGSIZE` (10040)** — a datagram larger than the 1500-byte buffer. `std` has no
///   `ErrorKind` for it, so it arrives as `Uncategorized` and can only be matched by its raw code.
///   Any local process can send one, which is what made the old threshold a way for unprivileged
///   code to switch off the machine's resolver.
///
/// Neither says the socket is unusable, and the very next read normally succeeds. Counting them
/// towards a fatal threshold is reading our own recent traffic as a diagnosis of our own health.
fn self_clearing(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::ConnectionReset || e.raw_os_error() == Some(10040)
}

/// A slot in [`IN_FLIGHT`], released when it is dropped.
///
/// The count used to be decremented by the last statement of the worker closure, which meant a
/// panic anywhere in `answer` leaked the slot **permanently** — and after 128 of them the server
/// drops every query for the rest of its life, silently, with no way back but a restart. The
/// probability is low and the consequence is a machine with no DNS, which is the wrong side of that
/// trade to leave to luck.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Time to live handed to clients, in seconds.
///
/// Deliberately short. A machine that cached our answers for an hour would keep using them
/// after vigil stopped, which is the DNS equivalent of a stranded proxy setting — except that
/// no repair tool can reach into another process's cache.
pub const TTL: u32 = 60;

#[derive(Debug, Default)]
pub struct DnsStats {
    pub queries: AtomicUsize,
    /// Questions answered with at least one address.
    pub answered: AtomicUsize,
    /// Questions we had no address for, answered NODATA or SERVFAIL.
    pub empty: AtomicUsize,
    /// Packets refused: not from loopback, or not a question we will answer.
    pub refused: AtomicUsize,
    /// Set when [`DnsServer::serve`] returns, for any reason.
    ///
    /// The tray used to compute "DNS is being served" once, at bind time, and never look again —
    /// so a server that died reported itself healthy for the life of the process. That is the
    /// failure mode the whole error-handling rewrite exists to prevent, and leaving it
    /// unobservable would have kept the *symptom* even after the cause was fixed: every website
    /// failing while vigil looks fine.
    pub stopped: AtomicBool,
    /// Receive errors skipped rather than treated as the end of the server. On Windows this counts
    /// ICMP port-unreachable replies from clients that closed their socket before our answer
    /// arrived — ordinary, and once enough to kill the whole resolver.
    pub recv_errors: AtomicUsize,
    /// Queries dropped because [`IN_FLIGHT`] were already being answered. Counted rather than
    /// hidden: a non-zero value here is the machine telling you the cap is too low, and a silent
    /// drop that nobody counts is indistinguishable from a bug.
    pub dropped: AtomicUsize,
}

pub struct DnsServer {
    resolver: Arc<Resolver>,
    pub stats: Arc<DnsStats>,
}

impl DnsStats {
    /// Is the server still answering? False the moment `serve` returns.
    pub fn serving(&self) -> bool {
        !self.stopped.load(Ordering::Relaxed)
    }

    /// One line for the panel and the details window. Short on purpose: it is read at a glance,
    /// and the number that matters is `recv_errors` climbing while `answered` does not.
    pub fn line(&self) -> String {
        format!(
            "dns {} · {} sorgu, {} cevap, {} boş, {} düşürüldü, {} alım hatası",
            if self.serving() { "açık" } else { "DURDU" },
            self.queries.load(Ordering::Relaxed),
            self.answered.load(Ordering::Relaxed),
            self.empty.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
            self.recv_errors.load(Ordering::Relaxed),
        )
    }
}

impl DnsServer {
    pub fn new(resolver: Arc<Resolver>) -> Self {
        DnsServer {
            resolver,
            stats: Arc::new(DnsStats::default()),
        }
    }

    /// Bind, refusing anything that is not loopback.
    ///
    /// Port 53 needs no privilege on Windows — unlike Unix, low ports are not reserved — so
    /// this runs as the ordinary user. Pointing the *system* at it is the part that needs
    /// administrator rights, and that is a separate, visible step.
    pub fn bind(addr: SocketAddr) -> std::io::Result<UdpSocket> {
        if !addr.ip().is_loopback() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the DNS server binds to loopback only: anything else is an open resolver",
            ));
        }
        let s = UdpSocket::bind(addr)?;
        // So a shutdown is not held up by a socket with nothing to read.
        s.set_read_timeout(Some(Duration::from_millis(500)))?;
        Ok(s)
    }

    /// Serve until the socket dies, **answering each query on its own thread**.
    ///
    /// This loop used to call `answer` inline, and `answer` blocks on an upstream lookup. That made
    /// one query at a time the limit for the whole machine: every program's name resolution queued
    /// behind whichever name happened to be in flight. Measured before the change: twenty names
    /// asked at once took 1.79 s — about 90 ms each, stacked rather than overlapped — and five names
    /// that nothing would answer did not finish in two minutes. A machine whose DNS is *this* is a
    /// machine where a game with fifty hostnames never finishes starting, which is what happened.
    ///
    /// Threads rather than a pool because the work is one blocking socket read and nothing else, and
    /// because a pool with a queue would reintroduce exactly the queue this removes. `IN_FLIGHT`
    /// bounds it: past the cap a query is **dropped rather than queued**, which is the correct answer
    /// to a flood — the client retries, and a resolver that queues under load is one that answers
    /// everything too late instead of most things on time.
    pub fn serve(self: Arc<Self>, socket: UdpSocket) {
        // Whatever happens below, say so on the way out. `Ending` is a guard rather than a line at
        // the bottom because two of the returns are inside the loop and a third is a `?`-shaped
        // early exit away from ever being written.
        struct Ending(Arc<DnsStats>);
        impl Drop for Ending {
            fn drop(&mut self) {
                self.0.stopped.store(true, Ordering::Relaxed);
            }
        }
        let _ending = Ending(Arc::clone(&self.stats));

        let mut buf = [0u8; 1500];
        let in_flight = Arc::new(AtomicUsize::new(0));
        // Consecutive receive errors of a kind we do not recognise. **Not one**, and — since
        // 2026-08-09 — not the recognised kinds at all: see `self_clearing`.
        //
        // This loop used to `return` on anything that was not a timeout, and on Windows that is a
        // way to be killed by an ordinary event. A worker replying to a client that has already
        // closed its port draws an ICMP port-unreachable, and Windows reports it as `ConnectionReset`
        // on the *next* `recv_from` of the shared socket — so one late reply took DNS off the machine
        // for good, silently, with the fallback resolver quietly picking up the pieces. Answering on
        // threads made late replies ordinary rather than rare: every timeout and every query past the
        // in-flight cap is a candidate.
        //
        // The first repair of this counted *every* error and gave up after 64 in a row, and an
        // adversarial reviewer killed the shipping binary at exactly that boundary — twice. Sixty-four
        // abandoned queries did it, and so did sixty-four oversized datagrams from any unprivileged
        // local process. The mistake was treating a self-clearing per-datagram condition as evidence
        // about the socket: `errors` only resets on a *successful* read, and the tail of a burst has
        // no successful reads to interleave. `IN_FLIGHT` is 128 — the design admits twice as many
        // concurrent queries as it took to die.
        //
        // So the recognised kinds are now skipped outright and never counted, and the counter is left
        // doing only the job it was added for: stopping a hot loop on a socket that has genuinely gone.
        const FATAL_AFTER: u32 = 64;
        let mut errors: u32 = 0;
        loop {
            let (n, from) = match socket.recv_from(&mut buf) {
                Ok(v) => {
                    errors = 0;
                    v
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                // Says nothing about the socket. Skipped, counted for diagnosis, never fatal.
                Err(e) if self_clearing(&e) => {
                    self.stats.recv_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                Err(_) => {
                    errors += 1;
                    self.stats.recv_errors.fetch_add(1, Ordering::Relaxed);
                    if errors >= FATAL_AFTER {
                        // Losing the machine's resolver must never be indistinguishable from working.
                        // In the reviewer's kills the process stayed alive and kept printing its
                        // healthy status line, so the only symptom was every website failing.
                        eprintln!(
                            "dns: giving up after {errors} consecutive unrecognised receive errors \
                             — this machine no longer has vigil as its resolver"
                        );
                        return;
                    }
                    continue;
                }
            };
            if !from.ip().is_loopback() {
                self.stats.refused.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            self.stats.queries.fetch_add(1, Ordering::Relaxed);

            if in_flight.load(Ordering::Relaxed) >= IN_FLIGHT {
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let Ok(reply_sock) = socket.try_clone() else {
                // Cannot hand a socket to the worker, so answer inline rather than not at all.
                if let Some(reply) = self.answer(&buf[..n]) {
                    let _ = socket.send_to(&reply, from);
                }
                continue;
            };
            let me = Arc::clone(&self);
            let query = buf[..n].to_vec();
            in_flight.fetch_add(1, Ordering::Relaxed);
            let slot = Slot(Arc::clone(&in_flight));
            if std::thread::Builder::new()
                .name("vigil-dns".into())
                .spawn(move || {
                    // Held for the life of the worker and released by `Drop`, so a panic in
                    // `answer` gives the slot back instead of retiring it.
                    let _slot = slot;
                    if let Some(reply) = me.answer(&query) {
                        let _ = reply_sock.send_to(&reply, from);
                    }
                })
                .is_err()
            {
                // Out of threads. Answer it here instead of losing it. The slot was moved into the
                // closure that failed to spawn and has already been dropped, so the count is right.
                if let Some(reply) = self.answer(&buf[..n]) {
                    let _ = socket.send_to(&reply, from);
                }
            }
        }
    }

    /// The pure-ish middle: bytes in, bytes out, one lookup.
    ///
    /// `None` means "say nothing at all", which is the right answer to a packet we cannot even
    /// read an id out of — replying to it would only tell a prober that something is here.
    pub fn answer(&self, query: &[u8]) -> Option<Vec<u8>> {
        let q: Question = match dnsmsg::parse_question(query) {
            Ok(q) => q,
            Err(_) => {
                self.stats.refused.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };
        // Anything that is not an internet A question gets NODATA: the name may well exist,
        // we simply have no record of that kind. NXDOMAIN here would make Windows stop asking
        // for the A record too, and the name would go dark on a machine we are fixing.
        if q.qtype != TYPE_A || q.qclass != dnsmsg::CLASS_IN {
            self.stats.empty.fetch_add(1, Ordering::Relaxed);
            return dnsmsg::encode_response(query, &q, &[], TTL, RCODE_NOERROR).ok();
        }

        // **Never the operating system from here.** See `Resolver::resolve_no_system`: when vigil is
        // the machine's resolver, the OS fallback asks us, and since each query gets its own thread
        // that recursion multiplies instead of blocking.
        let addrs: Vec<std::net::Ipv4Addr> = self
            .resolver
            .resolve_no_system(&q.name, 0)
            .into_iter()
            .filter_map(|s| match s.ip() {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            })
            .collect();

        if addrs.is_empty() {
            // SERVFAIL rather than NODATA: we could not answer, and a client that is told
            // "no such record" will not try its next resolver, while SERVFAIL makes it fail
            // over. Getting this backwards would turn one unreachable upstream into a machine
            // with no DNS at all.
            self.stats.empty.fetch_add(1, Ordering::Relaxed);
            return dnsmsg::encode_response(query, &q, &[], 0, RCODE_SERVFAIL).ok();
        }
        self.stats.answered.fetch_add(1, Ordering::Relaxed);
        dnsmsg::encode_response(query, &q, &addrs, TTL, RCODE_NOERROR).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn server() -> DnsServer {
        // No upstream servers and no system fallback: every lookup fails, which is what makes
        // the failure paths testable without a network.
        DnsServer::new(Arc::new(Resolver::new(Vec::new(), false)))
    }

    #[test]
    fn it_refuses_to_bind_anywhere_but_loopback() {
        let e = DnsServer::bind("0.0.0.0:0".parse().expect("literal")).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            e.to_string().contains("open resolver"),
            "the reason must say why: {e}"
        );
        // and loopback is fine
        assert!(DnsServer::bind("127.0.0.1:0".parse().expect("literal")).is_ok());
    }

    #[test]
    fn a_packet_it_cannot_read_gets_no_reply_at_all() {
        let s = server();
        assert!(s.answer(&[]).is_none());
        assert!(s.answer(&[0u8; 8]).is_none());
        assert!(s.answer(&[0xFFu8; 40]).is_none());
        assert_eq!(s.stats.refused.load(Ordering::Relaxed), 3);
    }

    /// An address literal is answered from the question itself, without asking anyone — and it
    /// is the one lookup that succeeds with no upstream, so it also proves the happy path.
    #[test]
    fn an_address_literal_is_answered_without_an_upstream() {
        let s = server();
        let q = dnsmsg::encode_query("127.0.0.1", 42).unwrap();
        let r = s.answer(&q).expect("a reply");
        assert_eq!(
            dnsmsg::decode_answers(&r, 42).unwrap(),
            vec![Ipv4Addr::new(127, 0, 0, 1)]
        );
        assert_eq!(s.stats.answered.load(Ordering::Relaxed), 1);
    }

    /// The AAAA question, which is the one that decides whether a machine keeps working.
    #[test]
    fn aaaa_gets_nodata_and_never_nxdomain() {
        let s = server();
        let mut q = dnsmsg::encode_query("discord.com", 5).unwrap();
        let n = q.len();
        q[n - 4..n - 2].copy_from_slice(&dnsmsg::TYPE_AAAA.to_be_bytes());
        let r = s.answer(&q).expect("a reply");
        assert_eq!(r[3] & 0x0F, RCODE_NOERROR, "must not be NXDOMAIN");
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 0, "no answers");
        assert_eq!(s.stats.empty.load(Ordering::Relaxed), 1);
    }

    /// A name we cannot resolve must fail over to the client's next resolver, not be declared
    /// nonexistent.
    #[test]
    fn an_unresolvable_name_is_servfail_so_the_client_tries_elsewhere() {
        let s = server();
        let q = dnsmsg::encode_query("nowhere.invalid", 6).unwrap();
        let r = s.answer(&q).expect("a reply");
        assert_eq!(r[3] & 0x0F, RCODE_SERVFAIL);
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 0);
    }

    /// **A burst of abandoned queries must not kill the server.** This is the one an adversarial
    /// reviewer used to kill the shipping `vigil.exe` on Windows, twice.
    ///
    /// A client that gives up before our answer arrives leaves a closed port; the reply draws an ICMP
    /// port-unreachable, and Windows reports it as `ConnectionReset` on the *next* `recv_from` of the
    /// shared socket. Windows' own resolver produces exactly this every time our answer arrives after
    /// its roughly one second of patience. The first version of `serve` died on the first such event;
    /// the second died on the sixty-fourth, measured to the digit — because the counter only reset on
    /// a successful read and the tail of a burst has none.
    ///
    /// 200 rather than 64: comfortably past the old threshold, and past `IN_FLIGHT` too, so the
    /// dropped-query path that manufactures more of these is exercised as well.
    ///
    /// On Linux this is a weaker test than on Windows — the kernel does not report ICMP errors on an
    /// unconnected UDP socket — so it cannot fail here for the original reason. It is still worth
    /// running everywhere: it covers the in-flight cap, the drop path, and the survival of the loop,
    /// and it fails on any platform if `serve` ever goes back to returning on the first error.
    #[test]
    fn a_burst_of_abandoned_queries_does_not_kill_the_server() {
        let sock = DnsServer::bind("127.0.0.1:0".parse().expect("literal")).expect("bind");
        let addr = sock.local_addr().expect("addr");
        // A dead upstream, so every answer is late by construction and every client has given up.
        let dead = {
            let s = UdpSocket::bind("127.0.0.1:0").expect("bind");
            let a = s.local_addr().expect("addr");
            drop(s);
            a
        };
        let s = Arc::new(DnsServer::new(Arc::new(Resolver::new(vec![dead], false))));
        let stats = Arc::clone(&s.stats);
        std::thread::spawn(move || s.serve(sock));

        for i in 0..200u16 {
            let c = UdpSocket::bind("127.0.0.1:0").expect("client");
            let q = dnsmsg::encode_query(&format!("gone{i}.example"), i | 1).expect("query");
            let _ = c.send_to(&q, addr);
            // Gone before the answer can arrive. This is the whole point.
            drop(c);
        }
        // An oversized datagram too: WSAEMSGSIZE is the other self-clearing error, and any local
        // process can send one. It must not count towards anything either.
        {
            let c = UdpSocket::bind("127.0.0.1:0").expect("client");
            let _ = c.send_to(&vec![0u8; 2000], addr);
        }

        // Let the workers finish and their late replies bounce.
        std::thread::sleep(Duration::from_secs(3));

        // The only assertion that matters: it still answers.
        let client = UdpSocket::bind("127.0.0.1:0").expect("client");
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let q = dnsmsg::encode_query("127.0.0.9", 0x33).expect("query");
        client.send_to(&q, addr).expect("send");
        let mut buf = [0u8; 512];
        let got = client.recv_from(&mut buf);
        assert!(
            got.is_ok(),
            "the server stopped answering after a burst of abandoned queries — \
             queries={} dropped={} recv_errors={}",
            stats.queries.load(Ordering::Relaxed),
            stats.dropped.load(Ordering::Relaxed),
            stats.recv_errors.load(Ordering::Relaxed)
        );
        // And it must actually have been through the hazardous path — a test that quietly exercises
        // nothing is the failure mode this project has already shipped once. Either signal will do:
        // `recv_errors` is the Windows one (the ICMP bounces that used to be fatal), `dropped` is the
        // in-flight cap. Linux reports no ICMP on an unconnected socket, so it can only show the
        // second.
        let dropped = stats.dropped.load(Ordering::Relaxed);
        let recv_errors = stats.recv_errors.load(Ordering::Relaxed);
        assert!(
            dropped + recv_errors > 0,
            "neither the in-flight cap nor a receive error was reached, so this test measured \
             nothing: queries={} dropped={dropped} recv_errors={recv_errors}",
            stats.queries.load(Ordering::Relaxed)
        );
    }

    /// The DNS server must never fall back to the operating system's resolver.
    ///
    /// When vigil is the machine's resolver, the OS resolver *is* vigil. `system()` calls
    /// `to_socket_addrs`, that goes to 127.0.0.1:53, and that is this server — so every failed
    /// lookup asks itself again. While queries were answered one at a time this was self-limiting:
    /// the inner query sat unread in the socket buffer until the outer one timed out. Giving each
    /// query its own thread turned it into an exponential fan-out, bounded only by `IN_FLIGHT` and
    /// the timeout, in exactly the configuration a user turns on with `--set-dns`.
    ///
    /// Asserted by pointing the resolver at a dead upstream and checking the whole thing finishes in
    /// about one timeout. If `answer` went back to `resolve()`, the OS lookup for `.example` would
    /// add its own delay on top of every one of these, and on a machine where vigil really is the
    /// resolver it would not terminate at all.
    #[test]
    fn the_server_never_asks_the_operating_system() {
        let dead = {
            let s = UdpSocket::bind("127.0.0.1:0").expect("bind");
            let a = s.local_addr().expect("addr");
            drop(s);
            a
        };
        // `allow_system: true` — the flag the *proxy* uses. The server must ignore it regardless.
        let r = Arc::new(Resolver::new(vec![dead], true));
        let server = DnsServer::new(Arc::clone(&r));

        let q = dnsmsg::encode_query("nothing.example", 0x51).expect("query");
        let started = std::time::Instant::now();
        let reply = server.answer(&q).expect("a reply, even if SERVFAIL");
        let took = started.elapsed();

        assert_eq!(
            reply[3] & 0x0F,
            RCODE_SERVFAIL,
            "nothing answered, so SERVFAIL"
        );
        assert!(
            took < Duration::from_secs(3),
            "one dead upstream took {took:?} — the operating system was asked as well"
        );
    }

    /// An upstream that accepts datagrams and never answers.
    ///
    /// **Not a closed port**, which is the obvious way to write this and is wrong. Measured
    /// 2026-08-09, sending to a closed loopback port with a 400 ms read timeout:
    ///
    /// | | Linux | Windows |
    /// |---|---|---|
    /// | closed port | times out (400 ms) | **`ConnectionReset` in 155 µs** |
    /// | bound, never reads | times out | times out (401 ms) |
    /// | `192.0.2.1` (no route) | `send_to` fails outright | `send_to` fails outright |
    ///
    /// So a closed port forces no timeout at all on Windows, and an unroutable address forces none
    /// anywhere — `ask_one` gives up at the send. Either would make the timing test below pass in
    /// microseconds having measured nothing, which is exactly how a reviewer found it going
    /// vacuously green under `unshare -rn`. A socket that is bound and simply never read is the one
    /// shape that times out on both.
    ///
    /// The returned socket must be kept alive by the caller; dropping it turns this back into a
    /// closed port.
    fn black_hole() -> (SocketAddr, UdpSocket) {
        let s = UdpSocket::bind("127.0.0.1:0").expect("bind black hole");
        let a = s.local_addr().expect("addr");
        (a, s)
    }

    /// **The gate.** A slow name must not hold up every other name on the machine, and the upstreams
    /// must be asked in parallel rather than one after another.
    ///
    /// Both halves of the 2026-08-09 rewrite, in one measurement, because the two failures it
    /// prevents are different: `serve` answering one query at a time, and `lookup` sweeping four
    /// upstreams in sequence. Before the rewrite the first cost 90 ms per queued name and the second
    /// cost 12 s for one unanswerable name; five such names did not finish in two minutes.
    ///
    /// **Four upstreams, not one.** With a single server a staggered fan-out and a plain
    /// `for s in &self.servers` loop are timing-identical by construction, so a "simplify the threads
    /// away" revert of `ask_all` would keep the whole suite green and ship a 4 × 1.5 s sweep.
    ///
    /// **And a lower bound.** The only assertion used to be `took < 5 s`, which is satisfied by a
    /// test that measured nothing at all. A timeout has to have actually elapsed for the upper bound
    /// to mean anything.
    #[test]
    fn one_slow_name_does_not_hold_up_the_others() {
        // Kept in scope for the whole test: dropping these turns them into closed ports, which is
        // the failure mode documented on `black_hole`.
        let holes: Vec<(SocketAddr, UdpSocket)> = (0..4).map(|_| black_hole()).collect();
        let upstreams: Vec<SocketAddr> = holes.iter().map(|(a, _)| *a).collect();

        let sock = DnsServer::bind("127.0.0.1:0".parse().expect("literal")).expect("bind");
        let addr = sock.local_addr().expect("addr");
        let s = Arc::new(DnsServer::new(Arc::new(Resolver::new(upstreams, false))));
        std::thread::spawn(move || s.serve(sock));

        let started = std::time::Instant::now();
        let workers: Vec<_> = (0..5u16)
            .map(|i| {
                std::thread::spawn(move || {
                    let c = UdpSocket::bind("127.0.0.1:0").expect("client");
                    c.set_read_timeout(Some(Duration::from_secs(30)))
                        .expect("timeout");
                    let q =
                        dnsmsg::encode_query(&format!("slow{i}.example"), 0x40 + i).expect("query");
                    c.send_to(&q, addr).expect("send");
                    let mut buf = [0u8; 512];
                    c.recv_from(&mut buf).is_ok()
                })
            })
            .collect();
        let answered = workers
            .into_iter()
            .filter_map(|w| w.join().ok())
            .filter(|ok| *ok)
            .count();
        let took = started.elapsed();

        assert_eq!(
            answered, 5,
            "every query must be answered, even if only SERVFAIL"
        );
        assert!(
            took > Duration::from_millis(1400),
            "finished in {took:?} — no upstream timeout can have elapsed, so this test measured \
             nothing. Check that the black holes are still bound; a closed port fails fast on \
             Windows and an unroutable address fails at the send on both."
        );
        // One timeout plus the stagger is about 2.1 s. Sequential upstreams would be four timeouts
        // for one name; sequential queries would be five times that again.
        assert!(
            took < Duration::from_secs(4),
            "five names against four dead upstreams took {took:?}. Either the queries are being \
             answered one at a time, or the upstreams are being swept one after another — the two \
             failures this test exists for."
        );
    }

    /// End to end over a real socket, because the parts agreeing in isolation is not the same
    /// as a client getting an answer.
    #[test]
    fn a_client_on_loopback_gets_an_answer() {
        let sock = DnsServer::bind("127.0.0.1:0".parse().expect("literal")).expect("bind");
        let addr = sock.local_addr().expect("addr");
        let s = Arc::new(server());
        std::thread::spawn(move || s.serve(sock));

        let client = UdpSocket::bind("127.0.0.1:0").expect("client");
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        let q = dnsmsg::encode_query("127.0.0.5", 0x77).unwrap();
        client.send_to(&q, addr).expect("send");
        let mut buf = [0u8; 512];
        let (n, _) = client.recv_from(&mut buf).expect("recv");
        assert_eq!(
            dnsmsg::decode_answers(&buf[..n], 0x77).unwrap(),
            vec![Ipv4Addr::new(127, 0, 0, 5)]
        );
    }
}
