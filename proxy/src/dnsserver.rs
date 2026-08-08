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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use vigil_core::dnsmsg::{self, Question, RCODE_NOERROR, RCODE_SERVFAIL, TYPE_A};

use crate::resolver::Resolver;

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
}

pub struct DnsServer {
    resolver: Arc<Resolver>,
    pub stats: Arc<DnsStats>,
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

    /// Serve until the socket dies.
    pub fn serve(&self, socket: UdpSocket) {
        let mut buf = [0u8; 1500];
        loop {
            let (n, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                Err(_) => return,
            };
            if !from.ip().is_loopback() {
                self.stats.refused.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            self.stats.queries.fetch_add(1, Ordering::Relaxed);
            if let Some(reply) = self.answer(&buf[..n]) {
                let _ = socket.send_to(&reply, from);
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

        let addrs: Vec<std::net::Ipv4Addr> = self
            .resolver
            .resolve(&q.name, 0)
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

    /// End to end over a real socket, because the parts agreeing in isolation is not the same
    /// as a client getting an answer.
    #[test]
    fn a_client_on_loopback_gets_an_answer() {
        let sock = DnsServer::bind("127.0.0.1:0".parse().expect("literal")).expect("bind");
        let addr = sock.local_addr().expect("addr");
        let s = server();
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
