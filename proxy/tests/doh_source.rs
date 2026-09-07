//! **The recursion, closed by type and re-checked by reading the source.**
//!
//! A DoH client that can be handed a hostname is one that can deadlock the resolver on its own
//! first query: DoH needs HTTPS, HTTPS needs a name, a name needs DNS. `Upstream::Doh` carries a
//! `SocketAddr` and `Endpoint` carries an `IpAddr`, so the mistake is unrepresentable — but a
//! `to_socket_addrs` added inside the module would reintroduce it without changing either type,
//! and no unit test of behaviour would notice, because the resolution would simply succeed.
//!
//! So the file's own text is the assertion. The same technique `platform/src/dnsclient.rs` uses.

/// Anything here inside `proxy/src/doh.rs` means a name is being resolved, or that rustls is being
/// driven by something that loops until a socket timeout instead of to a deadline.
const FORBIDDEN: &[(&str, &str)] = &[
    (
        "to_socket_addrs",
        "resolves a name — the recursion this module exists to avoid",
    ),
    ("ToSocketAddrs", "same"),
    ("lookup_host", "same"),
    (
        "ServerName::try_from",
        "builds a name, which would send an SNI",
    ),
    ("DnsName", "the name form of a server name"),
    (
        "TcpStream::connect(",
        "the &str form resolves; only connect_timeout(&SocketAddr, ..) is allowed",
    ),
    (
        "rustls::Stream",
        "loops until a socket timeout, which a trickler never trips",
    ),
    ("StreamOwned", "same"),
    ("complete_io", "same"),
];

#[test]
fn the_doh_module_never_resolves_a_name_and_never_hands_rustls_the_loop() {
    let src = include_str!("../src/doh.rs");
    let production = src.split("#[cfg(test)]").next().expect("source");
    for (line_no, line) in production.lines().enumerate() {
        let code = line.trim_start();
        // Comments may name these; the point is to explain why they are absent.
        if code.starts_with("//") || code.starts_with("*") {
            continue;
        }
        for (needle, why) in FORBIDDEN {
            assert!(
                !line.contains(needle),
                "proxy/src/doh.rs:{} contains {needle:?} — {why}\n  {line}",
                line_no + 1
            );
        }
    }
}

/// The flag refuses a hostname rather than resolving it and carrying on.
#[test]
fn a_doh_endpoint_must_be_an_address() {
    use vigil_proxy::resolver::parse_doh_endpoint;
    assert_eq!(
        parse_doh_endpoint("1.1.1.1").map(|a| a.to_string()),
        Ok("1.1.1.1:443".to_string()),
        "a bare address gets the default port"
    );
    assert_eq!(
        parse_doh_endpoint("1.1.1.1:8443").map(|a| a.to_string()),
        Ok("1.1.1.1:8443".to_string())
    );
    // `localhost` and not `dns.example`: a version that resolved through the operating system
    // would get 127.0.0.1 and accept it, while an unresolvable name would be refused for the
    // wrong reason and hide the defect.
    assert!(
        parse_doh_endpoint("localhost").is_err(),
        "a hostname must be refused, not resolved"
    );
    assert!(parse_doh_endpoint("localhost:443").is_err());
    assert!(parse_doh_endpoint("dns.example").is_err());
}
