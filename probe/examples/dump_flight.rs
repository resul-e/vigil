//! Dump the ClientHello rustls emits, for the parser test corpus.
//!
//! The corpus must contain what our *own* TLS stack produces, not only what curl and Chrome
//! produce, because the proxy will be parsing its own flights too.
//!
//! Usage:  cargo run -p probe --example dump_flight -- <outdir> <host>...

use std::path::PathBuf;

// Included by path rather than imported: `probe` is a binary crate, so its modules are not
// reachable as a library. This example needs only `config()`, hence the allow.
#[allow(dead_code)]
#[path = "../src/profile.rs"]
mod profile;

use profile::Profile;
use rustls::ClientConnection;
use rustls_pki_types::ServerName;

fn main() {
    let mut args = std::env::args().skip(1);
    let outdir = PathBuf::from(args.next().expect("usage: dump_flight <outdir> <host>..."));
    let hosts: Vec<String> = args.collect();
    assert!(!hosts.is_empty(), "give at least one host");
    std::fs::create_dir_all(&outdir).expect("create outdir");

    for host in hosts {
        for (prof, tag) in [
            (Profile::Small, "rustls-small"),
            (Profile::Default, "rustls"),
        ] {
            let name = ServerName::try_from(host.clone()).expect("valid host");
            let mut conn = ClientConnection::new(profile::config(prof), name).expect("tls init");
            let mut flight = Vec::new();
            while conn.wants_write() {
                conn.write_tls(&mut flight).expect("write_tls to Vec");
            }
            let path = outdir.join(format!("{tag}__{host}.bin"));
            std::fs::write(&path, &flight).expect("write fixture");
            println!("  {tag:<13} {host:<24} {:>5}B", flight.len());
        }
    }
}
