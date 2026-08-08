//! Does the stop hook actually run when the process is signalled?
//!
//! The Windows path is verified by driving a real `CTRL_C_EVENT` at `vigil.exe`. The Unix path
//! needs the same treatment and cannot be checked in-process, because the handler ends the
//! process by design — so it is checked here, from outside, with a real signal.
//!
//!   cargo run -p vigil-platform --example sighook -- /tmp/proof.txt &
//!   kill -TERM <pid>          # or -INT, or -HUP
//!   cat /tmp/proof.txt        # "ran"

use std::sync::OnceLock;

static PATH: OnceLock<String> = OnceLock::new();

fn cleanup() {
    if let Some(p) = PATH.get() {
        let _ = std::fs::write(p, "ran");
    }
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: sighook PATH");
    PATH.set(path).expect("once");
    let installed = vigil_platform::shutdown::on_stop(cleanup);
    println!("installed={installed}");
    loop {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}
