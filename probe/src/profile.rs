//! Client profiles — control over how big the ClientHello is.
//!
//! Without this the harness lies. rustls' default ClientHello is ~1730 B because of the
//! post-quantum key share; at MSS 1460 the kernel splits it before it ever reaches the wire,
//! so a "no split" arm built on it is silently pre-split and reports partial success for a
//! strategy that did nothing. That is exactly what the first run of this probe showed.
//!
//! `Small` pins a single classical key-exchange group, which drops the PQ key share and
//! brings the flight under one segment — the shape `curl`/OpenSSL emits, and the shape the
//! clients that actually need this tool (Discord desktop, games, updaters) emit.

use std::sync::Arc;

use rustls::crypto::aws_lc_rs;
use rustls::{ClientConfig, RootCertStore};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// One classical kx group, no post-quantum share. Fits a single TCP segment.
    Small,
    /// rustls defaults, including the ~1216 B post-quantum key share.
    Default,
}

impl Profile {
    pub fn label(&self) -> &'static str {
        match self {
            Profile::Small => "small",
            Profile::Default => "default",
        }
    }
}

fn roots() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

pub fn config(p: Profile) -> Arc<ClientConfig> {
    let mut cfg = match p {
        Profile::Default => ClientConfig::builder()
            .with_root_certificates(roots())
            .with_no_client_auth(),
        Profile::Small => {
            let mut provider = aws_lc_rs::default_provider();
            // Pinning one classical group removes the hybrid ML-KEM share, which is the
            // single biggest contributor to ClientHello size.
            provider.kx_groups = vec![aws_lc_rs::kx_group::X25519];
            ClientConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
                .expect("default protocol versions are always valid")
                .with_root_certificates(roots())
                .with_no_client_auth()
        }
    };

    // Trials must be independent. With the default in-memory session cache a later trial
    // resumes an earlier one, which changes the ClientHello and silently couples the
    // measurements together — the first probe run reported two different flight sizes for
    // the same host, which is how this was noticed.
    cfg.resumption = rustls::client::Resumption::disabled();
    Arc::new(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::ClientConnection;
    use rustls_pki_types::ServerName;

    /// Build the first flight offline — no network — and measure it.
    fn flight_len(p: Profile, host: &str) -> usize {
        let name = ServerName::try_from(host.to_string()).unwrap();
        let mut conn = ClientConnection::new(config(p), name).unwrap();
        let mut buf = Vec::new();
        while conn.wants_write() {
            conn.write_tls(&mut buf).unwrap();
        }
        buf.len()
    }

    /// Margin below the MSS that a profile must clear to be usable as a baseline.
    /// A flight that merely *happens* to fit today is not good enough: hostname length and
    /// extension changes move the size by tens of bytes.
    const SAFE_MARGIN: usize = 200;

    /// The property the whole harness depends on: the small profile must fit one segment
    /// with room to spare, so that "baseline" really is an unsplit baseline.
    #[test]
    fn small_profile_fits_one_segment_with_margin() {
        for host in [
            "discord.com",
            "roblox.com",
            "a-very-long-hostname.example.com",
        ] {
            let n = flight_len(Profile::Small, host);
            assert!(
                n + SAFE_MARGIN <= vigil_core::TYPICAL_MSS,
                "{host}: small ClientHello is {n} B; needs <= {} B to stay a valid baseline",
                vigil_core::TYPICAL_MSS - SAFE_MARGIN
            );
        }
    }

    /// The default profile sits *on* the MSS boundary — measured at 1458 B against an MSS of
    /// 1460 — so whether it occupies one segment or two flips on a couple of bytes of
    /// hostname. That is precisely why it must never be used as the baseline arm: it produced
    /// a "flaky" baseline in the first probe run that looked like DPI behaviour and was
    /// actually our own segmentation changing underneath us.
    #[test]
    fn default_profile_is_too_close_to_the_mss_boundary_to_be_a_baseline() {
        let n = flight_len(Profile::Default, "discord.com");
        assert!(
            n + SAFE_MARGIN > vigil_core::TYPICAL_MSS,
            "default ClientHello is {n} B, comfortably under the {} B MSS — if this ever \
             becomes true the comment above is stale and the profile split can be revisited",
            vigil_core::TYPICAL_MSS
        );
    }

    /// Flight size must depend only on the profile, never on anything else the harness does.
    /// The first probe run reported different sizes for the same host across strategies,
    /// which is impossible and meant the measurement could not be trusted.
    #[test]
    fn flight_size_is_stable_across_repeats() {
        for host in ["discord.com", "roblox.com", "example.com"] {
            let a = flight_len(Profile::Small, host);
            let b = flight_len(Profile::Small, host);
            let c = flight_len(Profile::Small, host);
            assert_eq!(a, b, "{host}: flight size varied between builds");
            assert_eq!(b, c, "{host}: flight size varied between builds");
        }
    }

    #[test]
    fn small_is_smaller_than_default() {
        assert!(
            flight_len(Profile::Small, "discord.com") < flight_len(Profile::Default, "discord.com")
        );
    }
}
