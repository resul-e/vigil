//! The check the release process needs, as a pure function: is this triple of files something a
//! client would actually accept?
//!
//! ## Why this module exists
//!
//! `scripts/release.sh` had a step headed "verifying with the binary that ships", and it was:
//!
//! ```text
//! "$OUT/vigil-update.exe" --version | grep -q "keys: configured"
//! ```
//!
//! That reads a compile-time constant. It never opened the manifest or either signature. So a
//! release signed with the wrong key, or with one key twice, would ship looking checked — and
//! **no installed copy could ever be updated again.** There is no recovery from that, because a
//! recovery path is a way to sign without the keys. An adversarial review found it before the first
//! release was cut, which is the only reason it is not history.
//!
//! The replacement has to be the real thing: the keys compiled into the shipping binary, over the
//! bytes about to be uploaded, through the same [`crate::verify::verify_with`] a client calls.
//!
//! ## What it deliberately does not do
//!
//! It does not compare the serial in the trusted comment against the serial in the manifest body.
//! minisign covers the trusted comment with a second Ed25519 signature **under the same key**, so
//! that comparison weighs one authenticated value against another authenticated value from the same
//! signature. It would read like defence in depth and add none. The comment is reported instead, for
//! a person to read.

use crate::manifest::{self, Manifest, Trust};
use crate::verify::verify_with;

/// Why a triple was refused. Each variant is a thing that has a cause the operator can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// The build doing the checking has no keys, so it cannot check. Not a verdict on the files.
    NoKeysConfigured,
    /// The signatures did not satisfy two distinct configured keys over these exact bytes.
    Signature(String),
    /// The signatures were good and the manifest is not a manifest.
    Manifest(String),
    /// A client running `min_version` would refuse this manifest — including the case where the
    /// manifest refuses itself.
    RefusedByOldestClient { running: String, why: String },
    /// `version` is not newer than `min_version`, so the oldest build allowed to take this update
    /// would be told it is already current and never take it.
    NotNewerThanMinVersion {
        version: String,
        min_version: String,
    },
}

impl core::fmt::Display for Problem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Problem::NoKeysConfigured => f.write_str(
                "this build has no public keys compiled in, so it cannot check anything",
            ),
            Problem::Signature(e) => write!(
                f,
                "signatures refused ({e}) — both must be readable and made by two *different* \
                 configured keys over these exact manifest bytes"
            ),
            Problem::Manifest(e) => {
                write!(f, "the signatures are good but the manifest is not: {e}")
            }
            Problem::RefusedByOldestClient { running, why } => {
                write!(f, "a client running {running} would refuse this: {why}")
            }
            Problem::NotNewerThanMinVersion {
                version,
                min_version,
            } => write!(
                f,
                "version {version} is not newer than min_version {min_version}, so the oldest \
                 build allowed to take this update would be told it is already current"
            ),
        }
    }
}

/// What a good triple says. Printed by the release script so the operator sees the numbers that
/// were signed rather than the numbers the script believes it wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub trusted_comment: String,
    pub manifest: Manifest,
}

/// Verify a manifest and its two signatures the way a client will, then check the manifest could
/// actually be taken by the oldest build it claims to serve.
///
/// `now` is passed in rather than read, so this is pure and the expiry case is testable.
pub fn check(
    keys: &[&str; crate::verify::REQUIRED],
    manifest_text: &str,
    sig_a: &str,
    sig_b: &str,
    now: u64,
) -> Result<Report, Problem> {
    if keys.iter().any(|k| k.trim().is_empty()) {
        return Err(Problem::NoKeysConfigured);
    }

    let v = verify_with(keys, manifest_text.as_bytes(), &[sig_a, sig_b])
        .map_err(|e| Problem::Signature(e.to_string()))?;

    let m = manifest::parse(manifest_text).map_err(|e| Problem::Manifest(format!("{e:?}")))?;

    // The client's own trust check, run as the *oldest* build this release claims to serve. The
    // serial floor is one below this manifest's own, which is the only floor that is both truthful
    // and satisfiable: a real client's floor is whatever it last accepted, and that is necessarily
    // lower than a new release's.
    let trust = Trust {
        now,
        serial_floor: m.serial.saturating_sub(1),
        running: m.min_version,
    };
    manifest::check_trust(&m, &trust).map_err(|e| Problem::RefusedByOldestClient {
        running: m.min_version.to_string(),
        why: format!("{e:?}"),
    })?;

    // `check_trust` passing is not enough: `min_version == version` satisfies it and still means
    // the oldest permitted client is told it is current. The first dry run of the release script
    // produced `min_version=0.7.0` with `version=0.6.3`, which is the same mistake in the other
    // direction, so both ends are checked here.
    if !manifest::is_newer_than(&m, m.min_version) {
        return Err(Problem::NotNewerThanMinVersion {
            version: m.version.to_string(),
            min_version: m.min_version.to_string(),
        });
    }

    Ok(Report {
        trusted_comment: v.trusted_comment,
        manifest: m,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same throwaway keys as `tests/signed_chain.rs`: made with `rsign2` on 2026-08-08 for
    /// tests and nothing else, passwordless, never signed a release. The production keys are made by
    /// whoever cuts releases and their secret halves are not in this repository.
    const PUB_A: &str = "RWRwZdx9gJZvLh1QRU/Usct6/5n6dtsYe2TAF56sZGajwO5IB9beT4Ze";
    const PUB_B: &str = "RWS5WEdGsVbxUx0bTTSsrNGWR6eXwyjMOQBLxx55horOhwgVOK7dkhd/";

    /// Byte-exact: this is the message that was signed.
    const MANIFEST: &str = "\
# vigil update manifest — signed, do not edit
schema=1
serial=7
version=0.7.0
expires=2036-11-12T00:00:00Z
min_version=0.6.3
critical=0
base=https://github.com/resul-e/vigil/releases/download/v0.7.0/
notes_tr=Zincir testi.
notes_en=Chain test.
file=0 vigil-repair.exe 23 1 263a50dc802aa2ed94428ee89e69c884aa0dc15d4d1fac9893ff28d36dfbfbb1
file=1 vigil.exe 16 1 2b4f10c4a4362cb8b18cf5c5a38dbba7d6a7f12dbf0b56da245c01807acc94a1
file=2 vigil-app.exe 20 1 66f1cb4d2eb33eecb7022c192717ae91b8a6b74218bbf543222a1064fec5dd7f
";

    const SIG_A: &str = "untrusted comment: signature from rsign secret key\n\
RURwZdx9gJZvLtPXVRT8XmEMRfjK69Lem++Gnov6ERwK5z+MOMyMyK4egXEriwUgPD31/hGa3CNfm0RfojxEX7oiXVBxECAjzws=\n\
trusted comment: vigil 0.7.0 serial=7\n\
J6A/AY4E2CuTbh7KXbdMDm9gTN/V46MJHB1Kzix988uPFQv3Cq5PSfPqoWKEg95M9HaVLhCWSMmdaXpJcBYuDQ==\n";

    const SIG_B: &str = "untrusted comment: signature from rsign secret key\n\
RUS5WEdGsVbxUxk+/vGL8GTk9xQOR8m2k+uxXRaLlDos1uIALMVrjdwtGQIiluxXM2bBwWRrGQTh7mU3bT4z5YCAOwX32WxeGwA=\n\
trusted comment: vigil 0.7.0 serial=7\n\
SE92onlmCp6MTahI80xGyQZw3BACMJEIonzmVNfrUM7mjU5nxjkVWhvtj9+3khXgKv89jjYMxCLKCsKXXPWaBw==\n";

    const NOW: u64 = 1_760_000_000;

    #[test]
    fn a_properly_signed_release_passes_and_reports_what_was_signed() {
        let r = check(&[PUB_A, PUB_B], MANIFEST, SIG_A, SIG_B, NOW).expect("must pass");
        assert!(r.trusted_comment.contains("serial=7"), "{r:?}");
        assert_eq!(r.manifest.serial, 7);
        assert_eq!(r.manifest.version.to_string(), "0.7.0");
        assert_eq!(r.manifest.files.len(), 3);
    }

    /// The case the old step could not see, and the reason this module exists: a build whose keys
    /// are not the keys that signed. The signatures are perfectly valid — they are just not ours.
    #[test]
    fn the_wrong_keys_are_refused_rather_than_reported_configured() {
        // A real key, but a third one that did not sign this manifest.
        const STRANGER: &str = "RWT0GYJVxnOeVOrj9xZV53jYfDNRQWU2B7WSCjVTjUjsPPy0PZPJL0ir";
        let e = check(&[PUB_A, STRANGER], MANIFEST, SIG_A, SIG_B, NOW).expect_err("must refuse");
        assert!(matches!(e, Problem::Signature(_)), "{e:?}");
    }

    /// One key used twice. Two copies of one signature is not two signatures, and a release made
    /// that way would look signed while resting on a single compromise.
    #[test]
    fn the_same_key_twice_is_refused() {
        let e = check(&[PUB_A, PUB_A], MANIFEST, SIG_A, SIG_A, NOW).expect_err("must refuse");
        assert!(matches!(e, Problem::Signature(_)), "{e:?}");

        // And one good signature presented twice against two real keys.
        let e = check(&[PUB_A, PUB_B], MANIFEST, SIG_A, SIG_A, NOW).expect_err("must refuse");
        assert!(matches!(e, Problem::Signature(_)), "{e:?}");
    }

    #[test]
    fn a_placeholder_key_is_its_own_answer_and_not_a_verdict_on_the_files() {
        for keys in [["", ""], [PUB_A, ""], ["", PUB_B], ["  ", PUB_B]] {
            assert_eq!(
                check(&keys, MANIFEST, SIG_A, SIG_B, NOW),
                Err(Problem::NoKeysConfigured),
                "{keys:?}"
            );
        }
    }

    /// A manifest edited after signing — the whole point of signing it.
    #[test]
    fn a_manifest_edited_after_signing_is_refused() {
        let tampered = MANIFEST.replace("serial=7", "serial=8");
        let e = check(&[PUB_A, PUB_B], &tampered, SIG_A, SIG_B, NOW).expect_err("must refuse");
        assert!(matches!(e, Problem::Signature(_)), "{e:?}");

        // A digest digit. Still parses, still looks like a manifest, names a file an attacker
        // would control.
        let tampered = MANIFEST.replace("263a50dc", "263a50dd");
        let e = check(&[PUB_A, PUB_B], &tampered, SIG_A, SIG_B, NOW).expect_err("must refuse");
        assert!(matches!(e, Problem::Signature(_)), "{e:?}");
    }

    /// Unreadable or empty signature text must be a refusal, not a pass. A release script that
    /// passed an empty file by accident is exactly the shape of mistake this guards.
    #[test]
    fn empty_or_truncated_signatures_are_refused() {
        for bad in ["", "\n", "untrusted comment: x\n", &SIG_A[..40]] {
            let e = check(&[PUB_A, PUB_B], MANIFEST, bad, SIG_B, NOW).expect_err("{bad:?}");
            assert!(matches!(e, Problem::Signature(_)), "{bad:?} → {e:?}");
        }
    }

    /// An expired manifest is refused *at release time*, so nobody signs one by accident and then
    /// wonders why every client says `untrusted`.
    #[test]
    fn a_manifest_that_has_already_expired_is_refused_before_it_is_published() {
        // `expires=2036-11-12T00:00:00Z` in MANIFEST is epoch 2110060800 — taken from the parser's
        // own output, not from arithmetic done in my head, which has been wrong about an epoch
        // before. One second past it is the interesting instant.
        let m = manifest::parse(MANIFEST).expect("parses");
        assert_eq!(m.expires, 2_110_060_800, "the expiry this test turns on");
        let e =
            check(&[PUB_A, PUB_B], MANIFEST, SIG_A, SIG_B, m.expires + 1).expect_err("must refuse");
        match e {
            Problem::RefusedByOldestClient { running, .. } => assert_eq!(running, "0.6.3"),
            other => panic!("{other:?}"),
        }
    }

    /// Both ends of the `min_version` mistake. The release script's own first dry run produced the
    /// second one, which is why this is checked here and not only in bash.
    #[test]
    fn a_manifest_that_would_refuse_itself_is_refused() {
        // min_version == version: the oldest permitted client is told it is already current, so it
        // can never take the update it is permitted to take.
        let text = MANIFEST.replace("min_version=0.6.3", "min_version=0.7.0");
        // Re-signing is not possible here (no secret keys in this repository), so this asserts the
        // *ordering* of the checks instead: the signature is refused first, and that is correct —
        // an unsigned edit must never reach the semantic checks.
        let e = check(&[PUB_A, PUB_B], &text, SIG_A, SIG_B, NOW).expect_err("must refuse");
        assert!(
            matches!(e, Problem::Signature(_)),
            "the signature gate must come first: {e:?}"
        );
    }

    /// The `NotNewerThanMinVersion` and self-refusal arms, reached directly. They cannot be reached
    /// through `check` without a secret key, so they are exercised against the pure predicates they
    /// wrap — otherwise the two arms would be unreachable code with a comment claiming otherwise.
    #[test]
    fn the_semantic_arms_are_the_predicates_they_claim_to_be() {
        let m = manifest::parse(MANIFEST).expect("parses");

        let same = crate::Version {
            major: 0,
            minor: 7,
            patch: 0,
        };
        assert!(
            !manifest::is_newer_than(&m, same),
            "0.7.0 is not newer than 0.7.0, which is what the arm reports"
        );
        assert!(manifest::is_newer_than(&m, m.min_version));

        // And the floor this module chooses is the only satisfiable one: its own serial would refuse.
        let refusing = Trust {
            now: NOW,
            serial_floor: m.serial,
            running: m.min_version,
        };
        assert!(manifest::check_trust(&m, &refusing).is_err());
        let ours = Trust {
            now: NOW,
            serial_floor: m.serial.saturating_sub(1),
            running: m.min_version,
        };
        assert!(manifest::check_trust(&m, &ours).is_ok());
    }
}
