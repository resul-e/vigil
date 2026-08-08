//! Is this manifest really from us?
//!
//! There is no code-signing certificate. Windows already warns about these binaries and the README
//! tells people to click through, so a certificate is not the story and cannot be. The story is
//! two minisign keys, **both of which must have signed**, verified before a single downloaded byte
//! is allowed near the application folder.
//!
//! ## Why two keys and not one
//!
//! One key is one laptop. If it is stolen, copied, or backed up somewhere careless, whoever has it
//! can sign an update for every installed copy of this tool — and the people running it are in
//! Turkey, using it to reach things somebody would rather they did not. Two keys, one of them kept
//! physically away from the machine that builds releases, means a single compromise produces
//! signatures that no client accepts.
//!
//! It cuts the other way too, and that is the part worth being honest about: **losing either key
//! means no installed copy can ever be updated again.** There is no recovery path built into the
//! design because there cannot be one — a recovery path is by definition a way to sign without the
//! keys. The mitigation is a rehearsal, not a mechanism: restore both secret keys from backup onto
//! a machine that has never held them and re-sign a manifest, before the first release ships.
//!
//! ## What the signature does and does not cover
//!
//! minisign signs the **exact bytes** of the file, so there is no canonical form to argue about.
//! It also signs a *trusted comment*, and the release process puts the serial in it, so the serial
//! is stated twice. [`verify`] returns it, and the release script prints it — **for a person to
//! read, not for the code to cross-check.** That distinction was wrong here until 2026-08-08: a
//! reviewer read `minisign-verify` and pointed out that the trusted comment is covered by a second
//! signature under the *same* key, so comparing the serial in the comment against the serial in the
//! body weighs one authenticated value against another authenticated value from the same signature.
//! It would read like defence in depth and add none. There is no reachable state in which the
//! comment is attacker-controlled while the body is not.
//!
//! The **untrusted** comment is not signed and is therefore worth nothing. A test asserts that
//! editing it changes nothing, so nobody is tempted to read anything out of it.

use minisign_verify::{PublicKey, Signature};

/// The production public keys, in the binary.
///
/// Generated 2026-08-09 by the person who cuts releases; the private halves have never been on any
/// machine that builds this, and key B's is kept off it entirely. They were deliberately *not*
/// generated as a side effect of writing this module — a key created by the code that checks it
/// belongs to nobody.
///
/// These are compiled in, and that is the whole point: a key fetched over the network is worthless,
/// because whoever can serve a forged update can serve a forged key with it. The consequence to
/// respect is that a build shipped with the placeholder can **never** be given keys afterwards — it
/// reports `nokeys` for the life of that install. `keys_are_configured` answers whether a build can
/// update itself, `scripts/release.sh` refuses to publish while it is false, and
/// `the_keys_that_ship_are_two_real_and_different_keys` guards the constant itself.
pub const PUBLIC_KEYS: [&str; 2] = [
    // key A — minisign key id 967CE701B683EE3D
    "RWQ97oO2Aed8lgUoDCOPmtccFe9Y6PUWECT7YTLfFd8mmrUfZgrAx/bV",
    // key B — minisign key id 3756C4BE817EF52D, secret half kept off the build machine
    "RWQt9X6BvsRWN5H2bY6mp5XiwpQXDclYEQV4TBdE+jNVXqF6m+qRWmsf",
];

/// How many signatures must verify. Both, always.
pub const REQUIRED: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The build has no keys compiled in, so it cannot check anything. Reported rather than
    /// treated as a failed signature: the difference is "this build cannot update" versus "this
    /// update is not genuine", and telling a user the second when the first is true is a lie.
    NoKeysConfigured,
    /// A compiled-in key is not a minisign public key. A build mistake, and a loud one.
    KeyUnreadable { index: usize },
    /// None of the supplied signature files parse.
    NoSignaturesReadable,
    /// A key that no supplied signature satisfies. The index says which, so a release that signed
    /// with only one key produces a message naming the one that is missing.
    NotSignedBy { index: usize },
    /// Two signatures that both verify — against the *same* key. Two copies of one signature is
    /// not two signatures, and without this check a single compromised key would be enough.
    SameKeyTwice { index: usize },
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use VerifyError::*;
        match self {
            NoKeysConfigured => f.write_str("this build has no update keys and cannot verify one"),
            KeyUnreadable { index } => write!(f, "compiled-in key {index} is not readable"),
            NoSignaturesReadable => f.write_str("no signature file could be read"),
            NotSignedBy { index } => write!(f, "not signed by key {index}"),
            SameKeyTwice { index } => write!(f, "both signatures are from key {index}"),
        }
    }
}

/// What a verified manifest came with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The trusted comment from the first signature. Signed, so it can be cross-checked against
    /// the manifest body.
    pub trusted_comment: String,
}

/// Does this build have keys at all?
pub fn keys_are_configured() -> bool {
    PUBLIC_KEYS.iter().all(|k| !k.trim().is_empty())
}

/// Verify `message` against the build's compiled-in keys.
pub fn verify(message: &[u8], signatures: &[&str]) -> Result<Verified, VerifyError> {
    if !keys_are_configured() {
        return Err(VerifyError::NoKeysConfigured);
    }
    verify_with(&PUBLIC_KEYS, message, signatures)
}

/// The same check against keys supplied by the caller.
///
/// Separate so the tests can exercise every path with keys they generated, and so the release
/// script can verify what it just signed with the keys it just used. The production path is
/// [`verify`]; this is the same function with the data made explicit.
pub fn verify_with(
    keys: &[&str; REQUIRED],
    message: &[u8],
    signatures: &[&str],
) -> Result<Verified, VerifyError> {
    let mut parsed_keys = Vec::with_capacity(REQUIRED);
    for (index, k) in keys.iter().enumerate() {
        parsed_keys.push(
            PublicKey::from_base64(k.trim()).map_err(|_| VerifyError::KeyUnreadable { index })?,
        );
    }

    // Parse whatever parses. A malformed extra file is not a reason to refuse an update that two
    // good signatures came with, and being strict here would make the release process brittle for
    // no gain in safety — an unparseable file satisfies nobody.
    let sigs: Vec<Signature> = signatures
        .iter()
        .filter_map(|s| Signature::decode(s).ok())
        .collect();
    if sigs.is_empty() {
        return Err(VerifyError::NoSignaturesReadable);
    }

    // Which signature satisfied which key. Order-independent on purpose: the release script
    // should not have to care which `.minisig` it writes first, and a design that depends on file
    // order is a design with a silent failure in it.
    let mut satisfied_by: Vec<usize> = Vec::with_capacity(REQUIRED);
    for (index, key) in parsed_keys.iter().enumerate() {
        let hit = sigs
            .iter()
            .position(|s| key.verify(message, s, false).is_ok())
            .ok_or(VerifyError::NotSignedBy { index })?;
        if satisfied_by.contains(&hit) {
            // The same signature satisfied two keys, which cannot happen for distinct keys — so
            // the two "keys" are the same key written twice.
            return Err(VerifyError::SameKeyTwice { index });
        }
        satisfied_by.push(hit);
    }

    Ok(Verified {
        trusted_comment: sigs[satisfied_by[0]].trusted_comment().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keys and signatures generated with `rsign2` for these tests and nothing else. They are
    /// passwordless, they have never signed a release, and they never will — the production keys
    /// are made separately by whoever cuts releases and their private halves do not exist here.
    const MSG: &[u8] = b"schema=1\nserial=7\n";

    const PUB_A: &str = "RWTcVsDrxv+rDY2Qo93wdBdXOLC9lrs/IWE6fmtaDKt2A2Th15uHH87K";
    const PUB_B: &str = "RWQJ0TJQ0mCNrMtjqPCEjume5P9wT6w/ArMAinQZmz5w/ffnXHPLv2MK";
    /// A third key nobody trusts: the stranger whose signature must never count.
    const PUB_C: &str = "RWT0GYJVxnOeVOrj9xZV53jYfDNRQWU2B7WSCjVTjUjsPPy0PZPJL0ir";

    const SIG_A: &str = "untrusted comment: signature from rsign secret key\n\
RUTcVsDrxv+rDaJyCS6h+GKYqwCGiLuVvlDD2p65ON2/petVn8reWI64fMuF4Dd/5IxpAO1S9mjri3vuylPOR8F6KbctsuREwwE=\n\
trusted comment: vigil manifest serial=7\n\
7bO30XjtQDr/okZYXHSkSZfpSLcPqC+KABW21wmAuSnTnLIuBlCXzrnK5l00p5sJ/9poUruyPO6TcfaxHnSmCw==\n";

    const SIG_B: &str = "untrusted comment: signature from rsign secret key\n\
RUQJ0TJQ0mCNrKDVsvz/pJk8hBoOSvHEtjSgrdpUxSknw4qKudqyXQwGdpUd6IomOa2Jv8G+BMpmkj8O+IDpJ24WXGUbhQlZ1Q4=\n\
trusted comment: vigil manifest serial=7\n\
7P88y6DgKQ5uPoVJzHTYftj1oJyaolKTNdLH6FW014YK45+LV+40vNpbb/ZMPJAKarcZM5qpssEcASKzzGsOAw==\n";

    const SIG_C: &str = "untrusted comment: signature from rsign secret key\n\
RUT0GYJVxnOeVJ6yDhOnaOZlENyCCscOHZB4LQVESpeXMc5CdNLyCLD37+rHf+kx/lUoRMBMEi6E6LZqSKxpQ+o31U0WOfKLtgs=\n\
trusted comment: vigil manifest serial=7\n\
lB2rVqk3G2HszXjcLi5TcU184tPA9qGGLucX1SRZPCEC6iuEq1YJAmViERC0LsL0kblJWMyK2HcXeRyLC7WzAA==\n";

    /// The shipped constant itself, guarded permanently.
    ///
    /// Every way this can be wrong locks the whole fleet out of updates with no recovery, and none
    /// of the other tests touch it — they all bring their own keys, deliberately, so that the logic
    /// could be exercised before a production key existed. That left the one value that actually
    /// ships as the only unchecked thing in the module.
    ///
    /// Three failure modes, all of which a person pasting base64 at midnight can produce, and all of
    /// which would have been discovered by the first user who never got an update:
    ///
    /// - a placeholder or blank entry — the build cannot verify anything, permanently, because these
    ///   are compiled in and cannot be delivered later;
    /// - a truncated or mistyped key — parses as nothing, so no signature ever satisfies it;
    /// - **the same key twice** — looks like two keys and is one, so a single compromise produces
    ///   signatures every client accepts. `verify_with` refuses this at runtime, which would show up
    ///   as a release that cannot be published. Better to fail here.
    #[test]
    fn the_keys_that_ship_are_two_real_and_different_keys() {
        assert!(
            keys_are_configured(),
            "PUBLIC_KEYS is the placeholder. A build that ships this reports `nokeys` for the life \
             of the install — the keys are compiled in, so they cannot be supplied afterwards."
        );

        for (i, k) in PUBLIC_KEYS.iter().enumerate() {
            PublicKey::from_base64(k.trim())
                .unwrap_or_else(|e| panic!("PUBLIC_KEYS[{i}] is not a minisign public key: {e}"));
        }

        // Compared as strings because `minisign_verify` does not expose the key id, and because for
        // keys `rsign` produced the comparison is exact anyway: its base64 is canonical, so the same
        // key is always the same string and two different keys can never collide. The ids themselves
        // were decoded and checked when these were pasted in — 967CE701B683EE3D and 3756C4BE817EF52D.
        assert_ne!(
            PUBLIC_KEYS[0].trim(),
            PUBLIC_KEYS[1].trim(),
            "both entries are the same key. Two copies of one signature is not two signatures, and \
             the whole point of two keys is that one compromise produces nothing a client accepts."
        );

        // No stray whitespace: `verify` trims, but a key with a newline in the middle of it would
        // trim to something that still fails, and the failure would arrive as "not signed by us".
        for (i, k) in PUBLIC_KEYS.iter().enumerate() {
            assert_eq!(k.trim(), *k, "PUBLIC_KEYS[{i}] has surrounding whitespace");
            assert!(!k.contains('\n'), "PUBLIC_KEYS[{i}] spans lines");
        }
    }

    /// A stranger's signatures must be refused by the keys that ship.
    ///
    /// The positive direction cannot be tested here — signing needs the secret halves, which are not
    /// in this repository and never will be, and `scripts/release.sh` checks it at the only moment it
    /// can: with `vigil-update verify`, over the files it just signed. So what is asserted here is the
    /// half that can be: real, well-formed signatures made by keys that are not ours get nowhere.
    #[test]
    fn signatures_from_keys_that_are_not_ours_are_refused_by_the_shipped_constant() {
        let e = verify(MSG, &[SIG_A, SIG_B]).expect_err("the test keys are not the release keys");
        assert!(
            matches!(e, VerifyError::NotSignedBy { .. }),
            "expected NotSignedBy, got {e:?}"
        );
    }

    #[test]
    fn a_build_without_keys_says_so_rather_than_calling_the_update_forged() {
        // Written when `PUBLIC_KEYS` was the placeholder, and it asserted that fact directly. Keys
        // shipped on 2026-08-09, so the *state* is now tested where it can be — through the explicit
        // form — while the property it exists for is unchanged: a build that cannot check must say
        // "I cannot check", never "this is not genuine". The distinction is the difference between a
        // user updating by hand and a user believing they are under attack.
        assert!(
            keys_are_configured(),
            "the shipped build has keys; the keyless case is exercised explicitly below"
        );
        for keyless in [["", ""], [" ", "\t"]] {
            assert_eq!(
                verify_with(&keyless, MSG, &[SIG_A]),
                Err(VerifyError::KeyUnreadable { index: 0 }),
                "an empty key cannot parse, and that is a build mistake rather than a verdict"
            );
        }
        // And the message the *product* path produces must not read as an accusation.
        assert!(VerifyError::NoKeysConfigured
            .to_string()
            .contains("cannot verify"));
        assert!(!VerifyError::NoKeysConfigured.to_string().contains("forged"));
    }

    #[test]
    fn an_unreadable_compiled_in_key_is_a_loud_build_mistake() {
        assert_eq!(
            verify_with(&["not a key", PUB_B], MSG, &[SIG_A]),
            Err(VerifyError::KeyUnreadable { index: 0 })
        );
        assert_eq!(
            verify_with(&[PUB_A, "RW-nonsense"], MSG, &[SIG_A]),
            Err(VerifyError::KeyUnreadable { index: 1 })
        );
    }

    #[test]
    fn no_readable_signature_is_its_own_answer() {
        assert_eq!(
            verify_with(&[PUB_A, PUB_B], MSG, &[]),
            Err(VerifyError::NoSignaturesReadable)
        );
        assert_eq!(
            verify_with(
                &[PUB_A, PUB_B],
                MSG,
                &["", "garbage", "untrusted comment: x"]
            ),
            Err(VerifyError::NoSignaturesReadable)
        );
    }

    /// One key is not enough, and the message names the one that is missing.
    #[test]
    fn one_signature_out_of_two_is_refused() {
        assert_eq!(
            verify_with(&[PUB_A, PUB_B], MSG, &[SIG_A]),
            Err(VerifyError::NotSignedBy { index: 1 })
        );
        assert!(VerifyError::NotSignedBy { index: 1 }
            .to_string()
            .contains("key 1"));
    }

    /// A signature over different bytes must not verify. This is the whole point of the exercise:
    /// the serial edited in the body, which is exactly what a rollback attack would do.
    #[test]
    fn a_message_that_was_not_the_one_signed_is_refused() {
        let tampered = b"schema=1\nserial=8\n";
        assert_eq!(
            verify_with(&[PUB_A, PUB_B], tampered, &[SIG_A, SIG_B]),
            Err(VerifyError::NotSignedBy { index: 0 })
        );
        // One bit is enough.
        let mut one_bit = MSG.to_vec();
        one_bit[0] ^= 1;
        assert_eq!(
            verify_with(&[PUB_A, PUB_B], &one_bit, &[SIG_A, SIG_B]),
            Err(VerifyError::NotSignedBy { index: 0 })
        );
        // And so is a trailing newline: minisign signs bytes, not lines.
        let mut extra = MSG.to_vec();
        extra.push(b'\n');
        assert!(verify_with(&[PUB_A, PUB_B], &extra, &[SIG_A, SIG_B]).is_err());
    }

    /// The case the whole module exists for: both real keys, both signatures, and it verifies —
    /// whichever order the files are handed over in.
    #[test]
    fn both_keys_signing_verifies_in_either_order() {
        let want = Ok(Verified {
            trusted_comment: "vigil manifest serial=7".into(),
        });
        assert_eq!(verify_with(&[PUB_A, PUB_B], MSG, &[SIG_A, SIG_B]), want);
        assert_eq!(verify_with(&[PUB_A, PUB_B], MSG, &[SIG_B, SIG_A]), want);
        // And the keys themselves may be listed in either order.
        assert_eq!(verify_with(&[PUB_B, PUB_A], MSG, &[SIG_A, SIG_B]), want);
    }

    /// The stranger's signature is a *real* signature — it verifies against the stranger's own
    /// key. Asserted first, because without it the refusals below would be testing that garbage
    /// fails rather than that a valid signature from the wrong signer fails, and those are
    /// different claims.
    #[test]
    fn the_strangers_signature_is_genuine_against_the_strangers_own_key() {
        assert!(
            verify_with(&[PUB_C, PUB_C], MSG, &[SIG_C, SIG_C]).is_err(),
            "the same key twice is still refused, even when it is the stranger's"
        );
        // The single-key check, which is what proves the material is valid: C's signature against
        // C's key and A's key, both configured, must fail only on the missing A.
        assert_eq!(
            verify_with(&[PUB_C, PUB_A], MSG, &[SIG_C]),
            Err(VerifyError::NotSignedBy { index: 1 }),
            "C's signature satisfied C, so the only thing missing was A"
        );
    }

    /// A stranger's signature counts for nothing, even alongside a real one. This is the attack
    /// the second key exists to stop: one compromised key plus one attacker key is still refused.
    #[test]
    fn a_third_partys_signature_does_not_substitute_for_a_missing_key() {
        assert_eq!(
            verify_with(&[PUB_A, PUB_B], MSG, &[SIG_A, SIG_C]),
            Err(VerifyError::NotSignedBy { index: 1 })
        );
        assert_eq!(
            verify_with(&[PUB_A, PUB_B], MSG, &[SIG_C, SIG_B]),
            Err(VerifyError::NotSignedBy { index: 0 })
        );
        // Three signatures, one of them a stranger's: the two real ones still carry it, because an
        // extra file nobody asked for satisfies nobody and refusing over it would gain nothing.
        assert!(verify_with(&[PUB_A, PUB_B], MSG, &[SIG_C, SIG_A, SIG_B]).is_ok());
        // And the stranger alone is refused twice over.
        assert_eq!(
            verify_with(&[PUB_A, PUB_B], MSG, &[SIG_C]),
            Err(VerifyError::NotSignedBy { index: 0 })
        );
    }

    /// Two copies of one signature is not two signatures. Without this check a single compromised
    /// key would be enough to ship an update — sign twice with it and hand over both files.
    #[test]
    fn one_key_signing_twice_cannot_stand_in_for_two() {
        // The shape a release script bug would produce: the same key configured twice.
        assert_eq!(
            verify_with(&[PUB_A, PUB_A], MSG, &[SIG_A, SIG_A]),
            Err(VerifyError::SameKeyTwice { index: 1 })
        );
        assert_eq!(
            verify_with(&[PUB_A, PUB_A], MSG, &[SIG_A]),
            Err(VerifyError::SameKeyTwice { index: 1 })
        );
    }

    /// The trusted comment is signed, so it can carry the serial as a second statement and be
    /// cross-checked against the body. This is the only thing in the signature worth reading.
    #[test]
    fn the_trusted_comment_comes_back_for_cross_checking() {
        let v = verify_with(&[PUB_A, PUB_B], MSG, &[SIG_A, SIG_B]).expect("verifies");
        assert_eq!(v.trusted_comment, "vigil manifest serial=7");
        assert!(v.trusted_comment.contains("serial=7"));
    }

    /// And the untrusted comment is worth nothing, which is asserted so nobody reads anything out
    /// of it later.
    #[test]
    fn editing_the_unsigned_comment_changes_nothing() {
        let edited = SIG_A.replacen(
            "untrusted comment: signature from rsign secret key",
            "untrusted comment: totally legitimate, promise",
            1,
        );
        let a = verify_with(&[PUB_A, PUB_B], MSG, &[SIG_A, SIG_B]);
        let b = verify_with(&[PUB_A, PUB_B], MSG, &[&edited, SIG_B]);
        assert_eq!(
            a, b,
            "the untrusted comment is not signed and must not matter"
        );
    }

    /// Truncating or corrupting a signature file must be a refusal, never a panic: it arrives over
    /// a network from a host that may be lying.
    #[test]
    fn a_corrupt_signature_never_panics() {
        for n in 0..SIG_A.len() {
            if let Some(s) = SIG_A.get(..n) {
                let _ = verify_with(&[PUB_A, PUB_B], MSG, &[s]);
            }
        }
        let bytes = SIG_A.as_bytes().to_vec();
        for i in 0..bytes.len() {
            for b in [0u8, b'\n', b'A', b'=', 0xff] {
                let mut m = bytes.clone();
                m[i] = b;
                if let Ok(s) = core::str::from_utf8(&m) {
                    let _ = verify_with(&[PUB_A, PUB_B], MSG, &[s]);
                }
            }
        }
    }

    /// `keys_are_configured` must need **both** halves, because a release that pasted one key and
    /// left the other blank is a build that can never verify anything and would otherwise look
    /// finished.
    #[test]
    fn keys_are_configured_needs_both_halves() {
        // The real constant has both, which is the only acceptable shipped state.
        assert!(keys_are_configured());

        // The predicate itself, over the shapes a half-finished release produces. Tested against the
        // same expression the constant uses rather than by mutating a `const`, which cannot be done —
        // the earlier version of this test could only assert its own premise, and did.
        let configured = |pair: [&str; 2]| pair.iter().all(|k| !k.trim().is_empty());
        for half in [
            ["", ""],
            [PUB_A, ""],
            ["", PUB_B],
            ["  ", PUB_B],
            [PUB_A, "\n"],
        ] {
            assert!(!configured(half), "{half:?} must not count as configured");
        }
        assert!(configured([PUB_A, PUB_B]));
        assert!(configured([PUBLIC_KEYS[0], PUBLIC_KEYS[1]]));
    }
}
