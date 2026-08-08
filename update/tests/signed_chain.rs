//! The whole chain in one test: a manifest that was **really signed**, verified by the shipping
//! verifier, staged from bytes a fetcher handed over, planned, applied — and only then checked
//! against the hashes in the text that was signed.
//!
//! Every link in this chain already has its own tests, and that was the gap. `verify` is tested
//! against a fixed message; `stage` is tested with a fetcher that hands over known bytes; `plan` is
//! tested against hand-written digest tables; `apply` is tested by the crash matrix. Each of those
//! proves its own link and none of them proves the links are *joined* — that the digest `plan`
//! compares is the digest out of the manifest that `verify` accepted, over the bytes `stage`
//! actually wrote. A mismatch there is invisible to every one of them and is precisely the shape
//! of bug that ends with a file being trusted because it is present rather than because it is right.
//!
//! Runs on Linux, so it is in the fast loop. The one Windows-only thing in `apply` — running the
//! replaced repair tool — is a closure, and here it is a stub; the crash matrix is what exercises
//! it for real.

use vigil_core::sha256;
use vigil_update::manifest::{self, Trust};
use vigil_update::plan;
use vigil_update::stage;
use vigil_update::verify::verify_with;
use vigil_update::{apply, version::Version};

/// Keys made with `rsign2` for this test and nothing else: passwordless, generated on 2026-08-08,
/// never signed a release and never will. The production keys are made by whoever cuts releases and
/// their secret halves do not exist in this repository — which is why `PUBLIC_KEYS` is still empty
/// and a build says `nokeys` rather than pretending.
const PUB_A: &str = "RWRwZdx9gJZvLh1QRU/Usct6/5n6dtsYe2TAF56sZGajwO5IB9beT4Ze";
const PUB_B: &str = "RWS5WEdGsVbxUx0bTTSsrNGWR6eXwyjMOQBLxx55horOhwgVOK7dkhd/";

/// **Byte-exact**, including the trailing newline: this is the message that was signed, so a single
/// character of drift here makes the signature fail and the test tells you so.
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

/// The bytes the manifest above describes. Fixed content, so the hashes in the signed text are
/// constants and the signature can be a constant too.
const NEW: &[(&str, &[u8])] = &[
    ("vigil-repair.exe", b"vigil-repair 0.7.0 new\n"),
    ("vigil.exe", b"vigil 0.7.0 new\n"),
    ("vigil-app.exe", b"vigil-app 0.7.0 new\n"),
];

/// A folder holding the old build, in a directory this test owns.
fn sandbox(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "vigil-chain-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("sandbox");
    for (name, _) in NEW {
        std::fs::write(p.join(name), format!("{name} 0.6.3 old\n")).expect("old file");
    }
    p
}

/// Serve the manifest's own bytes, by URL. Stands in for the network and for nothing else — the
/// real fetcher has its own tests and its own live measurement.
fn serve(url: &str) -> Result<Vec<u8>, String> {
    for (name, bytes) in NEW {
        if url.ends_with(name) {
            return Ok(bytes.to_vec());
        }
    }
    Err(format!("no such file: {url}"))
}

#[test]
fn a_really_signed_manifest_goes_all_the_way_to_replaced_files() {
    // 1. Two signatures over the manifest, checked by the code that ships.
    let v = verify_with(&[PUB_A, PUB_B], MANIFEST.as_bytes(), &[SIG_A, SIG_B])
        .expect("both signatures must verify over the exact manifest bytes");
    assert!(
        v.trusted_comment.contains("serial=7"),
        "the trusted comment is where the serial is stated a second time: {:?}",
        v.trusted_comment
    );

    // 2. Only now is the text parsed. Trust checked against a running build older than this one.
    let m = manifest::parse(MANIFEST).expect("parses");
    manifest::check_trust(
        &m,
        &Trust {
            now: 1_760_000_000,
            serial_floor: 0,
            running: Version {
                major: 0,
                minor: 6,
                patch: 3,
            },
        },
    )
    .expect("a fresh manifest from a newer release must be trusted");
    assert!(manifest::is_newer_than(
        &m,
        Version {
            major: 0,
            minor: 6,
            patch: 3
        }
    ));

    // 3. Stage from "the network". Every file is fetched, because the folder holds the old build.
    let folder = sandbox("full");
    let staged = stage::stage(&folder, &m, serve).expect("stages");
    assert_eq!(staged.fetched.len(), 3, "{staged:?}");
    assert!(staged.gave_up.is_empty(), "{staged:?}");
    assert!(staged.complete(&m));

    // **The join.** The digests `plan` will compare are the ones out of the signed text, and they
    // must describe the bytes `stage` wrote. This assertion is the reason this file exists.
    let on_staging = stage::hash_folder(&stage::staging_dir(&folder), &m);
    for f in &m.files {
        let got = on_staging
            .get(&f.name)
            .unwrap_or_else(|| panic!("{} was not staged", f.name));
        assert!(
            sha256::eq(got, &f.digest),
            "{}: staged bytes do not hash to the digest that was signed",
            f.name
        );
    }

    // 4. Plan, in the order the crash-safety argument requires.
    let on_disk = stage::hash_folder(&folder, &m);
    let p = plan::plan(&m, &on_disk, &on_staging).expect("plans");
    let names: Vec<&str> = p.steps.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["vigil-repair.exe", "vigil.exe", "vigil-app.exe"],
        "the safety net first and the application last"
    );

    // 5. Apply. The repair check is a stub here; the crash matrix runs the real binary.
    std::fs::write(stage::ready_marker(&folder), stage::ready_text(&m)).expect("marker");
    let mut check = |_: &std::path::Path| Ok(());
    let out = apply::apply(&folder, &p, &mut check, None).expect("applies");
    assert!(out.finished(), "{out:?}");

    // 6. The far end of the chain: what is on disk is what was signed.
    assert!(
        apply::folder_matches(&folder, &m),
        "outstanding: {:?}",
        apply::outstanding(&folder, &m)
    );
    for (name, bytes) in NEW {
        assert_eq!(
            std::fs::read(folder.join(name)).expect("replaced file"),
            *bytes,
            "{name}"
        );
    }

    let _ = std::fs::remove_dir_all(&folder);
}

/// The same chain, one byte different. Nothing may reach the folder.
///
/// Two independent refusals, and the test checks both — because either one alone would make the
/// other's failure invisible.
#[test]
fn a_manifest_edited_by_anybody_without_the_keys_stops_at_the_first_gate() {
    // A digit of a digest, changed. This is the interesting tamper: the text still parses, still
    // looks like a manifest, and names a file the attacker controls.
    let tampered = MANIFEST.replace(
        "263a50dc802aa2ed94428ee89e69c884aa0dc15d4d1fac9893ff28d36dfbfbb1",
        "263a50dc802aa2ed94428ee89e69c884aa0dc15d4d1fac9893ff28d36dfbfbb0",
    );
    assert_ne!(tampered, MANIFEST, "the replacement must have happened");

    // Gate one: the signature. It fails, and that is where a real client stops.
    assert!(
        verify_with(&[PUB_A, PUB_B], tampered.as_bytes(), &[SIG_A, SIG_B]).is_err(),
        "an edited manifest must not verify"
    );

    // Gate two, on the assumption that gate one was somehow passed: the bytes still have to hash
    // to what the manifest says. A file cannot be trusted for being present.
    let m = manifest::parse(&tampered).expect("the tampered text still parses — that is the point");
    let folder = sandbox("tampered");
    let staged = stage::stage(&folder, &m, serve);
    match staged {
        Err(_) => {}
        Ok(s) => assert!(
            !s.complete(&m),
            "a required file whose bytes do not match the manifest must not be reported staged: {s:?}"
        ),
    }
    let on_disk = stage::hash_folder(&folder, &m);
    let on_staging = stage::hash_folder(&stage::staging_dir(&folder), &m);
    assert!(
        on_staging.get("vigil-repair.exe").is_none(),
        "bytes that failed their hash must not be left staged"
    );
    // And the planner refuses rather than quietly skipping the file it cannot account for.
    let p = plan::plan(&m, &on_disk, &on_staging);
    assert!(
        p.is_err()
            || p.as_ref()
                .unwrap()
                .steps
                .iter()
                .all(|s| s.name != "vigil-repair.exe"),
        "a required file with no correct bytes anywhere must never become a swap step: {p:?}"
    );

    // Nothing was replaced.
    assert_eq!(
        std::fs::read(folder.join("vigil-repair.exe")).expect("still there"),
        b"vigil-repair.exe 0.6.3 old\n",
        "the old file must be untouched"
    );

    let _ = std::fs::remove_dir_all(&folder);
}

/// What `scripts/release.sh` calls, over three files on disk, with signatures that were really made.
///
/// `release::check` is unit-tested against these same constants, so what this adds is the part the
/// unit tests cannot reach: **reading three files and passing them in the right order.** That is the
/// whole body of `verify_cmd`, and getting the argument order wrong there would fail at exactly one
/// moment — the first real release, at whatever hour it happens — with the operator holding two keys
/// and no idea whether the problem is the keys or the script.
///
/// The remaining untested atom is that `verify_cmd` passes `verify::PUBLIC_KEYS` rather than some
/// other array. That one is a single token, and a keyless build has been confirmed by hand to exit 3
/// with its reason rather than passing, so the failure direction is safe either way.
#[test]
fn the_release_check_works_over_files_on_disk_in_the_order_the_script_passes_them() {
    use vigil_update::release::{self, Problem};

    let dir = std::env::temp_dir().join(format!(
        "vigil-relcheck-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let m = dir.join("vigil-manifest.txt");
    let a = dir.join("vigil-manifest.txt.minisig");
    let b = dir.join("vigil-manifest.txt.minisig2");
    std::fs::write(&m, MANIFEST).expect("manifest");
    std::fs::write(&a, SIG_A).expect("sig a");
    std::fs::write(&b, SIG_B).expect("sig b");

    let read = |p: &std::path::Path| std::fs::read_to_string(p).expect("readable");
    let now = 1_760_000_000;

    let r = release::check(&[PUB_A, PUB_B], &read(&m), &read(&a), &read(&b), now)
        .expect("the triple the script writes must verify");
    assert_eq!(r.manifest.serial, 7);
    assert!(r.trusted_comment.contains("0.7.0"));

    // Order does not matter to the verifier — two distinct keys, satisfied in any arrangement — and
    // that is worth pinning, because it is why the script cannot break by naming the sigs the other
    // way round.
    assert!(release::check(&[PUB_A, PUB_B], &read(&m), &read(&b), &read(&a), now).is_ok());

    // And one file swapped for another is refused rather than silently accepted.
    let e = release::check(&[PUB_A, PUB_B], &read(&a), &read(&a), &read(&b), now)
        .expect_err("the manifest argument is not a signature");
    assert!(matches!(e, Problem::Signature(_)), "{e:?}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Re-running the whole chain over a folder that is already updated does nothing and costs no fetch.
///
/// The property the design leans on — no rollback journal, because re-planning from hashes yields
/// exactly the remaining work — stated over the real chain rather than over a digest table.
#[test]
fn running_the_chain_twice_is_a_no_op_the_second_time() {
    let m = manifest::parse(MANIFEST).expect("parses");
    let folder = sandbox("twice");

    let mut check = |_: &std::path::Path| Ok(());
    let first = stage::stage(&folder, &m, serve).expect("stages");
    assert_eq!(first.fetched.len(), 3);
    std::fs::write(stage::ready_marker(&folder), stage::ready_text(&m)).expect("marker");
    let p = plan::plan(
        &m,
        &stage::hash_folder(&folder, &m),
        &stage::hash_folder(&stage::staging_dir(&folder), &m),
    )
    .expect("plans");
    apply::apply(&folder, &p, &mut check, None).expect("applies");
    assert!(apply::folder_matches(&folder, &m));

    // Second run: the folder is already right, so nothing is fetched and there is nothing to do.
    let second = stage::stage(&folder, &m, |url| {
        panic!("the second run must not fetch anything, and it asked for {url}")
    })
    .expect("stages");
    assert_eq!(second.current.len(), 3, "{second:?}");
    assert!(second.fetched.is_empty(), "{second:?}");
    let p2 = plan::plan(
        &m,
        &stage::hash_folder(&folder, &m),
        &stage::hash_folder(&stage::staging_dir(&folder), &m),
    )
    .expect("plans");
    assert!(p2.nothing_to_do(), "{p2:?}");

    let _ = std::fs::remove_dir_all(&folder);
}
