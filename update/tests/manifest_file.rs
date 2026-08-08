//! The manifest the release script writes must parse with the parser that will read it.
//!
//! Two programs produce and consume this file — a shell script and a Rust parser — and nothing else
//! connects them. Without this test the first time anyone discovers a mismatch is when a client
//! refuses a release, which is the worst possible moment: the fix has to be delivered by the
//! mechanism that just broke.

use vigil_update::manifest;
use vigil_update::Version;

/// `update/vigil-manifest.txt`, which `scripts/release.sh` writes and
/// `raw.githubusercontent.com` serves as the fallback endpoint.
fn manifest_text() -> Option<String> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vigil-manifest.txt");
    std::fs::read_to_string(p).ok()
}

#[test]
fn the_committed_manifest_parses_and_is_internally_consistent() {
    let Some(text) = manifest_text() else {
        // Before the first release there is nothing to check, and inventing a pass would be worse
        // than saying so.
        eprintln!("no update/vigil-manifest.txt yet — nothing to check");
        return;
    };

    let m = manifest::parse(&text).expect("the release script must write a manifest we can parse");

    // The version in the manifest is the version of this workspace. If they drift, the release
    // script hashed one build and described another.
    assert_eq!(
        m.version,
        Version::running(),
        "the manifest names {} but this workspace is {}",
        m.version,
        Version::running()
    );

    // A manifest whose min_version is above its own version refuses itself: the client compares
    // min_version against what is running, which after the update is exactly `version`.
    assert!(
        m.min_version <= m.version,
        "min_version {} is newer than version {} — this manifest would refuse itself",
        m.min_version,
        m.version
    );

    // The order that makes an interrupted update safe.
    assert_eq!(
        m.files.first().expect("some").name,
        "vigil-repair.exe",
        "the safety net must be replaced first"
    );
    assert_eq!(
        m.files.last().expect("some").name,
        "vigil-app.exe",
        "the application must be replaced last"
    );

    // Every file the update carries must be one the swap planner accepts, and the required ones
    // must include the two that matter.
    for want in ["vigil-repair.exe", "vigil-update.exe", "vigil-app.exe"] {
        let f = m
            .files
            .iter()
            .find(|f| f.name == want)
            .unwrap_or_else(|| panic!("{want} is missing from the manifest"));
        assert!(f.required, "{want} must be required");
        assert!(f.size > 0);
    }

    // And it must be trustworthy to a client running this version, with a floor below its serial.
    let trust = manifest::Trust {
        now: vigil_core::clock::parse_utc("2026-08-08T00:00:00Z").expect("a fixed now"),
        serial_floor: m.serial - 1,
        running: Version::running(),
    };
    manifest::check_trust(&m, &trust).expect("a freshly written manifest must be trusted");
}

/// The base URL must point at the release for *this* version, or the client downloads the previous
/// release's binaries and every hash fails.
#[test]
fn the_base_url_names_this_versions_release() {
    let Some(text) = manifest_text() else { return };
    let m = manifest::parse(&text).expect("parses");
    assert!(
        m.base.ends_with(&format!("/v{}/", m.version)),
        "base {:?} does not name v{}",
        m.base,
        m.version
    );
    assert!(m
        .base
        .starts_with("https://github.com/resul-e/vigil/releases/download/"));
}
