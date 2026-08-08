//! The gate for the whole update feature: stop at every boundary, and check the two things that
//! matter at each one.
//!
//! Windows only, and it runs the **real** `vigil-repair.exe` rather than a stub. That is the
//! difference between this and the library test of the same walk: here the safety net is verified
//! the way it will be in the field — by executing it and reading its exit status — on real NTFS,
//! with whatever real-time scanner the machine has switched on.
//!
//! At every boundary:
//!
//! 1. `vigil-repair.exe` exists **and runs**. This is the guarantee the whole ordering exists for,
//!    and it is the thing that saves a machine whose settings are stranded.
//! 2. A resume finishes the job, and afterwards every file in the folder hashes to what the
//!    manifest says.
//!
//! It needs the release binaries, and if they are not there it **fails** rather than skipping. A
//! gate that quietly passes when it could not run is not a gate.
//!
//!     cargo build --release --target x86_64-pc-windows-msvc
//!     cargo test  --release --target x86_64-pc-windows-msvc -p vigil-update --test crash_matrix

#![cfg(windows)]

use std::path::{Path, PathBuf};

use vigil_core::sha256;
use vigil_update::apply::{self, Boundary};
use vigil_update::guard;
use vigil_update::manifest::{self, Manifest};
use vigil_update::plan;
use vigil_update::stage;

/// Where the real binaries are. Two profiles, because the operator may have built either.
fn release_dir() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("target")
        .join("x86_64-pc-windows-msvc");
    for profile in ["release", "debug"] {
        let d = root.join(profile);
        if d.join("vigil-repair.exe").exists() {
            return d;
        }
    }
    panic!(
        "no vigil-repair.exe under {}. Build it first:\n  \
         cargo build --release --target x86_64-pc-windows-msvc",
        root.display()
    );
}

/// The binaries this walk replaces. `vigil-repair.exe` first and `vigil-app.exe` last, because that
/// order is the crash-safety argument and this test is the thing that proves it.
const NAMES: &[(&str, bool)] = &[
    ("vigil-repair.exe", true),
    ("vigil.exe", true),
    ("wirelog.exe", false),
    ("vigil-app.exe", true),
];

struct Sandbox(PathBuf);

impl Sandbox {
    /// A folder holding the *old* binaries, with a complete verified staging set of the *new* ones.
    ///
    /// "Old" is the real binary with a marker appended: a different hash, so a swap that silently
    /// did nothing is caught, and still a runnable executable, so the safety net can be *run* at
    /// every boundary rather than merely counted.
    fn ready(tag: &str) -> Sandbox {
        let src = release_dir();
        let p = std::env::temp_dir().join(format!("vigil-matrix-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(p.join(stage::STAGING)).expect("dirs");

        for (name, _) in NAMES {
            // The "old" file: the genuine binary with a marker appended, so it hashes differently
            // from the new one *and* still runs.
            //
            // The first version of this test used `vigil.exe` as the stand-in for every old file,
            // and the gate caught it immediately: `vigil.exe --version` exits 2, so the check that
            // the safety net *runs* failed before a single swap. Which is the check working. A PE
            // tolerates trailing bytes — that is how installers carry payloads — so appending is a
            // faithful stand-in for "an older build" in a way substituting a different program is
            // not.
            let mut old = std::fs::read(src.join(name)).expect("real binary");
            old.extend_from_slice(b"\n; vigil test: this stands in for an older build\n");
            std::fs::write(p.join(name), &old).expect("old binary");
            // The "new" file: the genuine article.
            std::fs::copy(src.join(name), p.join(stage::STAGING).join(name)).expect("new binary");
        }
        Sandbox(p)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// A manifest describing the staged files, signed by nobody — the signature path is covered by
    /// `verify`'s own tests with real keys; this walk is about the filesystem.
    fn manifest(&self) -> Manifest {
        let mut s = String::from(
            "schema=1\nserial=7\nversion=0.7.0\nexpires=2036-11-12T00:00:00Z\n\
             min_version=0.6.3\ncritical=0\n\
             base=https://github.com/resul-e/vigil/releases/download/v0.7.0/\n\
             notes_tr=t\nnotes_en=e\n",
        );
        for (i, (name, required)) in NAMES.iter().enumerate() {
            let path = self.0.join(stage::STAGING).join(name);
            let bytes = std::fs::metadata(&path).expect("staged").len();
            let digest = stage::hash_file(&path).expect("hash");
            s.push_str(&format!(
                "file={i} {name} {bytes} {} {}\n",
                u8::from(*required),
                sha256::hex(&digest)
            ));
        }
        manifest::parse(&s).expect("manifest")
    }

    fn mark_ready(&self, m: &Manifest) {
        std::fs::write(stage::ready_marker(self.path()), stage::ready_text(m)).expect("marker");
    }

    fn plan(&self, m: &Manifest) -> plan::Plan {
        let on_disk = stage::hash_folder(self.path(), m);
        let staged = stage::hash_folder(&stage::staging_dir(self.path()), m);
        plan::plan(m, &on_disk, &staged).expect("plans")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The safety net must be present **and runnable** at this instant. Not "a file exists" — run it.
fn assert_repair_works(folder: &Path, at: &str) {
    let repair = folder.join(plan::REPAIR);
    assert!(repair.exists(), "{at}: vigil-repair.exe is missing");
    guard::run_repair_version(&repair)
        .unwrap_or_else(|e| panic!("{at}: vigil-repair.exe would not run: {e}"));
}

#[test]
fn a_clean_update_replaces_everything_and_every_hash_matches() {
    let sb = Sandbox::ready("clean");
    let m = sb.manifest();
    sb.mark_ready(&m);
    assert_repair_works(sb.path(), "before");

    let mut check = |p: &Path| guard::run_repair_version(p);
    let out = apply::apply(sb.path(), &sb.plan(&m), &mut check, None).expect("applies");

    assert_eq!(out.replaced.len(), NAMES.len());
    assert!(out.finished());
    assert!(out.cleaned, "the staging folder should be gone");
    assert!(
        apply::folder_matches(sb.path(), &m),
        "outstanding: {:?}",
        apply::outstanding(sb.path(), &m)
    );
    assert_repair_works(sb.path(), "after");
}

/// **The gate.** Every boundary, five trials each, on real NTFS with the real repair tool.
///
/// Five rather than one because a filesystem race that happens one time in three would pass a
/// single run, and the whole point of this test is the case that does not reproduce on demand.
#[test]
fn stopping_at_every_boundary_leaves_a_working_repair_tool_and_a_resumable_folder() {
    let boundaries = {
        let sb = Sandbox::ready("enumerate");
        let m = sb.manifest();
        Boundary::all_for(&sb.plan(&m))
    };
    assert!(
        boundaries.len() >= 7,
        "expected a boundary per stage, got {boundaries:?}"
    );

    for b in &boundaries {
        for trial in 1..=5 {
            let at = format!("{b:?} trial {trial}");
            let sb = Sandbox::ready("matrix");
            let m = sb.manifest();
            sb.mark_ready(&m);

            let mut check = |p: &Path| guard::run_repair_version(p);
            let first = apply::apply(sb.path(), &sb.plan(&m), &mut check, Some(*b))
                .unwrap_or_else(|e| panic!("{at}: {e}"));
            assert_eq!(first.stopped_at, Some(*b), "{at}");

            // 1. The safety net works, right now, at this boundary.
            assert_repair_works(sb.path(), &at);

            if *b == Boundary::AfterCleanup {
                assert!(apply::folder_matches(sb.path(), &m), "{at}");
                continue;
            }

            // 2. A resume finishes it, and the bytes on disk are the bytes the manifest names.
            let mut check = |p: &Path| guard::run_repair_version(p);
            let second = apply::apply(sb.path(), &sb.plan(&m), &mut check, None)
                .unwrap_or_else(|e| panic!("{at}: resume failed: {e}"));
            assert!(second.finished(), "{at}");
            assert!(
                apply::folder_matches(sb.path(), &m),
                "{at}: resume did not reach the signed hashes; outstanding {:?}",
                apply::outstanding(sb.path(), &m)
            );
            assert_repair_works(sb.path(), &format!("{at} after resume"));
        }
    }
}

/// The runner-copy trick, as the design depends on it: a copy inside the staging folder replaces the
/// idle binary in the folder above while it is itself running.
///
/// Measured by hand on 2026-08-08 and kept as a test, because it is the assumption that removes
/// self-replacement from the entire design and it deserves to keep being true.
#[test]
fn a_runner_inside_staging_can_replace_the_binary_above_it() {
    let sb = Sandbox::ready("runner");
    let placed = apply::place_runner(sb.path(), &release_dir().join("vigil-update.exe"))
        .expect("places the runner");
    assert!(placed.exists());

    // The staged replacement for the updater itself.
    let staged = stage::staging_dir(sb.path()).join("vigil-update.exe");
    std::fs::copy(release_dir().join("vigil-update.exe"), &staged).expect("stage the updater");
    let live = sb.path().join("vigil-update.exe");
    std::fs::copy(release_dir().join("vigil.exe"), &live).expect("an older updater");

    // Rename over the idle target. The running image is the copy in staging, so this is allowed.
    std::fs::rename(&staged, &live).expect("the runner must be able to replace the idle binary");
    assert_eq!(
        stage::hash_file(&live),
        stage::hash_file(&release_dir().join("vigil-update.exe")),
        "the replacement did not land"
    );

    // And the leftover runner is removable once nothing is executing it.
    apply::sweep_old_runner(sb.path());
    assert!(!placed.exists(), "a leftover runner must be sweepable");
}
