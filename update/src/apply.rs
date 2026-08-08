//! Phase B: replacing the binaries. No network, and only after the settings are back.
//!
//! Everything here is one `rename` after another. That is not a simplification — it is the design.
//! Each replacement is a single same-volume rename over an **idle** file, so the target is either
//! wholly the old binary or wholly the new one and there is no instant at which a filename has no
//! file behind it. Nothing needs to replace itself, because `vigil-app.exe` has already exited and
//! this process runs from a copy inside the staging folder.
//!
//! Measured on this machine, 2026-08-08, with Defender real-time protection on:
//!
//! - a copy running from `.vigil-update/` renamed a staged file over an idle binary in the folder
//!   above it, and kept running;
//! - the leftover copy was deletable once it exited, and not before;
//! - **twenty swaps of a freshly written executable needed zero retries**, which is why this uses
//!   `std::fs::rename` and not two hand-declared Win32 externs;
//! - a file written by our own code carries no `Zone.Identifier`, so self-updating does not hand
//!   SmartScreen a reason it did not already have.
//!
//! ## The one rollback
//!
//! `vigil-repair.exe` is replaced first and then **run**, because it is the thing that saves a
//! machine whose settings are stranded and a broken one is worse than an old one. Before it is
//! replaced, the old copy is set aside; if the new one will not report its version, the old one
//! goes back and the update stops. That is the only rollback in the design, it is one file, and it
//! needs no log.
//!
//! ## Crash boundaries
//!
//! [`Boundary`] enumerates every point at which this can stop, and `apply` can be told to stop at
//! one on purpose. That is not a debugging convenience: the crash matrix is the gate for the whole
//! feature, and a gate that depends on someone killing a process at the right moment by hand is a
//! gate nobody runs twice.

use std::path::{Path, PathBuf};

use vigil_core::sha256;

use crate::manifest::Manifest;
use crate::plan::{Plan, APP, REPAIR};
use crate::stage::{hash_file, staging_dir, READY};

/// Where the old safety net is kept while the new one is being proved.
pub const PREVIOUS_REPAIR: &str = "vigil-repair.exe.previous";

/// Every point at which applying an update can stop.
///
/// Ordered as they occur. `apply` takes an optional one and stops there, which is how the crash
/// matrix is a repeatable command rather than a ritual with a stopwatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boundary {
    /// Before anything is renamed. Nothing has changed.
    BeforeAnything,
    /// The safety net has been set aside but not replaced.
    AfterSettingRepairAside,
    /// The safety net is replaced, and has not yet been proved to run.
    AfterRepairReplaced,
    /// The safety net ran and reported its version.
    AfterRepairVerified,
    /// After the nth ordinary file — counted from the first step that is not the safety net.
    AfterFile(usize),
    /// The application itself is replaced. Nothing is running.
    AfterApp,
    /// Everything is replaced and the staging folder has been cleaned up.
    AfterCleanup,
}

impl Boundary {
    /// Every boundary a plan of this shape actually has, in order. Used by the crash matrix so it
    /// tests the boundaries that exist rather than a list somebody kept in their head.
    pub fn all_for(plan: &Plan) -> Vec<Boundary> {
        let mut v = vec![Boundary::BeforeAnything];
        if plan.steps.iter().any(|s| s.name == REPAIR) {
            v.push(Boundary::AfterSettingRepairAside);
            v.push(Boundary::AfterRepairReplaced);
            v.push(Boundary::AfterRepairVerified);
        }
        let ordinary = plan
            .steps
            .iter()
            .filter(|s| s.name != REPAIR && s.name != APP)
            .count();
        for i in 0..ordinary {
            v.push(Boundary::AfterFile(i));
        }
        if plan.steps.iter().any(|s| s.name == APP) {
            v.push(Boundary::AfterApp);
        }
        v.push(Boundary::AfterCleanup);
        v
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyError {
    /// No `ready.txt`, so the staged set was never completed. Refused rather than half-applied.
    NotReady,
    /// The safety net was replaced and would not run. The old one has been put back and nothing
    /// else was touched.
    RepairBroken {
        detail: String,
        restored: bool,
    },
    /// A required file could not be replaced. What has already been replaced stays replaced — every
    /// binary in this set is standalone and a mixed set runs — and the next start finishes the job.
    RequiredSwapFailed {
        name: String,
        detail: String,
    },
    Io(String),
}

impl core::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use ApplyError::*;
        match self {
            NotReady => f.write_str("the staged update is not complete"),
            RepairBroken { detail, restored } => write!(
                f,
                "the new vigil-repair.exe would not run ({detail}); the old one was {}",
                if *restored {
                    "put back"
                } else {
                    "NOT put back"
                }
            ),
            RequiredSwapFailed { name, detail } => write!(f, "could not replace {name}: {detail}"),
            Io(e) => write!(f, "io: {e}"),
        }
    }
}

/// What applying did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub replaced: Vec<String>,
    /// Optional files that would not move. Recorded, not fatal — a locked `vigil-scan.exe` should
    /// not stop the update that fixes `vigil-app.exe`.
    pub skipped: Vec<String>,
    /// Where it stopped, when it was told to stop.
    pub stopped_at: Option<Boundary>,
    /// Whether the staging folder was cleaned up.
    pub cleaned: bool,
}

impl Applied {
    pub fn finished(&self) -> bool {
        self.stopped_at.is_none()
    }
}

/// How to run the new safety net, so the caller decides and this module stays testable.
///
/// On Windows this runs `vigil-repair.exe --version` and checks the exit status. In a test it is a
/// closure that says yes or no, which is how the "the new repair tool is broken" path is exercised
/// at all — provoking it for real would mean shipping a deliberately broken binary.
pub type RepairCheck<'a> = &'a mut dyn FnMut(&Path) -> Result<(), String>;

/// Replace the staged files, in plan order.
///
/// `stop_at` makes it stop deliberately, which is what turns the crash matrix into a command.
pub fn apply(
    app_folder: &Path,
    plan: &Plan,
    repair_check: RepairCheck<'_>,
    stop_at: Option<Boundary>,
) -> Result<Applied, ApplyError> {
    let dir = staging_dir(app_folder);
    if !dir.join(READY).exists() {
        return Err(ApplyError::NotReady);
    }

    let mut out = Applied {
        replaced: Vec::new(),
        skipped: Vec::new(),
        stopped_at: None,
        cleaned: false,
    };

    if stop_at == Some(Boundary::BeforeAnything) {
        out.stopped_at = stop_at;
        return Ok(out);
    }

    let mut ordinary = 0usize;
    for step in &plan.steps {
        let staged = dir.join(&step.name);
        let live = app_folder.join(&step.name);

        if step.name == REPAIR {
            // Set the old one aside first. This is the only rollback in the design and it is one
            // file: a `rename` cannot be undone once the old bytes are gone.
            //
            // **Copied, not moved.** Moving it was the first version, and the crash matrix caught
            // it immediately: between the move and the replacement there is an instant with no
            // `vigil-repair.exe` in the folder at all, which is precisely the guarantee this
            // ordering exists to provide. A copy costs 400 KB and one extra write, and it means the
            // safety net is present at every boundary rather than at all but one of them.
            let aside = dir.join(PREVIOUS_REPAIR);
            if live.exists() {
                std::fs::copy(&live, &aside).map_err(|e| ApplyError::Io(e.to_string()))?;
            }
            if stop_at == Some(Boundary::AfterSettingRepairAside) {
                out.stopped_at = stop_at;
                return Ok(out);
            }
            swap(&staged, &live).map_err(|e| ApplyError::RequiredSwapFailed {
                name: step.name.clone(),
                detail: e,
            })?;
            out.replaced.push(step.name.clone());
            if stop_at == Some(Boundary::AfterRepairReplaced) {
                out.stopped_at = stop_at;
                return Ok(out);
            }

            // Prove it runs before anything else moves.
            if let Err(detail) = repair_check(&live) {
                let restored = if aside.exists() {
                    std::fs::rename(&aside, &live).is_ok()
                } else {
                    false
                };
                return Err(ApplyError::RepairBroken { detail, restored });
            }
            let _ = std::fs::remove_file(&aside);
            if stop_at == Some(Boundary::AfterRepairVerified) {
                out.stopped_at = stop_at;
                return Ok(out);
            }
            continue;
        }

        match swap(&staged, &live) {
            Ok(()) => out.replaced.push(step.name.clone()),
            Err(detail) => {
                if step.required {
                    return Err(ApplyError::RequiredSwapFailed {
                        name: step.name.clone(),
                        detail,
                    });
                }
                // A file somebody has open. Skipped and named, and the next run will get it.
                out.skipped.push(step.name.clone());
            }
        }

        if step.name == APP {
            if stop_at == Some(Boundary::AfterApp) {
                out.stopped_at = stop_at;
                return Ok(out);
            }
        } else {
            if stop_at == Some(Boundary::AfterFile(ordinary)) {
                out.stopped_at = stop_at;
                return Ok(out);
            }
            ordinary += 1;
        }
    }

    // The staging folder has done its job. Left behind on any failure, so a resume can use it.
    let _ = crate::stage::discard(app_folder);
    out.cleaned = true;
    if stop_at == Some(Boundary::AfterCleanup) {
        out.stopped_at = stop_at;
    }
    Ok(out)
}

/// One replacement. A few tries, because a scanner or an indexer can hold a freshly written file
/// for a moment — measured at zero retries needed across twenty swaps with Defender on, so this is
/// insurance rather than an expectation.
fn swap(staged: &Path, live: &Path) -> Result<(), String> {
    let mut last = String::new();
    for attempt in 0..5 {
        match std::fs::rename(staged, live) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last = format!("{:?}", e.kind());
                if attempt < 4 {
                    std::thread::sleep(std::time::Duration::from_millis(120));
                }
            }
        }
    }
    Err(last)
}

/// Is the folder now exactly what the manifest describes?
///
/// The verification a resume relies on and the one the crash matrix asserts: not "did the steps
/// return Ok" but "do the bytes on disk hash to what was signed".
pub fn folder_matches(app_folder: &Path, m: &Manifest) -> bool {
    m.files
        .iter()
        .all(|f| hash_file(&app_folder.join(&f.name)).is_some_and(|d| sha256::eq(&d, &f.digest)))
}

/// Which required files do **not** yet match. Named so a report can say what is left rather than
/// only that something is.
pub fn outstanding(app_folder: &Path, m: &Manifest) -> Vec<String> {
    m.files
        .iter()
        .filter(|f| {
            f.required
                && !hash_file(&app_folder.join(&f.name)).is_some_and(|d| sha256::eq(&d, &f.digest))
        })
        .map(|f| f.name.clone())
        .collect()
}

/// The runner: a copy of this executable inside the staging folder, so the one in the application
/// folder is idle and can be replaced like any other file.
pub fn runner_path(app_folder: &Path) -> PathBuf {
    staging_dir(app_folder).join("runner.exe")
}

/// Put a copy of `me` in the staging folder and return where it went.
pub fn place_runner(app_folder: &Path, me: &Path) -> Result<PathBuf, ApplyError> {
    let dst = runner_path(app_folder);
    std::fs::create_dir_all(staging_dir(app_folder)).map_err(|e| ApplyError::Io(e.to_string()))?;
    std::fs::copy(me, &dst).map_err(|e| ApplyError::Io(e.to_string()))?;
    Ok(dst)
}

/// Delete a runner left behind by a previous update. It cannot delete itself while running, so this
/// is the next run's job — measured: refused while alive, fine once it has exited.
pub fn sweep_old_runner(app_folder: &Path) {
    let _ = std::fs::remove_file(runner_path(app_folder));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest;
    use crate::plan::{self, SwapStep};
    use crate::stage;

    fn new_body(name: &str) -> Vec<u8> {
        format!("NEW {name} bytes").into_bytes()
    }
    fn old_body(name: &str) -> Vec<u8> {
        format!("OLD {name}").into_bytes()
    }

    const NAMES: &[(&str, bool)] = &[
        ("vigil-repair.exe", true),
        ("vigil.exe", true),
        ("wirelog.exe", false),
        ("vigil-app.exe", true),
    ];

    fn manifest_of() -> Manifest {
        let mut s = String::from(
            "schema=1\nserial=7\nversion=0.7.0\nexpires=2026-11-12T00:00:00Z\n\
             min_version=0.6.3\ncritical=0\n\
             base=https://github.com/resul-e/vigil/releases/download/v0.7.0/\n\
             notes_tr=t\nnotes_en=e\n",
        );
        for (i, (name, required)) in NAMES.iter().enumerate() {
            let b = new_body(name);
            s.push_str(&format!(
                "file={i} {name} {} {} {}\n",
                b.len(),
                u8::from(*required),
                sha256::hex(&sha256::hash(&b))
            ));
        }
        manifest::parse(&s).expect("test manifest")
    }

    struct Sandbox(PathBuf);

    impl Sandbox {
        /// An application folder with the old binaries, and a fully staged, ready update.
        fn ready(tag: &str) -> Sandbox {
            let p = std::env::temp_dir().join(format!(
                "vigil-apply-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(p.join(stage::STAGING)).expect("dirs");
            for (name, _) in NAMES {
                std::fs::write(p.join(name), old_body(name)).expect("old");
                std::fs::write(p.join(stage::STAGING).join(name), new_body(name)).expect("staged");
            }
            std::fs::write(p.join(stage::STAGING).join(READY), b"ready").expect("marker");
            Sandbox(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
        fn plan(&self) -> Plan {
            let m = manifest_of();
            let on_disk = stage::hash_folder(self.path(), &m);
            let staged = stage::hash_folder(&staging_dir(self.path()), &m);
            plan::plan(&m, &on_disk, &staged).expect("plans")
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn ok_check() -> impl FnMut(&Path) -> Result<(), String> {
        |_| Ok(())
    }

    #[test]
    fn a_complete_apply_replaces_everything_and_cleans_up() {
        let sb = Sandbox::ready("full");
        let m = manifest_of();
        let mut check = ok_check();
        let out = apply(sb.path(), &sb.plan(), &mut check, None).expect("applies");

        assert_eq!(out.replaced.len(), NAMES.len());
        assert!(out.skipped.is_empty());
        assert!(out.finished());
        assert!(out.cleaned);
        assert!(folder_matches(sb.path(), &m), "every hash must match");
        assert!(outstanding(sb.path(), &m).is_empty());
        assert!(!staging_dir(sb.path()).exists(), "staging should be gone");
    }

    #[test]
    fn applying_without_a_ready_marker_is_refused_and_changes_nothing() {
        let sb = Sandbox::ready("notready");
        std::fs::remove_file(staging_dir(sb.path()).join(READY)).expect("remove marker");
        let plan = sb.plan();
        let mut check = ok_check();
        assert_eq!(
            apply(sb.path(), &plan, &mut check, None),
            Err(ApplyError::NotReady)
        );
        for (name, _) in NAMES {
            assert_eq!(
                std::fs::read(sb.path().join(name)).expect("read"),
                old_body(name),
                "{name} must be untouched"
            );
        }
    }

    /// The one rollback. A safety net that will not run is worse than an old one, so the old one
    /// goes back and nothing else moves.
    #[test]
    fn a_new_repair_tool_that_will_not_run_is_rolled_back() {
        let sb = Sandbox::ready("badrepair");
        let m = manifest_of();
        let mut check = |_: &Path| Err("exit code 3221225781".to_string());
        let got = apply(sb.path(), &sb.plan(), &mut check, None);
        assert_eq!(
            got,
            Err(ApplyError::RepairBroken {
                detail: "exit code 3221225781".into(),
                restored: true
            })
        );
        // The old safety net is back, byte for byte.
        assert_eq!(
            std::fs::read(sb.path().join(REPAIR)).expect("read"),
            old_body(REPAIR)
        );
        // And nothing after it was touched.
        for (name, _) in NAMES.iter().filter(|(n, _)| *n != REPAIR) {
            assert_eq!(
                std::fs::read(sb.path().join(name)).expect("read"),
                old_body(name),
                "{name} must not have moved"
            );
        }
        assert!(!folder_matches(sb.path(), &m));
        // The message says plainly that the old one was put back.
        assert!(got.unwrap_err().to_string().contains("put back"));
    }

    /// An optional file that will not move is skipped and named; a required one stops the run.
    #[test]
    fn a_file_that_cannot_be_replaced_is_optional_or_fatal_by_manifest() {
        // Remove the staged copy so the rename fails the way a locked file would.
        for (target, required) in NAMES.iter().filter(|(n, _)| *n != REPAIR) {
            let sb = Sandbox::ready("locked");
            std::fs::remove_file(staging_dir(sb.path()).join(target)).expect("remove staged");
            // Plan from before the removal, so the step is still in it — this is exactly the shape
            // of a file that disappeared between planning and applying.
            let plan = Plan {
                steps: NAMES
                    .iter()
                    .map(|(n, r)| SwapStep {
                        order: 0,
                        name: n.to_string(),
                        required: *r,
                        digest: sha256::hash(&new_body(n)),
                    })
                    .collect(),
                skipped: Vec::new(),
            };
            let mut check = ok_check();
            let got = apply(sb.path(), &plan, &mut check, None);
            if *required {
                assert!(
                    matches!(got, Err(ApplyError::RequiredSwapFailed { ref name, .. }) if name == target),
                    "{target} is required, got {got:?}"
                );
            } else {
                let out = got.expect("an optional file may fail");
                assert_eq!(out.skipped, vec![target.to_string()]);
                assert!(out.replaced.contains(&"vigil-app.exe".to_string()));
            }
        }
    }

    /// **The crash matrix, on Linux.** Stop at every boundary the plan has, and at each one assert
    /// the two things that matter: the safety net is present and readable, and a resume finishes
    /// the job to a folder whose every hash matches the signed manifest.
    ///
    /// The Windows run of this is the gate for the feature — it also asserts that the internet
    /// works and that `vigil-repair.exe --version` really exits zero. This is the same walk with
    /// the platform parts stubbed, and it is what makes the Windows run a confirmation rather than
    /// an exploration.
    #[test]
    fn stopping_at_every_boundary_leaves_a_resumable_folder() {
        let m = manifest_of();
        let boundaries = {
            let sb = Sandbox::ready("enumerate");
            Boundary::all_for(&sb.plan())
        };
        assert!(
            boundaries.len() >= 7,
            "expected a boundary per stage, got {boundaries:?}"
        );

        for b in boundaries {
            let sb = Sandbox::ready("matrix");
            let mut check = ok_check();
            let first = apply(sb.path(), &sb.plan(), &mut check, Some(b))
                .unwrap_or_else(|e| panic!("{b:?}: {e}"));
            assert_eq!(first.stopped_at, Some(b));

            // The safety net must exist and be one of the two known-good versions at every single
            // boundary. This is the guarantee the ordering exists for.
            let repair = sb.path().join(REPAIR);
            let bytes = std::fs::read(&repair)
                .unwrap_or_else(|e| panic!("{b:?}: the safety net is missing: {e}"));
            assert!(
                bytes == old_body(REPAIR) || bytes == new_body(REPAIR),
                "{b:?}: the safety net is neither version"
            );

            // And a resume finishes it, unless the boundary was after cleanup — in which case it
            // is already finished.
            if b == Boundary::AfterCleanup {
                assert!(folder_matches(sb.path(), &m), "{b:?}");
                continue;
            }
            let mut check = ok_check();
            let second = apply(sb.path(), &sb.plan(), &mut check, None)
                .unwrap_or_else(|e| panic!("{b:?}: resume failed: {e}"));
            assert!(second.finished(), "{b:?}");
            assert!(
                folder_matches(sb.path(), &m),
                "{b:?}: resume did not reach the signed hashes; outstanding {:?}",
                outstanding(sb.path(), &m)
            );
        }
    }

    /// A resume must never redo work, and never lose the marker it depends on.
    #[test]
    fn a_resume_only_does_what_is_left() {
        let sb = Sandbox::ready("resume");
        let mut check = ok_check();
        let first = apply(
            sb.path(),
            &sb.plan(),
            &mut check,
            Some(Boundary::AfterRepairVerified),
        )
        .expect("stops");
        assert_eq!(first.replaced, vec![REPAIR.to_string()]);

        let mut check = ok_check();
        let second = apply(sb.path(), &sb.plan(), &mut check, None).expect("resumes");
        assert!(
            !second.replaced.contains(&REPAIR.to_string()),
            "the safety net must not be replaced twice"
        );
        assert_eq!(second.replaced.len(), NAMES.len() - 1);
    }

    #[test]
    fn the_boundary_list_matches_the_shape_of_the_plan() {
        let sb = Sandbox::ready("shape");
        let b = Boundary::all_for(&sb.plan());
        assert_eq!(b.first(), Some(&Boundary::BeforeAnything));
        assert_eq!(b.last(), Some(&Boundary::AfterCleanup));
        assert!(b.contains(&Boundary::AfterSettingRepairAside));
        assert!(b.contains(&Boundary::AfterRepairVerified));
        assert!(b.contains(&Boundary::AfterApp));
        // One ordinary file between the safety net and the application: vigil.exe and wirelog.exe.
        assert!(b.contains(&Boundary::AfterFile(0)));
        assert!(b.contains(&Boundary::AfterFile(1)));

        // A plan without the safety net has no repair boundaries to stop at.
        let bare = Plan {
            steps: vec![SwapStep {
                order: 0,
                name: "vigil-scan.exe".into(),
                required: true,
                digest: sha256::hash(b"x"),
            }],
            skipped: Vec::new(),
        };
        let b = Boundary::all_for(&bare);
        assert!(!b.contains(&Boundary::AfterRepairReplaced));
        assert!(!b.contains(&Boundary::AfterApp));
    }

    #[test]
    fn the_runner_is_placed_in_staging_and_an_old_one_is_swept() {
        let sb = Sandbox::ready("runner");
        let me = sb.path().join("vigil.exe");
        let placed = place_runner(sb.path(), &me).expect("places");
        assert_eq!(placed, runner_path(sb.path()));
        assert!(placed.exists());
        assert_eq!(
            std::fs::read(&placed).expect("read"),
            std::fs::read(&me).expect("read")
        );
        sweep_old_runner(sb.path());
        assert!(!placed.exists());
        // Sweeping nothing is fine — the usual case, since most runs follow no update.
        sweep_old_runner(sb.path());
    }

    #[test]
    fn outstanding_names_what_is_left_rather_than_only_that_something_is() {
        let sb = Sandbox::ready("outstanding");
        let m = manifest_of();
        let left = outstanding(sb.path(), &m);
        assert!(left.contains(&REPAIR.to_string()));
        assert!(left.contains(&"vigil-app.exe".to_string()));
        // `wirelog.exe` is not required, so it is not outstanding even though it is old.
        assert!(!left.contains(&"wirelog.exe".to_string()));
        let mut check = ok_check();
        apply(sb.path(), &sb.plan(), &mut check, None).expect("applies");
        assert!(outstanding(sb.path(), &m).is_empty());
    }
}
