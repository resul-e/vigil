//! What to replace, in what order, given what is already on disk.
//!
//! Pure. Three inputs — the manifest, the hashes of the files in the application folder, and the
//! hashes of the files staged in `.vigil-update/` — and one output: the list of replacements left
//! to do. No I/O, no clock, no filesystem.
//!
//! ## Why hashes and not a journal
//!
//! A half-finished update is **fully described** by which files hash to what. Re-planning after any
//! interruption therefore yields exactly the remaining work, and it does so by *looking* rather
//! than by trusting a record it may have failed to write. A rollback log would be a second source
//! of truth that can itself be stale, half-written or simply wrong — more risk than it removes, on
//! the one path where being wrong is expensive. That is not a preference: the failure this project
//! has actually suffered was a cleanup that only ran on the happy path.
//!
//! The consequence worth naming: this planner is **idempotent**. Apply some of it, plan again, and
//! you get the rest. A test walks every one of the 2ⁿ partial-completion states and asserts it.
//!
//! ## Why the order is in the manifest and not here
//!
//! `vigil-repair.exe` is order 0 and `vigil-app.exe` is last, and that sequence is a promise about
//! what a crash leaves behind: the safety net is in place before anything else moves, and the
//! application the user double-clicks is the last thing to change. The manifest states it, this
//! module preserves it, and both are asserted — a planner that sorted by name would quietly break
//! the guarantee.

use vigil_core::sha256::{self, Digest};

use crate::manifest::{FileEntry, Manifest};

/// The hashes of a set of files, by name. Missing means the file is not there.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Digests(Vec<(String, Digest)>);

impl Digests {
    pub fn new() -> Digests {
        Digests(Vec::new())
    }

    pub fn with(mut self, name: &str, digest: Digest) -> Digests {
        self.0.retain(|(n, _)| n != name);
        self.0.push((name.to_string(), digest));
        self
    }

    pub fn without(mut self, name: &str) -> Digests {
        self.0.retain(|(n, _)| n != name);
        self
    }

    pub fn get(&self, name: &str) -> Option<&Digest> {
        self.0.iter().find(|(n, _)| n == name).map(|(_, d)| d)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromIterator<(String, Digest)> for Digests {
    fn from_iter<I: IntoIterator<Item = (String, Digest)>>(iter: I) -> Self {
        Digests(iter.into_iter().collect())
    }
}

/// One replacement to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapStep {
    pub order: u32,
    pub name: String,
    /// Whether failing this one fails the whole update.
    pub required: bool,
    pub digest: Digest,
}

/// Something the plan is deliberately not doing, and why. Reported rather than dropped: a file that
/// silently vanished from an update is the kind of thing that gets noticed three releases later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skipped {
    /// Already the right bytes. The delta strategy, and the reason re-running a check is free.
    AlreadyCurrent(String),
    /// Not staged, and not required. `wirelog.exe` is a developer instrument; an update that could
    /// not fetch it is still an update.
    OptionalAndMissing(String),
}

/// Why no plan could be made. Every one of these means "change nothing".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A required file is not in the staging folder. Not a skip: the manifest says the update is
    /// incomplete without it.
    RequiredNotStaged(String),
    /// A staged file's bytes do not hash to what the signed manifest says. **Never a skip.** The
    /// signature covers the manifest, the manifest covers the hash, and a disagreement here means
    /// the bytes on disk are not the bytes that were signed.
    StagedHashMismatch { name: String },
    /// Nothing in the manifest is required. A manifest with no required file cannot promise that
    /// the safety net survives, so it is refused rather than half-applied.
    NothingRequired,
    /// The safety net is not first, or the application is not last. The manifest is signed, so this
    /// is a release-process mistake rather than an attack — and it is refused either way, because
    /// the order *is* the crash-safety argument.
    OrderBroken { expected: &'static str, at: usize },
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use Refusal::*;
        match self {
            RequiredNotStaged(n) => write!(f, "{n} is required and was not staged"),
            StagedHashMismatch { name } => {
                write!(f, "the staged {name} is not the file the manifest names")
            }
            NothingRequired => f.write_str("the manifest marks nothing as required"),
            OrderBroken { expected, at } => {
                write!(f, "{expected} must not be at position {at}")
            }
        }
    }
}

/// The name of the safety net, which must be replaced and verified before anything else.
pub const REPAIR: &str = "vigil-repair.exe";
/// The name of the application, which must be replaced last.
pub const APP: &str = "vigil-app.exe";

/// What is left to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub steps: Vec<SwapStep>,
    pub skipped: Vec<Skipped>,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Is the folder already exactly what the manifest describes?
    pub fn nothing_to_do(&self) -> bool {
        self.steps.is_empty()
    }
}

/// Work out the remaining replacements.
///
/// `on_disk` is the application folder; `staged` is `.vigil-update/`. Both are hashes, because a
/// hash is the only thing that answers "is this the right file" without trusting a name, a size or
/// a timestamp.
pub fn plan(m: &Manifest, on_disk: &Digests, staged: &Digests) -> Result<Plan, Refusal> {
    check_order(m)?;
    if !m.files.iter().any(|f| f.required) {
        return Err(Refusal::NothingRequired);
    }

    let mut steps = Vec::new();
    let mut skipped = Vec::new();

    // Manifest order, preserved. The sequence is the crash-safety argument.
    for f in &m.files {
        if on_disk
            .get(&f.name)
            .is_some_and(|d| sha256::eq(d, &f.digest))
        {
            skipped.push(Skipped::AlreadyCurrent(f.name.clone()));
            continue;
        }
        match staged.get(&f.name) {
            Some(d) if sha256::eq(d, &f.digest) => steps.push(step(f)),
            // Staged, and wrong. This is the one case that must never degrade into a skip.
            Some(_) => {
                return Err(Refusal::StagedHashMismatch {
                    name: f.name.clone(),
                })
            }
            None if f.required => return Err(Refusal::RequiredNotStaged(f.name.clone())),
            None => skipped.push(Skipped::OptionalAndMissing(f.name.clone())),
        }
    }

    Ok(Plan { steps, skipped })
}

fn step(f: &FileEntry) -> SwapStep {
    SwapStep {
        order: f.order,
        name: f.name.clone(),
        required: f.required,
        digest: f.digest,
    }
}

/// The safety net first, the application last — when they are present at all.
///
/// A manifest that updates only `vigil-scan.exe` is perfectly legitimate and mentions neither, so
/// this checks position rather than presence.
fn check_order(m: &Manifest) -> Result<(), Refusal> {
    if let Some(at) = m.files.iter().position(|f| f.name == REPAIR) {
        if at != 0 {
            return Err(Refusal::OrderBroken {
                expected: REPAIR,
                at,
            });
        }
    }
    if let Some(at) = m.files.iter().position(|f| f.name == APP) {
        if at + 1 != m.files.len() {
            return Err(Refusal::OrderBroken { expected: APP, at });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest;

    /// A manifest whose digests are the hashes of predictable little strings, so a test can build
    /// the "file on disk" side by hashing the same strings.
    fn body_for(name: &str) -> Vec<u8> {
        format!("the new {name}").into_bytes()
    }
    fn old_body_for(name: &str) -> Vec<u8> {
        format!("the old {name}").into_bytes()
    }
    fn digest_of(name: &str) -> Digest {
        sha256::hash(&body_for(name))
    }
    fn old_digest_of(name: &str) -> Digest {
        sha256::hash(&old_body_for(name))
    }

    const NAMES: &[(&str, bool)] = &[
        ("vigil-repair.exe", true),
        ("vigil.exe", true),
        ("wirelog.exe", false),
        ("vigil-scan.exe", false),
        ("vigil-update.exe", true),
        ("vigil-app.exe", true),
    ];

    fn manifest_text() -> String {
        let mut s = String::from(
            "schema=1\nserial=7\nversion=0.7.0\nexpires=2026-11-12T00:00:00Z\n\
             min_version=0.6.3\ncritical=0\n\
             base=https://github.com/resul-e/vigil/releases/download/v0.7.0/\n\
             notes_tr=t\nnotes_en=e\n",
        );
        for (i, (name, required)) in NAMES.iter().enumerate() {
            s.push_str(&format!(
                "file={i} {name} 1000 {} {}\n",
                u8::from(*required),
                sha256::hex(&digest_of(name))
            ));
        }
        s
    }

    fn good() -> Manifest {
        manifest::parse(&manifest_text()).expect("the test manifest must parse")
    }

    /// A folder where every file is the old version.
    fn all_old() -> Digests {
        NAMES
            .iter()
            .map(|(n, _)| (n.to_string(), old_digest_of(n)))
            .collect()
    }

    /// A staging folder with every new file verified and present.
    fn all_staged() -> Digests {
        NAMES
            .iter()
            .map(|(n, _)| (n.to_string(), digest_of(n)))
            .collect()
    }

    #[test]
    fn a_fresh_update_plans_every_file_in_manifest_order() {
        let p = plan(&good(), &all_old(), &all_staged()).expect("plans");
        let names: Vec<&str> = p.steps.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "vigil-repair.exe",
                "vigil.exe",
                "wirelog.exe",
                "vigil-scan.exe",
                "vigil-update.exe",
                "vigil-app.exe"
            ]
        );
        assert!(p.skipped.is_empty());
    }

    /// The sequence is the crash-safety argument, so it is asserted rather than assumed.
    #[test]
    fn the_safety_net_is_first_and_the_application_is_last() {
        let p = plan(&good(), &all_old(), &all_staged()).expect("plans");
        assert_eq!(p.steps.first().expect("some").name, REPAIR);
        assert_eq!(p.steps.last().expect("some").name, APP);
    }

    /// A signed manifest with the order wrong is a release-process mistake, and it is refused
    /// rather than applied in the wrong sequence — the order is the whole guarantee.
    #[test]
    fn a_manifest_with_the_order_wrong_is_refused() {
        // Swap the repair tool out of position 0.
        let text = manifest_text()
            .replace("file=0 vigil-repair.exe", "file=9 vigil-repair.exe")
            .replace("file=1 vigil.exe", "file=0 vigil.exe")
            .replace("file=9 vigil-repair.exe", "file=1 vigil-repair.exe");
        let m = manifest::parse(&text).expect("still a valid manifest by shape");
        assert_eq!(
            plan(&m, &all_old(), &all_staged()),
            Err(Refusal::OrderBroken {
                expected: REPAIR,
                at: 1
            })
        );
    }

    /// A manifest that touches neither the safety net nor the application is fine. The check is
    /// about position, not presence.
    #[test]
    fn a_manifest_updating_only_one_tool_is_allowed() {
        let text = format!(
            "schema=1\nserial=7\nversion=0.7.0\nexpires=2026-11-12T00:00:00Z\n\
             min_version=0.6.3\ncritical=0\n\
             base=https://github.com/resul-e/vigil/releases/download/v0.7.0/\n\
             notes_tr=t\nnotes_en=e\nfile=0 vigil-scan.exe 1000 1 {}\n",
            sha256::hex(&digest_of("vigil-scan.exe"))
        );
        let m = manifest::parse(&text).expect("parses");
        let p = plan(&m, &all_old(), &all_staged()).expect("plans");
        assert_eq!(p.steps.len(), 1);
        assert_eq!(p.steps[0].name, "vigil-scan.exe");
    }

    /// The delta strategy: a file that is already the right bytes is not in the plan at all. This
    /// is what makes re-running a check free, and it needs no patch format.
    #[test]
    fn a_file_that_already_matches_is_skipped_not_replaced() {
        let disk = all_old().with("vigil.exe", digest_of("vigil.exe"));
        let p = plan(&good(), &disk, &all_staged()).expect("plans");
        assert!(!p.steps.iter().any(|s| s.name == "vigil.exe"));
        assert!(p
            .skipped
            .contains(&Skipped::AlreadyCurrent("vigil.exe".into())));
        assert_eq!(p.steps.len(), NAMES.len() - 1);
    }

    #[test]
    fn a_folder_that_is_already_correct_has_nothing_to_do() {
        let p = plan(&good(), &all_staged(), &all_staged()).expect("plans");
        assert!(p.nothing_to_do());
        assert_eq!(p.skipped.len(), NAMES.len());
    }

    /// The case that must never become a skip. The signature covers the manifest and the manifest
    /// covers the hash; a staged file that disagrees is not the file that was signed.
    #[test]
    fn a_staged_file_whose_hash_disagrees_refuses_the_whole_update() {
        for (name, _) in NAMES {
            let staged = all_staged().with(name, sha256::hash(b"something else entirely"));
            assert_eq!(
                plan(&good(), &all_old(), &staged),
                Err(Refusal::StagedHashMismatch {
                    name: name.to_string()
                }),
                "a wrong {name} must refuse everything"
            );
        }
    }

    /// A required file that never arrived stops the update; an optional one does not.
    #[test]
    fn required_and_optional_missing_files_are_treated_differently() {
        for (name, required) in NAMES {
            let staged = all_staged().without(name);
            let got = plan(&good(), &all_old(), &staged);
            if *required {
                assert_eq!(
                    got,
                    Err(Refusal::RequiredNotStaged(name.to_string())),
                    "{name} is required"
                );
            } else {
                let p = got.expect("an optional file may be missing");
                assert!(!p.steps.iter().any(|s| &s.name == name));
                assert!(p
                    .skipped
                    .contains(&Skipped::OptionalAndMissing(name.to_string())));
            }
        }
    }

    /// A manifest that requires nothing cannot promise the safety net survives.
    #[test]
    fn a_manifest_that_requires_nothing_is_refused() {
        let text = manifest_text().replace(" 1000 1 ", " 1000 0 ");
        let m = manifest::parse(&text).expect("parses");
        assert_eq!(
            plan(&m, &all_old(), &all_staged()),
            Err(Refusal::NothingRequired)
        );
    }

    /// **The property the whole no-journal design rests on.** Take every possible partially applied
    /// folder — all 2⁶ of them — and check that the plan is exactly the work that is left, that it
    /// is still in manifest order, and that applying it and re-planning gives nothing to do.
    #[test]
    fn planning_is_idempotent_across_every_partial_completion_state() {
        let m = good();
        let n = NAMES.len();
        assert_eq!(n, 6, "the 2^6 in the name should mean something");

        for mask in 0..(1u32 << n) {
            // Build the folder: bit set means that file has already been replaced.
            let mut disk = Digests::new();
            let mut done = Vec::new();
            for (i, (name, _)) in NAMES.iter().enumerate() {
                if mask & (1 << i) != 0 {
                    disk = disk.with(name, digest_of(name));
                    done.push(*name);
                } else {
                    disk = disk.with(name, old_digest_of(name));
                }
            }

            let p =
                plan(&m, &disk, &all_staged()).unwrap_or_else(|e| panic!("mask {mask:#08b}: {e}"));

            // Exactly the complement, in manifest order.
            let want: Vec<&str> = NAMES
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) == 0)
                .map(|(_, (n, _))| *n)
                .collect();
            let got: Vec<&str> = p.steps.iter().map(|s| s.name.as_str()).collect();
            assert_eq!(got, want, "mask {mask:#08b}");

            // Applying it leaves nothing to do, and one more plan is empty. That is idempotence:
            // the second run of an interrupted update finds no work rather than redoing it.
            let mut after = disk.clone();
            for s in &p.steps {
                after = after.with(&s.name, s.digest);
            }
            let again = plan(&m, &after, &all_staged()).expect("re-plans");
            assert!(again.nothing_to_do(), "mask {mask:#08b} did not converge");
            assert_eq!(again.skipped.len(), n);
        }
    }

    /// And the same property when the update is interrupted *mid-plan* rather than between plans:
    /// applying any prefix of the steps must always shrink the next plan by exactly that much.
    #[test]
    fn applying_any_prefix_shrinks_the_next_plan_by_exactly_that_much() {
        let m = good();
        let staged = all_staged();
        for cut in 0..=NAMES.len() {
            let mut disk = all_old();
            let first = plan(&m, &disk, &staged).expect("plans");
            for s in first.steps.iter().take(cut) {
                disk = disk.with(&s.name, s.digest);
            }
            let next = plan(&m, &disk, &staged).expect("re-plans");
            assert_eq!(
                next.steps.len(),
                NAMES.len() - cut,
                "stopping after {cut} steps"
            );
            // Never re-does what is done.
            for s in first.steps.iter().take(cut) {
                assert!(
                    !next.steps.iter().any(|t| t.name == s.name),
                    "{} was planned twice",
                    s.name
                );
            }
        }
    }

    /// A file the folder does not have at all is a replacement, not a refusal — a user who deleted
    /// `wirelog.exe` should get it back rather than being told the update is broken.
    #[test]
    fn a_file_missing_from_the_folder_is_simply_replaced() {
        let disk = all_old().without("wirelog.exe").without("vigil.exe");
        let p = plan(&good(), &disk, &all_staged()).expect("plans");
        assert!(p.steps.iter().any(|s| s.name == "wirelog.exe"));
        assert!(p.steps.iter().any(|s| s.name == "vigil.exe"));
    }
}
