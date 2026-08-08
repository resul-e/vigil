//! Downloading into a staging folder, and never anywhere else.
//!
//! This is the whole of phase A's filesystem work, and its one promise is that **the application
//! folder is byte-identical before and after, whatever happens.** Every write goes into
//! `.vigil-update/`; nothing in here can replace a binary, because nothing in here knows how.
//!
//! ## Why the download is a parameter
//!
//! `stage` takes a fetcher rather than calling the network itself. That is not indirection for its
//! own sake — it is what makes the interesting cases testable at all: a body that is one byte
//! short, a body whose hash disagrees with the signed manifest, a host that fails on the third file
//! of six, a re-run that should download nothing. Those are the failures that matter on a
//! silently-dropping line, and none of them can be provoked reliably against a real server.
//!
//! ## `.part`, and why the rename is the whole trick
//!
//! A download lands on `<name>.part`. It is hashed, and only if the hash matches the signed
//! manifest is it renamed to `<name>`. So a staged file existing *means* it verified — there is no
//! second place that has to remember. A truncated body, a censored connection, an expired signed
//! URL and a power cut are then all the same event: a `.part` the next run deletes.
//!
//! `ready.txt` is written last, after every file is present and verified. Its presence means the
//! full set is staged, which is what lets the interface offer to resume rather than to restart.

use std::path::{Path, PathBuf};

use vigil_core::sha256::{self, Digest};

use crate::manifest::Manifest;
use crate::plan::Digests;

/// The staging directory, inside the application folder and dotted so Explorer keeps it out of the
/// way. Inside the folder rather than in `%TEMP%` deliberately: the swap must be a same-volume
/// rename, and `%TEMP%` is not guaranteed to be on the same volume.
pub const STAGING: &str = ".vigil-update";
/// Written last. Its presence means every file staged and verified.
pub const READY: &str = "ready.txt";
/// The manifest and its signatures, kept beside the staged files.
///
/// So that phase B can **verify again, offline**, rather than trusting that the staging folder was
/// not touched between the download and the swap. Phase A runs while the user is protected and phase
/// B can be minutes or a reboot later; anything with write access to the folder in between could
/// otherwise substitute a file, and the hash it would be checked against would be the one it
/// brought with it.
pub const MANIFEST: &str = "manifest.txt";
pub const SIG_A: &str = "manifest.txt.minisig";
pub const SIG_B: &str = "manifest.txt.minisig2";
/// How many times one file is re-fetched before the run gives up on it.
pub const ATTEMPTS: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageError {
    /// The application folder cannot be written to: a read-only directory, a zip opened in
    /// Explorer's temporary view, a network share. Reported before anything is attempted, because
    /// the honest answer is "download it yourself" and it should arrive early.
    FolderNotWritable(String),
    /// A file could not be fetched after [`ATTEMPTS`] tries.
    Unfetchable {
        name: String,
        last: String,
    },
    /// The bytes arrived and are not the bytes the signed manifest names. Never retried into
    /// success and never accepted: it means either the wire lied or the release did.
    HashMismatch {
        name: String,
    },
    /// A body of the wrong length. Separate from a hash mismatch because it is the ordinary shape
    /// of censorship rather than of tampering, and the two should read differently in a log.
    WrongLength {
        name: String,
        want: u64,
        got: u64,
    },
    Io(String),
}

impl core::fmt::Display for StageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use StageError::*;
        match self {
            FolderNotWritable(w) => write!(f, "cannot write to the program folder: {w}"),
            Unfetchable { name, last } => write!(f, "could not download {name}: {last}"),
            HashMismatch { name } => write!(f, "{name} arrived with the wrong contents"),
            WrongLength { name, want, got } => {
                write!(f, "{name} arrived as {got} bytes, not {want}")
            }
            Io(e) => write!(f, "io: {e}"),
        }
    }
}

/// What one staging run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Staged {
    /// Downloaded and verified this run.
    pub fetched: Vec<String>,
    /// Already staged and already correct, so not fetched again. The reason re-running is free.
    pub already: Vec<String>,
    /// Already the right bytes *in the application folder*, so there is nothing to stage.
    pub current: Vec<String>,
    /// Optional files that could not be fetched. Recorded, not fatal.
    pub gave_up: Vec<String>,
}

impl Staged {
    /// Is the whole set staged or already current?
    pub fn complete(&self, m: &Manifest) -> bool {
        m.files.iter().all(|f| {
            !f.required
                || self.fetched.contains(&f.name)
                || self.already.contains(&f.name)
                || self.current.contains(&f.name)
        })
    }
}

pub fn staging_dir(app_folder: &Path) -> PathBuf {
    app_folder.join(STAGING)
}

pub fn ready_marker(app_folder: &Path) -> PathBuf {
    staging_dir(app_folder).join(READY)
}

/// Can we write into the application folder at all?
///
/// Creates the staging directory, writes a probe file and renames it — the same operations the swap
/// will need. Checked up front because "this folder is read-only" is an answer a user can act on,
/// and discovering it three files into a download is not.
pub fn check_writable(app_folder: &Path) -> Result<(), StageError> {
    let dir = staging_dir(app_folder);
    std::fs::create_dir_all(&dir).map_err(|e| StageError::FolderNotWritable(e.to_string()))?;
    let probe = dir.join("probe.tmp");
    let moved = dir.join("probe.moved");
    std::fs::write(&probe, b"vigil").map_err(|e| StageError::FolderNotWritable(e.to_string()))?;
    // The rename is the operation the swap depends on, so it is the operation that gets tested.
    let renamed = std::fs::rename(&probe, &moved);
    let _ = std::fs::remove_file(&probe);
    let _ = std::fs::remove_file(&moved);
    renamed.map_err(|e| StageError::FolderNotWritable(e.to_string()))?;
    Ok(())
}

/// Hash every file the manifest names, in whichever directory. Missing files are simply absent.
///
/// Streamed in 64 KiB pieces rather than read whole: the largest of these is a 2.7 MB executable
/// today, and reading one into memory to hash it is a habit worth not forming.
pub fn hash_folder(dir: &Path, m: &Manifest) -> Digests {
    let mut out = Digests::new();
    for f in &m.files {
        if let Some(d) = hash_file(&dir.join(&f.name)) {
            out = out.with(&f.name, d);
        }
    }
    out
}

pub fn hash_file(path: &Path) -> Option<Digest> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut h = sha256::Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => h.update(&buf[..n]),
            Err(_) => return None,
        }
    }
    Some(h.finish())
}

/// Download whatever is missing, verify it, and leave it staged.
///
/// `fetch` is given a URL and returns the bytes. It is called at most [`ATTEMPTS`] times per file,
/// and never at all for a file that is already correct in either directory.
pub fn stage<F>(app_folder: &Path, m: &Manifest, mut fetch: F) -> Result<Staged, StageError>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    check_writable(app_folder)?;
    let dir = staging_dir(app_folder);

    // A stale marker from a previous run must not survive a new one: it would claim a set is ready
    // that this run is still assembling.
    let _ = std::fs::remove_file(dir.join(READY));

    let on_disk = hash_folder(app_folder, m);
    let staged_now = hash_folder(&dir, m);

    let mut out = Staged {
        fetched: Vec::new(),
        already: Vec::new(),
        current: Vec::new(),
        gave_up: Vec::new(),
    };

    for f in &m.files {
        if on_disk
            .get(&f.name)
            .is_some_and(|d| sha256::eq(d, &f.digest))
        {
            out.current.push(f.name.clone());
            continue;
        }
        if staged_now
            .get(&f.name)
            .is_some_and(|d| sha256::eq(d, &f.digest))
        {
            out.already.push(f.name.clone());
            continue;
        }
        // Anything already there is not what we want. Remove it rather than leaving a wrong file
        // for a later run to trip over.
        let _ = std::fs::remove_file(dir.join(&f.name));

        let url = crate::manifest::url_for(m, f);
        let mut last = String::new();
        let mut done = false;
        for _ in 0..ATTEMPTS {
            match fetch(&url) {
                Err(e) => last = e,
                Ok(bytes) => {
                    if bytes.len() as u64 != f.size {
                        // The ordinary shape of censorship. Retried, because a short read can also
                        // be a bad moment on a slow line.
                        last = StageError::WrongLength {
                            name: f.name.clone(),
                            want: f.size,
                            got: bytes.len() as u64,
                        }
                        .to_string();
                        continue;
                    }
                    if !sha256::eq(&sha256::hash(&bytes), &f.digest) {
                        // Not retried into success. The signature covers the manifest and the
                        // manifest covers this hash, so a disagreement is not bad luck.
                        return Err(StageError::HashMismatch {
                            name: f.name.clone(),
                        });
                    }
                    write_verified(&dir, &f.name, &bytes)?;
                    out.fetched.push(f.name.clone());
                    done = true;
                    break;
                }
            }
        }
        if !done {
            if f.required {
                return Err(StageError::Unfetchable {
                    name: f.name.clone(),
                    last,
                });
            }
            out.gave_up.push(f.name.clone());
        }
    }

    if out.complete(m) {
        std::fs::write(dir.join(READY), ready_text(m))
            .map_err(|e| StageError::Io(e.to_string()))?;
    }
    Ok(out)
}

/// `<name>.part`, flushed, then renamed. A staged file existing means it verified.
fn write_verified(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), StageError> {
    use std::io::Write;
    let part = dir.join(format!("{name}.part"));
    let final_path = dir.join(name);
    {
        let mut f = std::fs::File::create(&part).map_err(|e| StageError::Io(e.to_string()))?;
        f.write_all(bytes)
            .map_err(|e| StageError::Io(e.to_string()))?;
        // Before the rename, not after. A rename that beats the data to disk is how a "verified"
        // file turns out to be zeros after a power cut.
        f.sync_all().map_err(|e| StageError::Io(e.to_string()))?;
    }
    std::fs::rename(&part, &final_path).map_err(|e| {
        let _ = std::fs::remove_file(&part);
        StageError::Io(e.to_string())
    })?;
    Ok(())
}

/// What the marker says. Human-readable on purpose: somebody will find this file and wonder.
pub fn ready_text(m: &Manifest) -> String {
    format!(
        "vigil {} staged, serial {}\nEvery file here was verified against a signed manifest.\n\
         Delete this folder to cancel the update.\n",
        m.version, m.serial
    )
}

/// Keep the manifest and its signatures beside the staged files, so phase B can verify offline.
pub fn save_inputs(
    app_folder: &Path,
    manifest_text: &str,
    sigs: &[String],
) -> Result<(), StageError> {
    let dir = staging_dir(app_folder);
    std::fs::create_dir_all(&dir).map_err(|e| StageError::Io(e.to_string()))?;
    std::fs::write(dir.join(MANIFEST), manifest_text).map_err(|e| StageError::Io(e.to_string()))?;
    for (name, sig) in [SIG_A, SIG_B].iter().zip(sigs.iter()) {
        std::fs::write(dir.join(name), sig).map_err(|e| StageError::Io(e.to_string()))?;
    }
    Ok(())
}

/// Read them back. `None` when the set is not there — which phase B treats as "nothing to apply"
/// rather than as an error, because that is the ordinary state of a folder with no update pending.
pub fn load_inputs(app_folder: &Path) -> Option<(String, Vec<String>)> {
    let dir = staging_dir(app_folder);
    let text = std::fs::read_to_string(dir.join(MANIFEST)).ok()?;
    let sigs: Vec<String> = [SIG_A, SIG_B]
        .iter()
        .filter_map(|n| std::fs::read_to_string(dir.join(n)).ok())
        .collect();
    if sigs.is_empty() {
        return None;
    }
    Some((text, sigs))
}

/// Delete the staging folder. Used to cancel, and after a successful apply.
pub fn discard(app_folder: &Path) -> Result<(), StageError> {
    let dir = staging_dir(app_folder);
    if !dir.exists() {
        return Ok(());
    }
    std::fs::remove_dir_all(&dir).map_err(|e| StageError::Io(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest;

    fn body_for(name: &str) -> Vec<u8> {
        format!("the new {name} with some length to it").into_bytes()
    }
    fn old_body_for(name: &str) -> Vec<u8> {
        format!("the old {name}").into_bytes()
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
            let b = body_for(name);
            s.push_str(&format!(
                "file={i} {name} {} {} {}\n",
                b.len(),
                u8::from(*required),
                sha256::hex(&sha256::hash(&b))
            ));
        }
        manifest::parse(&s).expect("the test manifest must parse")
    }

    struct Sandbox(PathBuf);

    impl Sandbox {
        fn new(tag: &str) -> Sandbox {
            let p = std::env::temp_dir().join(format!(
                "vigil-stage-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).expect("sandbox");
            Sandbox(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
        /// Put the *old* version of every binary in the application folder.
        fn with_old_binaries(self) -> Sandbox {
            for (name, _) in NAMES {
                std::fs::write(self.0.join(name), old_body_for(name)).expect("write");
            }
            self
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A fetcher that serves the right bytes and counts calls.
    fn good_fetcher(calls: &mut Vec<String>) -> impl FnMut(&str) -> Result<Vec<u8>, String> + '_ {
        move |url: &str| {
            calls.push(url.to_string());
            let name = url.rsplit('/').next().unwrap_or("");
            Ok(body_for(name))
        }
    }

    #[test]
    fn six_stale_binaries_are_downloaded_and_verified_and_a_marker_is_left() {
        let sb = Sandbox::new("fresh").with_old_binaries();
        let m = manifest_of();
        let mut calls = Vec::new();
        let out = stage(sb.path(), &m, good_fetcher(&mut calls)).expect("stages");

        assert_eq!(out.fetched.len(), NAMES.len());
        assert!(out.already.is_empty());
        assert!(out.current.is_empty());
        assert!(out.complete(&m));
        assert_eq!(calls.len(), NAMES.len(), "one fetch per file, no more");

        // Every staged file is the right bytes, and no `.part` survived.
        for (name, _) in NAMES {
            let staged = staging_dir(sb.path()).join(name);
            assert_eq!(std::fs::read(&staged).expect("staged"), body_for(name));
            assert!(!staging_dir(sb.path()).join(format!("{name}.part")).exists());
        }
        assert!(ready_marker(sb.path()).exists());
        // And the application folder is untouched — the promise of the whole phase.
        for (name, _) in NAMES {
            assert_eq!(
                std::fs::read(sb.path().join(name)).expect("app folder"),
                old_body_for(name),
                "{name} in the application folder must not have been touched"
            );
        }
    }

    /// The delta strategy, end to end: run it twice and the second run downloads nothing.
    #[test]
    fn a_second_run_downloads_nothing() {
        let sb = Sandbox::new("again").with_old_binaries();
        let m = manifest_of();
        let mut first = Vec::new();
        stage(sb.path(), &m, good_fetcher(&mut first)).expect("stages");
        assert_eq!(first.len(), NAMES.len());

        let mut second = Vec::new();
        let out = stage(sb.path(), &m, good_fetcher(&mut second)).expect("stages again");
        assert!(second.is_empty(), "nothing should be fetched twice");
        assert_eq!(out.already.len(), NAMES.len());
        assert!(out.fetched.is_empty());
        assert!(out.complete(&m));
    }

    /// Corrupt exactly one staged file and exactly that one is fetched again.
    #[test]
    fn corrupting_one_staged_file_re_downloads_only_that_one() {
        let sb = Sandbox::new("corrupt").with_old_binaries();
        let m = manifest_of();
        let mut calls = Vec::new();
        stage(sb.path(), &m, good_fetcher(&mut calls)).expect("stages");

        std::fs::write(staging_dir(sb.path()).join("vigil.exe"), b"tampered").expect("corrupt");
        let mut again = Vec::new();
        let out = stage(sb.path(), &m, good_fetcher(&mut again)).expect("stages");
        assert_eq!(again.len(), 1, "only the corrupt file, got {again:?}");
        assert!(again[0].ends_with("vigil.exe"));
        assert_eq!(out.fetched, vec!["vigil.exe".to_string()]);
    }

    /// A file already correct in the application folder is not staged at all.
    #[test]
    fn a_binary_that_is_already_current_is_not_downloaded() {
        let sb = Sandbox::new("current").with_old_binaries();
        let m = manifest_of();
        std::fs::write(sb.path().join("wirelog.exe"), body_for("wirelog.exe")).expect("write");
        let mut calls = Vec::new();
        let out = stage(sb.path(), &m, good_fetcher(&mut calls)).expect("stages");
        assert_eq!(out.current, vec!["wirelog.exe".to_string()]);
        assert!(!calls.iter().any(|u| u.ends_with("wirelog.exe")));
    }

    /// Bytes that do not hash to the signed manifest are never accepted and never retried into
    /// success — and nothing is left staged.
    #[test]
    fn bytes_that_do_not_match_the_signed_hash_refuse_the_run() {
        let sb = Sandbox::new("badhash").with_old_binaries();
        let m = manifest_of();
        // Right length, wrong contents: the shape a substituted file would take.
        let mut calls = 0;
        let out = stage(sb.path(), &m, |url| {
            calls += 1;
            let name = url.rsplit('/').next().unwrap_or("");
            let mut b = body_for(name);
            b[0] ^= 0xff;
            Ok(b)
        });
        assert_eq!(
            out,
            Err(StageError::HashMismatch {
                name: "vigil-repair.exe".into()
            })
        );
        assert_eq!(calls, 1, "a hash mismatch must not be retried");
        assert!(!ready_marker(sb.path()).exists());
        assert!(!staging_dir(sb.path()).join("vigil-repair.exe").exists());
    }

    /// A short body is the ordinary shape of censorship. It is retried — a slow line has bad
    /// moments — and if it keeps happening the run fails without staging anything.
    #[test]
    fn a_truncated_body_is_retried_and_then_refused() {
        let sb = Sandbox::new("short").with_old_binaries();
        let m = manifest_of();
        let mut calls = 0;
        let out = stage(sb.path(), &m, |url| {
            calls += 1;
            let name = url.rsplit('/').next().unwrap_or("");
            let mut b = body_for(name);
            b.truncate(b.len() - 1);
            Ok(b)
        });
        assert!(
            matches!(out, Err(StageError::Unfetchable { .. })),
            "{out:?}"
        );
        assert_eq!(calls, ATTEMPTS, "a short body is worth retrying");
        assert!(!staging_dir(sb.path()).join("vigil-repair.exe").exists());
        assert!(!ready_marker(sb.path()).exists());
    }

    /// And a short body that recovers on the second try is a success, because that is what a bad
    /// moment on a slow line looks like.
    #[test]
    fn a_short_body_that_recovers_is_not_a_failure() {
        let sb = Sandbox::new("recover").with_old_binaries();
        let m = manifest_of();
        let mut seen: Vec<String> = Vec::new();
        let out = stage(sb.path(), &m, |url| {
            let name = url.rsplit('/').next().unwrap_or("").to_string();
            let first = !seen.contains(&name);
            seen.push(name.clone());
            let mut b = body_for(&name);
            if first {
                b.truncate(1);
            }
            Ok(b)
        })
        .expect("recovers");
        assert_eq!(out.fetched.len(), NAMES.len());
        assert!(out.complete(&m));
    }

    /// A required file that never arrives stops the run; an optional one is noted and skipped.
    #[test]
    fn a_required_file_that_never_arrives_stops_the_run() {
        let m = manifest_of();
        for (target, required) in NAMES {
            let sb = Sandbox::new("unfetchable").with_old_binaries();
            let out = stage(sb.path(), &m, |url| {
                let name = url.rsplit('/').next().unwrap_or("");
                if name == *target {
                    return Err("silently dropped".into());
                }
                Ok(body_for(name))
            });
            if *required {
                assert_eq!(
                    out,
                    Err(StageError::Unfetchable {
                        name: target.to_string(),
                        last: "silently dropped".into()
                    }),
                    "{target} is required"
                );
            } else {
                let out = out.expect("an optional file may fail");
                assert_eq!(out.gave_up, vec![target.to_string()]);
                assert!(out.complete(&m), "the required set is still complete");
                assert!(ready_marker(sb.path()).exists());
            }
        }
    }

    /// The marker means "the whole set is here". A run that did not complete must not leave one
    /// behind, and a stale one from a previous manifest must not survive.
    #[test]
    fn the_ready_marker_only_exists_when_the_set_is_complete() {
        let sb = Sandbox::new("marker").with_old_binaries();
        let m = manifest_of();
        // Plant a stale marker, then fail the run.
        std::fs::create_dir_all(staging_dir(sb.path())).expect("dir");
        std::fs::write(ready_marker(sb.path()), b"stale").expect("write");
        let out = stage(sb.path(), &m, |_| Err("nothing works".into()));
        assert!(out.is_err());
        assert!(
            !ready_marker(sb.path()).exists(),
            "a stale marker must not survive a failed run"
        );
    }

    #[test]
    fn the_marker_says_which_version_and_serial_it_is_for() {
        let m = manifest_of();
        let t = ready_text(&m);
        assert!(t.contains("0.7.0"));
        assert!(t.contains("serial 7"));
        assert!(t.contains("Delete this folder to cancel"));
    }

    #[test]
    fn discarding_removes_the_whole_staging_folder_and_is_idempotent() {
        let sb = Sandbox::new("discard").with_old_binaries();
        let m = manifest_of();
        let mut calls = Vec::new();
        stage(sb.path(), &m, good_fetcher(&mut calls)).expect("stages");
        assert!(staging_dir(sb.path()).exists());
        discard(sb.path()).expect("discards");
        assert!(!staging_dir(sb.path()).exists());
        discard(sb.path()).expect("discarding nothing is fine");
    }

    #[test]
    fn a_writable_folder_passes_the_preflight_and_leaves_no_probe_behind() {
        let sb = Sandbox::new("writable");
        check_writable(sb.path()).expect("writable");
        let dir = staging_dir(sb.path());
        assert!(dir.exists());
        assert!(!dir.join("probe.tmp").exists());
        assert!(!dir.join("probe.moved").exists());
    }

    /// Hashing a folder must simply not see what is not there, rather than failing.
    #[test]
    fn hashing_a_folder_skips_what_is_missing() {
        let sb = Sandbox::new("hash");
        let m = manifest_of();
        assert!(hash_folder(sb.path(), &m).is_empty());
        std::fs::write(sb.path().join("vigil.exe"), body_for("vigil.exe")).expect("write");
        let d = hash_folder(sb.path(), &m);
        assert_eq!(d.len(), 1);
        assert_eq!(
            d.get("vigil.exe"),
            Some(&sha256::hash(&body_for("vigil.exe")))
        );
    }

    /// The hash of a real file must agree with hashing its bytes, including across the 64 KiB
    /// streaming boundary.
    #[test]
    fn hashing_a_file_agrees_with_hashing_its_bytes_at_any_size() {
        let sb = Sandbox::new("sizes");
        for n in [0usize, 1, 64 * 1024 - 1, 64 * 1024, 64 * 1024 + 1, 200_000] {
            let body = vec![0x5au8; n];
            let p = sb.path().join("x.bin");
            std::fs::write(&p, &body).expect("write");
            assert_eq!(hash_file(&p), Some(sha256::hash(&body)), "{n} bytes");
        }
        assert_eq!(hash_file(&sb.path().join("nope.bin")), None);
    }
}

#[cfg(test)]
mod input_tests {
    use super::*;

    /// Phase B has to be able to verify again without the network. The manifest and both signatures
    /// therefore live beside the staged files — otherwise the only hash a substituted file would be
    /// checked against is the one it arrived with.
    #[test]
    fn the_manifest_and_signatures_survive_for_phase_b() {
        let dir = std::env::temp_dir().join(format!("vigil-inputs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");

        assert_eq!(load_inputs(&dir), None, "nothing staged yet");

        let sigs = vec!["sig one".to_string(), "sig two".to_string()];
        save_inputs(&dir, "schema=1\n", &sigs).expect("saves");
        let (text, back) = load_inputs(&dir).expect("loads");
        assert_eq!(text, "schema=1\n");
        assert_eq!(back, sigs);

        // One signature missing is still loadable — the verifier is what decides that two are
        // required, and it must be the thing that says so rather than the file reader.
        std::fs::remove_file(staging_dir(&dir).join(SIG_B)).expect("remove");
        let (_, one) = load_inputs(&dir).expect("still loads");
        assert_eq!(one.len(), 1);

        // No signatures at all is "nothing to apply", not an error.
        std::fs::remove_file(staging_dir(&dir).join(SIG_A)).expect("remove");
        assert_eq!(load_inputs(&dir), None);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
