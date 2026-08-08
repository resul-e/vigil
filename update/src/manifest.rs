//! The update manifest: what it looks like, how it is read, and what makes it untrustworthy.
//!
//! Pure. No I/O, no network, no clock — `now` is a parameter. Everything here runs and is tested
//! on Linux, which is the point: this is the half that decides whether an update is allowed to
//! happen at all, and a decision that can only be tested on Windows on the day it was written is
//! not a decision anybody can check.
//!
//! ## The format, and why it is not JSON
//!
//! Line-oriented `key=value` text, matching the three files this project already writes that way:
//! `sysproxy-snapshot.txt`, `envproxy-snapshot.txt` and the strategy cache. That costs zero
//! dependencies and there is no parser to get wrong. It also removes a question JSON would have
//! raised: minisign signs the **exact bytes of the file**, so there is no canonical form to agree
//! on — the thing verified is the thing parsed.
//!
//! ```text
//! # vigil update manifest — signed, do not edit
//! schema=1
//! serial=7
//! version=0.7.0
//! expires=2026-11-12T00:00:00Z
//! min_version=0.7.0
//! critical=0
//! base=https://github.com/resul-e/vigil/releases/download/v0.7.0/
//! notes_tr=Güncelleme artık kendini yapıyor.
//! notes_en=Updates now install themselves.
//! file=0 vigil-repair.exe 401408 1 3a7f1c…
//! file=5 vigil-app.exe    730112 1 51aa38…
//! ```
//!
//! ## Strictness is the feature
//!
//! Every reader here refuses rather than repairs. An unknown key, a duplicate key, a trailing
//! space in a number, a name with a path separator in it — all rejections. The reason is not
//! tidiness: this file is signed, and every liberty a parser takes is a way for what was signed
//! and what was understood to differ. The signer is a script in this repository and it emits one
//! shape.

use vigil_core::sha256::{self, Digest};

use crate::version::Version;

/// The largest manifest that will be read at all. A signed file is not a reason to read an
/// unbounded one: the bytes arrive over a network before anything has verified them.
pub const MAX_BYTES: usize = 16 * 1024;
/// The most files one update may carry. Six today.
pub const MAX_FILES: usize = 64;
/// The largest single file. `probe.exe` is 2.8 MB; 64 MB is far above anything this project could
/// legitimately ship and far below anything that would fill a disk.
pub const MAX_FILE_SIZE: u64 = 64 * 1024 * 1024;
/// How far ahead of the floor a serial may jump. Without a ceiling, one absurd signed manifest —
/// `serial=u64::MAX` — would raise the floor past anything a real release could ever use and lock
/// the client out of updates for good.
pub const SERIAL_WINDOW: u64 = 1000;

/// Hosts a download may come from. Checked on the base URL and again after every redirect.
///
/// An allowlist rather than "any https", because the manifest is the one thing an attacker who
/// obtained a signing key would rewrite, and pinning where the bytes may come from is a second
/// wall that key alone does not knock down.
pub const ALLOWED_HOSTS: &[&str] = &[
    "github.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
];

/// One binary in an update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// The order it must be replaced in. Not decoration: `vigil-repair.exe` is 0 so the safety
    /// net is in place before anything else moves, and `vigil-app.exe` is last so an interruption
    /// leaves an old application beside new everything-else rather than the reverse.
    pub order: u32,
    pub name: String,
    pub size: u64,
    /// Whether the update must fail if this one cannot be replaced. `wirelog.exe` is a
    /// developer instrument and may be skipped; `vigil-repair.exe` may not.
    pub required: bool,
    pub digest: Digest,
}

/// A manifest that parsed. Parsing says nothing about whether it may be *acted on* — that is
/// [`check_trust`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub schema: u32,
    pub serial: u64,
    pub version: Version,
    /// Seconds since the Unix epoch.
    pub expires: u64,
    pub min_version: Version,
    pub critical: bool,
    pub base: String,
    pub notes_tr: String,
    pub notes_en: String,
    /// Sorted by `order`, contiguous from zero.
    pub files: Vec<FileEntry>,
}

/// Why a manifest was refused. One variant per reason, because "invalid manifest" in a log is a
/// message that costs somebody an evening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    TooLarge {
        bytes: usize,
    },
    NotUtf8,
    UnknownKey(String),
    DuplicateKey(String),
    MissingKey(&'static str),
    MalformedLine(String),
    BadNumber {
        key: &'static str,
        value: String,
    },
    BadVersion {
        key: &'static str,
        value: String,
    },
    BadTimestamp(String),
    BadFlag {
        key: &'static str,
        value: String,
    },
    UnsupportedSchema(u32),
    BadBase(String),
    BaseHostNotAllowed(String),
    BadName(String),
    BadDigest(String),
    FileTooLarge {
        name: String,
        size: u64,
    },
    EmptyFile(String),
    NoFiles,
    TooManyFiles(usize),
    DuplicateOrder(u32),
    OrderNotContiguous {
        expected: u32,
        got: u32,
    },
    DuplicateName(String),
    /// Trust failures. Separate from shape failures because they mean "not now" rather than
    /// "not ever", and the interface says different things about them.
    SerialNotNewer {
        serial: u64,
        floor: u64,
    },
    SerialTooFarAhead {
        serial: u64,
        floor: u64,
    },
    Expired {
        expires: u64,
        now: u64,
    },
    RunningTooOld {
        running: Version,
        min: Version,
    },
}

impl core::fmt::Display for Reject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use Reject::*;
        match self {
            TooLarge { bytes } => write!(f, "manifest is {bytes} bytes, over the limit"),
            NotUtf8 => f.write_str("manifest is not UTF-8"),
            UnknownKey(k) => write!(f, "unknown key {k:?}"),
            DuplicateKey(k) => write!(f, "key {k:?} appears twice"),
            MissingKey(k) => write!(f, "missing key {k:?}"),
            MalformedLine(l) => write!(f, "malformed line {l:?}"),
            BadNumber { key, value } => write!(f, "{key}: {value:?} is not a number"),
            BadVersion { key, value } => write!(f, "{key}: {value:?} is not major.minor.patch"),
            BadTimestamp(v) => write!(f, "expires: {v:?} is not YYYY-MM-DDTHH:MM:SSZ"),
            BadFlag { key, value } => write!(f, "{key}: {value:?} is not 0 or 1"),
            UnsupportedSchema(n) => write!(f, "schema {n} is not understood"),
            BadBase(b) => write!(f, "base {b:?} must be https and end with a slash"),
            BaseHostNotAllowed(h) => write!(f, "base host {h:?} is not on the allowlist"),
            BadName(n) => write!(f, "file name {n:?} is not acceptable"),
            BadDigest(d) => write!(f, "digest {d:?} is not 64 hex characters"),
            FileTooLarge { name, size } => write!(f, "{name} is {size} bytes, over the limit"),
            EmptyFile(n) => write!(f, "{n} is zero bytes"),
            NoFiles => f.write_str("manifest lists no files"),
            TooManyFiles(n) => write!(f, "{n} files is too many"),
            DuplicateOrder(o) => write!(f, "two files claim order {o}"),
            OrderNotContiguous { expected, got } => {
                write!(f, "expected order {expected}, got {got}")
            }
            DuplicateName(n) => write!(f, "two entries name {n:?}"),
            SerialNotNewer { serial, floor } => {
                write!(f, "serial {serial} is not newer than {floor}")
            }
            SerialTooFarAhead { serial, floor } => {
                write!(f, "serial {serial} is implausibly far ahead of {floor}")
            }
            Expired { expires, now } => write!(f, "manifest expired at {expires}, now {now}"),
            RunningTooOld { running, min } => {
                write!(f, "running {running} is below the required {min}")
            }
        }
    }
}

/// What the client knows when it decides whether to trust a manifest.
#[derive(Debug, Clone, Copy)]
pub struct Trust {
    /// Seconds since the Unix epoch. A parameter, never read from the clock in here.
    pub now: u64,
    /// `max(compiled-in serial, last serial we accepted)`. The compiled-in half is load-bearing:
    /// vigil is portable and "delete the folder and it is gone", so the remembered half may be
    /// missing on any run, and the constant is the one thing an attacker cannot reset without
    /// replacing the binary he is trying to replace.
    pub serial_floor: u64,
    pub running: Version,
}

/// Parse and shape-check. Does **not** decide whether the manifest may be acted on.
pub fn parse(text: &str) -> Result<Manifest, Reject> {
    if text.len() > MAX_BYTES {
        return Err(Reject::TooLarge { bytes: text.len() });
    }

    let mut scalars: Vec<(String, String)> = Vec::new();
    let mut files: Vec<FileEntry> = Vec::new();

    for raw in text.lines() {
        let line = raw.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // No leading whitespace, and no trailing whitespace: both are invisible in an editor and
        // would make two byte-different files parse the same, which for a signed file is exactly
        // the ambiguity to avoid.
        if line != line.trim() {
            return Err(Reject::MalformedLine(line.to_string()));
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(Reject::MalformedLine(line.to_string()));
        };
        // A line that starts with `=` has no key at all. Treated as malformed rather than as an
        // unknown key, because "" is not a name anybody typed by mistake.
        if key.is_empty() {
            return Err(Reject::MalformedLine(line.to_string()));
        }
        if key == "file" {
            files.push(parse_file(value)?);
            continue;
        }
        if !is_known_key(key) {
            return Err(Reject::UnknownKey(key.to_string()));
        }
        if scalars.iter().any(|(k, _)| k == key) {
            return Err(Reject::DuplicateKey(key.to_string()));
        }
        scalars.push((key.to_string(), value.to_string()));
    }

    let get = |k: &'static str| -> Result<&str, Reject> {
        scalars
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.as_str())
            .ok_or(Reject::MissingKey(k))
    };

    let schema = number("schema", get("schema")?)? as u32;
    if schema != 1 {
        // No forward compatibility on purpose. A client that guesses at a format it does not know
        // is a client that can act on a field it has misread.
        return Err(Reject::UnsupportedSchema(schema));
    }

    let serial = number("serial", get("serial")?)?;
    let version = version_of("version", get("version")?)?;
    let min_version = version_of("min_version", get("min_version")?)?;
    let expires_raw = get("expires")?;
    let expires = vigil_core::clock::parse_utc(expires_raw)
        .ok_or(Reject::BadTimestamp(expires_raw.into()))?;
    let critical = flag("critical", get("critical")?)?;

    let base = get("base")?.to_string();
    check_base(&base)?;

    let manifest = Manifest {
        schema,
        serial,
        version,
        expires,
        min_version,
        critical,
        base,
        notes_tr: get("notes_tr")?.to_string(),
        notes_en: get("notes_en")?.to_string(),
        files: order_files(files)?,
    };
    Ok(manifest)
}

fn is_known_key(k: &str) -> bool {
    matches!(
        k,
        "schema"
            | "serial"
            | "version"
            | "expires"
            | "min_version"
            | "critical"
            | "base"
            | "notes_tr"
            | "notes_en"
    )
}

fn number(key: &'static str, v: &str) -> Result<u64, Reject> {
    if v.is_empty() || !v.bytes().all(|c| c.is_ascii_digit()) {
        return Err(Reject::BadNumber {
            key,
            value: v.to_string(),
        });
    }
    // Leading zeros are two spellings of one number in a signed file.
    if v.len() > 1 && v.starts_with('0') {
        return Err(Reject::BadNumber {
            key,
            value: v.to_string(),
        });
    }
    v.parse().map_err(|_| Reject::BadNumber {
        key,
        value: v.to_string(),
    })
}

fn version_of(key: &'static str, v: &str) -> Result<Version, Reject> {
    Version::parse(v).ok_or(Reject::BadVersion {
        key,
        value: v.to_string(),
    })
}

fn flag(key: &'static str, v: &str) -> Result<bool, Reject> {
    match v {
        "0" => Ok(false),
        "1" => Ok(true),
        // Not `true`/`yes`/`on`. One spelling.
        _ => Err(Reject::BadFlag {
            key,
            value: v.to_string(),
        }),
    }
}

/// `https://host/path/`, host on the allowlist, ending in a slash.
///
/// The trailing slash is required rather than added, because appending a name to a base that
/// silently lacks one produces a different URL than the signer meant, and "the signer meant
/// something else" is the entire class of bug this file guards against.
fn check_base(base: &str) -> Result<(), Reject> {
    let Some(rest) = base.strip_prefix("https://") else {
        return Err(Reject::BadBase(base.to_string()));
    };
    if !base.ends_with('/') || rest.is_empty() {
        return Err(Reject::BadBase(base.to_string()));
    }
    // No credentials, no query, no fragment, no dot-segments: all of them are ways to make a URL
    // read as one host and resolve as another.
    if rest.contains('@')
        || rest.contains('?')
        || rest.contains('#')
        || rest.contains("..")
        // An empty path segment. `https://host//a/` and `https://host/a/` are different URLs to a
        // server and the same one to a careless reader.
        || rest.contains("//")
    {
        return Err(Reject::BadBase(base.to_string()));
    }
    let host = rest.split('/').next().unwrap_or("");
    if host.is_empty() || !ALLOWED_HOSTS.contains(&host) {
        return Err(Reject::BaseHostNotAllowed(host.to_string()));
    }
    Ok(())
}

/// `<order> <name> <size> <required> <sha256>`, single spaces or runs of them, nothing else.
fn parse_file(value: &str) -> Result<FileEntry, Reject> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 5 {
        return Err(Reject::MalformedLine(format!("file={value}")));
    }
    let order = number("file.order", parts[0])? as u32;
    let name = parts[1].to_string();
    check_name(&name)?;
    let size = number("file.size", parts[2])?;
    if size == 0 {
        return Err(Reject::EmptyFile(name));
    }
    if size > MAX_FILE_SIZE {
        return Err(Reject::FileTooLarge { name, size });
    }
    let required = flag("file.required", parts[3])?;
    let digest = sha256::from_hex(parts[4]).ok_or(Reject::BadDigest(parts[4].to_string()))?;
    Ok(FileEntry {
        order,
        name,
        size,
        required,
        digest,
    })
}

/// A plain file name, and nothing that could reach outside the folder.
///
/// This name is joined onto a directory path and onto a URL base, so a separator or a dot-segment
/// in it is a directory traversal in one direction and a different host in the other.
fn check_name(name: &str) -> Result<(), Reject> {
    let bad = name.is_empty()
        || name.len() > 64
        || !name.ends_with(".exe")
        || name.contains('/')
        || name.contains('\\')
        || name.contains("..")
        || name.starts_with('.')
        || name.contains(':')
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'.');
    if bad {
        return Err(Reject::BadName(name.to_string()));
    }
    Ok(())
}

/// Sort by order and insist the orders are `0..n` with no gaps, no repeats, and no repeated names.
fn order_files(mut files: Vec<FileEntry>) -> Result<Vec<FileEntry>, Reject> {
    if files.is_empty() {
        return Err(Reject::NoFiles);
    }
    if files.len() > MAX_FILES {
        return Err(Reject::TooManyFiles(files.len()));
    }
    files.sort_by_key(|f| f.order);
    for (i, f) in files.iter().enumerate() {
        if i > 0 && files[i - 1].order == f.order {
            return Err(Reject::DuplicateOrder(f.order));
        }
        if f.order != i as u32 {
            return Err(Reject::OrderNotContiguous {
                expected: i as u32,
                got: f.order,
            });
        }
    }
    for (i, f) in files.iter().enumerate() {
        if files[..i].iter().any(|g| g.name == f.name) {
            return Err(Reject::DuplicateName(f.name.clone()));
        }
    }
    Ok(files)
}

/// May this manifest be acted on, right now, by this build?
///
/// Separate from [`parse`] because the answers mean different things: a shape failure is "this
/// file is wrong", and a trust failure is "this file is not for us, or not yet, or not any more".
pub fn check_trust(m: &Manifest, t: &Trust) -> Result<(), Reject> {
    if m.serial <= t.serial_floor {
        return Err(Reject::SerialNotNewer {
            serial: m.serial,
            floor: t.serial_floor,
        });
    }
    if m.serial > t.serial_floor.saturating_add(SERIAL_WINDOW) {
        return Err(Reject::SerialTooFarAhead {
            serial: m.serial,
            floor: t.serial_floor,
        });
    }
    if m.expires <= t.now {
        return Err(Reject::Expired {
            expires: m.expires,
            now: t.now,
        });
    }
    if t.running < m.min_version {
        return Err(Reject::RunningTooOld {
            running: t.running,
            min: m.min_version,
        });
    }
    Ok(())
}

/// Is this manifest offering something newer than what is running?
///
/// Deliberately not part of [`check_trust`]: a manifest for the version already installed is
/// perfectly trustworthy, it just has nothing to do. Keeping them apart is what lets the
/// interface say "up to date" rather than reporting a refusal.
pub fn is_newer_than(m: &Manifest, running: Version) -> bool {
    m.version > running
}

/// The URL a file is fetched from. The base is already validated and ends in a slash, and the
/// name is already known to contain no separators, so this is a concatenation rather than a
/// URL join with its own rules.
pub fn url_for(m: &Manifest, f: &FileEntry) -> String {
    format!("{}{}", m.base, f.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "\
# vigil update manifest — signed, do not edit
schema=1
serial=7
version=0.7.0
expires=2026-11-12T00:00:00Z
min_version=0.6.3
critical=0
base=https://github.com/resul-e/vigil/releases/download/v0.7.0/
notes_tr=Güncelleme artık kendini yapıyor.
notes_en=Updates now install themselves.
file=0 vigil-repair.exe 401408 1 7ebad6de0411611e7aa7db11c640fdd6ed1b0aa47d0c3591ff6456398d1ca91f
file=1 vigil.exe 707072 1 c3096f1267755a4b09f19c27d601b7926748016e13c9f17f4165f08ed896833a
file=2 wirelog.exe 391168 0 6edd2a8ba577c8549f2493f46994590c7e27fc4f09f7cb1feee31d8b006e961e
file=3 vigil-scan.exe 961024 0 366f324a769ad0e49a1851279e23d1ea6891274b64074487c8b260871a8532c0
file=4 vigil-app.exe 730112 1 00e1f530d8e678d3625d7c4e954363ceae857951be9e92be32abc5b0b68d8e6d
";

    fn good() -> Manifest {
        parse(GOOD).expect("the golden manifest must parse")
    }

    /// Replace one line of the golden manifest, so every rejection test differs from a passing
    /// manifest in exactly one way.
    fn with(key: &str, line: &str) -> String {
        GOOD.lines()
            .map(|l| {
                if l.starts_with(&format!("{key}=")) {
                    line.to_string()
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn without(key: &str) -> String {
        GOOD.lines()
            .filter(|l| !l.starts_with(&format!("{key}=")))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_golden_manifest_parses_completely() {
        let m = good();
        assert_eq!(m.schema, 1);
        assert_eq!(m.serial, 7);
        assert_eq!(m.version, Version::new(0, 7, 0));
        assert_eq!(m.min_version, Version::new(0, 6, 3));
        assert!(!m.critical);
        assert_eq!(m.expires, 1_794_441_600);
        assert!(m.notes_tr.starts_with("Güncelleme"));
        assert_eq!(m.files.len(), 5);
    }

    /// The order is a promise about the sequence of replacements, so it is asserted here rather
    /// than trusted to whoever writes the next manifest.
    #[test]
    fn the_repair_tool_is_first_and_the_application_is_last() {
        let m = good();
        assert_eq!(m.files.first().expect("some").name, "vigil-repair.exe");
        assert_eq!(m.files.last().expect("some").name, "vigil-app.exe");
        assert!(m.files.first().expect("some").required);
        assert!(m.files.last().expect("some").required);
        // A developer instrument may be skipped; the safety net may not.
        let wirelog = m
            .files
            .iter()
            .find(|f| f.name == "wirelog.exe")
            .expect("some");
        assert!(!wirelog.required);
    }

    #[test]
    fn entries_come_back_sorted_whatever_order_they_were_written_in() {
        let shuffled: String = {
            let mut lines: Vec<&str> = GOOD.lines().collect();
            lines.reverse();
            lines.join("\n")
        };
        let m = parse(&shuffled).expect("order in the file must not matter");
        let orders: Vec<u32> = m.files.iter().map(|f| f.order).collect();
        assert_eq!(orders, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn the_url_is_the_base_and_the_name() {
        let m = good();
        assert_eq!(
            url_for(&m, &m.files[0]),
            "https://github.com/resul-e/vigil/releases/download/v0.7.0/vigil-repair.exe"
        );
    }

    // ------------------------------------------------------------------ shape rejections

    #[test]
    fn a_manifest_larger_than_the_limit_is_refused_before_it_is_read() {
        let big = format!("{GOOD}\n# {}", "x".repeat(MAX_BYTES));
        assert!(matches!(parse(&big), Err(Reject::TooLarge { .. })));
    }

    #[test]
    fn every_required_key_is_required() {
        for key in [
            "schema",
            "serial",
            "version",
            "expires",
            "min_version",
            "critical",
            "base",
            "notes_tr",
            "notes_en",
        ] {
            assert_eq!(
                parse(&without(key)),
                Err(Reject::MissingKey(match key {
                    "schema" => "schema",
                    "serial" => "serial",
                    "version" => "version",
                    "expires" => "expires",
                    "min_version" => "min_version",
                    "critical" => "critical",
                    "base" => "base",
                    "notes_tr" => "notes_tr",
                    _ => "notes_en",
                })),
                "dropping {key} must be refused"
            );
        }
    }

    #[test]
    fn an_unknown_key_is_refused_rather_than_ignored() {
        let s = format!("{GOOD}rollout=50\n");
        assert_eq!(parse(&s), Err(Reject::UnknownKey("rollout".into())));
    }

    #[test]
    fn a_duplicate_key_is_refused_rather_than_last_one_winning() {
        let s = format!("{GOOD}serial=9\n");
        assert_eq!(parse(&s), Err(Reject::DuplicateKey("serial".into())));
    }

    #[test]
    fn a_line_that_is_not_key_equals_value_is_refused() {
        for line in ["schema", "just some words", "=", "  schema=1", "schema=1  "] {
            let s = format!("{GOOD}{line}\n");
            assert!(
                matches!(
                    parse(&s),
                    Err(Reject::MalformedLine(_)) | Err(Reject::DuplicateKey(_))
                ),
                "{line:?} should not be accepted"
            );
        }
    }

    #[test]
    fn comments_and_blank_lines_are_the_only_things_skipped() {
        let s = format!("# a comment\n\n{GOOD}\n\n# another\n");
        assert_eq!(parse(&s).expect("parses").serial, 7);
    }

    #[test]
    fn a_schema_we_do_not_understand_is_refused_outright() {
        assert_eq!(
            parse(&with("schema", "schema=2")),
            Err(Reject::UnsupportedSchema(2))
        );
        assert_eq!(
            parse(&with("schema", "schema=0")),
            Err(Reject::UnsupportedSchema(0))
        );
    }

    #[test]
    fn numbers_must_be_plain_decimal_with_no_padding_or_sign() {
        for v in [
            "", "-1", "+1", "0x7", "7 ", " 7", "07", "seven", "7.0", "١٢",
        ] {
            let s = with("serial", &format!("serial={v}"));
            assert!(
                matches!(
                    parse(&s),
                    Err(Reject::BadNumber { .. }) | Err(Reject::MalformedLine(_))
                ),
                "serial={v:?} should be refused"
            );
        }
    }

    #[test]
    fn versions_must_be_three_numbers() {
        for v in ["", "1", "1.2", "v0.7.0", "0.7.0-rc1", "0.7", "a.b.c"] {
            assert!(
                matches!(
                    parse(&with("version", &format!("version={v}"))),
                    Err(Reject::BadVersion { .. })
                ),
                "version={v:?} should be refused"
            );
            assert!(
                matches!(
                    parse(&with("min_version", &format!("min_version={v}"))),
                    Err(Reject::BadVersion { .. })
                ),
                "min_version={v:?} should be refused"
            );
        }
    }

    #[test]
    fn the_expiry_must_be_the_exact_timestamp_shape() {
        for v in [
            "",
            "2026-11-12",
            "2026-11-12 00:00:00",
            "2026-11-12T00:00:00+03:00",
            "2026-13-01T00:00:00Z",
            "2026-02-30T00:00:00Z",
            "never",
        ] {
            assert!(
                matches!(
                    parse(&with("expires", &format!("expires={v}"))),
                    Err(Reject::BadTimestamp(_))
                ),
                "expires={v:?} should be refused"
            );
        }
    }

    #[test]
    fn flags_are_zero_or_one_and_nothing_else() {
        for v in ["", "true", "yes", "2", "01", "no", "TRUE"] {
            assert!(
                matches!(
                    parse(&with("critical", &format!("critical={v}"))),
                    Err(Reject::BadFlag { .. })
                ),
                "critical={v:?} should be refused"
            );
        }
    }

    #[test]
    fn the_base_must_be_https_and_end_in_a_slash() {
        for v in [
            "",
            "http://github.com/x/",
            "https://github.com/x",
            "github.com/x/",
            "https://",
            "https://github.com/x/?a=b",
            "https://github.com/x/#f",
            "https://user@github.com/x/",
            "https://github.com/../x/",
        ] {
            assert!(
                matches!(
                    parse(&with("base", &format!("base={v}"))),
                    Err(Reject::BadBase(_)) | Err(Reject::BaseHostNotAllowed(_))
                ),
                "base={v:?} should be refused"
            );
        }
    }

    /// The allowlist is a second wall behind the signature: even a manifest signed with a stolen
    /// key cannot point the download at a host of the attacker's choosing.
    #[test]
    fn the_base_host_must_be_on_the_allowlist() {
        for host in [
            "example.com",
            "github.com.evil.net",
            "notgithub.com",
            "gitHub.com",
            "raw.githubusercontent.com.evil.net",
        ] {
            assert_eq!(
                parse(&with("base", &format!("base=https://{host}/x/"))),
                Err(Reject::BaseHostNotAllowed(host.to_string())),
                "{host} must not be allowed"
            );
        }
        for host in ALLOWED_HOSTS {
            assert!(
                parse(&with("base", &format!("base=https://{host}/x/"))).is_ok(),
                "{host} must be allowed"
            );
        }
    }

    #[test]
    fn a_file_line_must_have_exactly_five_fields() {
        for v in [
            "0 vigil.exe 100 1",
            "0 vigil.exe 100 1 abc def",
            "0 vigil.exe 100",
            "",
        ] {
            let s = format!("{GOOD}file={v}\n");
            assert!(
                matches!(parse(&s), Err(Reject::MalformedLine(_))),
                "file={v:?} should be refused"
            );
        }
    }

    /// The name is joined onto a directory path and onto a URL. A separator in it is a directory
    /// traversal in one direction and a different host in the other.
    #[test]
    fn a_name_that_could_escape_the_folder_is_refused() {
        let d = "7ebad6de0411611e7aa7db11c640fdd6ed1b0aa47d0c3591ff6456398d1ca91f";
        for name in [
            "../vigil.exe",
            "..\\vigil.exe",
            "sub/vigil.exe",
            "sub\\vigil.exe",
            "C:vigil.exe",
            ".hidden.exe",
            "vigil.exe.txt",
            "vigil",
            "vigil.dll",
            "vigil exe",
            "vigil*.exe",
            "",
            "a..b.exe",
        ] {
            let s = format!("{GOOD}file=5 {name} 100 1 {d}\n");
            assert!(
                matches!(
                    parse(&s),
                    Err(Reject::BadName(_)) | Err(Reject::MalformedLine(_))
                ),
                "name {name:?} should be refused"
            );
        }
    }

    #[test]
    fn a_digest_must_be_sixty_four_hex_characters() {
        for d in [
            "",
            "abc",
            &"a".repeat(63),
            &"a".repeat(65),
            &"g".repeat(64),
            &"A".repeat(64).replace('A', "z"),
        ] {
            let s = format!("{GOOD}file=5 extra.exe 100 1 {d}\n");
            assert!(
                matches!(
                    parse(&s),
                    Err(Reject::BadDigest(_)) | Err(Reject::MalformedLine(_))
                ),
                "digest {d:?} should be refused"
            );
        }
        // Uppercase hex is the same digest, so it parses — the comparison is on bytes.
        let up = "7EBAD6DE0411611E7AA7DB11C640FDD6ED1B0AA47D0C3591FF6456398D1CA91F";
        assert!(parse(&format!("{GOOD}file=5 extra.exe 100 1 {up}\n")).is_ok());
    }

    #[test]
    fn a_zero_byte_or_absurdly_large_file_is_refused() {
        let d = "7ebad6de0411611e7aa7db11c640fdd6ed1b0aa47d0c3591ff6456398d1ca91f";
        assert!(matches!(
            parse(&format!("{GOOD}file=5 extra.exe 0 1 {d}\n")),
            Err(Reject::EmptyFile(_))
        ));
        assert!(matches!(
            parse(&format!(
                "{GOOD}file=5 extra.exe {} 1 {d}\n",
                MAX_FILE_SIZE + 1
            )),
            Err(Reject::FileTooLarge { .. })
        ));
    }

    #[test]
    fn a_manifest_with_no_files_has_nothing_to_do_and_is_refused() {
        let only_scalars: String = GOOD
            .lines()
            .filter(|l| !l.starts_with("file="))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(parse(&only_scalars), Err(Reject::NoFiles));
    }

    #[test]
    fn too_many_files_is_refused() {
        let d = "7ebad6de0411611e7aa7db11c640fdd6ed1b0aa47d0c3591ff6456398d1ca91f";
        let mut s = GOOD.to_string();
        for i in 5..=MAX_FILES {
            s.push_str(&format!("file={i} f{i}.exe 100 0 {d}\n"));
        }
        assert!(matches!(parse(&s), Err(Reject::TooManyFiles(_))));
    }

    /// A gap or a repeat in the order means the sequence of replacements is not fully specified,
    /// and the sequence is the thing that keeps a half-applied update safe.
    #[test]
    fn orders_must_be_contiguous_from_zero_with_no_repeats() {
        let d = "7ebad6de0411611e7aa7db11c640fdd6ed1b0aa47d0c3591ff6456398d1ca91f";
        assert!(matches!(
            parse(&format!("{GOOD}file=6 extra.exe 100 0 {d}\n")),
            Err(Reject::OrderNotContiguous { .. })
        ));
        assert!(matches!(
            parse(&format!("{GOOD}file=4 extra.exe 100 0 {d}\n")),
            Err(Reject::DuplicateOrder(4))
        ));
        let shifted = GOOD
            .replace("file=0 ", "file=1 ")
            .replace("file=1 vigil.exe", "file=2 vigil.exe");
        assert!(parse(&shifted).is_err(), "orders not starting at zero");
    }

    #[test]
    fn the_same_name_twice_is_refused() {
        let d = "7ebad6de0411611e7aa7db11c640fdd6ed1b0aa47d0c3591ff6456398d1ca91f";
        assert_eq!(
            parse(&format!("{GOOD}file=5 vigil.exe 100 0 {d}\n")),
            Err(Reject::DuplicateName("vigil.exe".into()))
        );
    }

    // ------------------------------------------------------------------ trust

    fn trust() -> Trust {
        Trust {
            now: 1_760_000_000,
            serial_floor: 6,
            running: Version::new(0, 6, 3),
        }
    }

    #[test]
    fn a_good_manifest_is_trusted() {
        assert_eq!(check_trust(&good(), &trust()), Ok(()));
        assert!(is_newer_than(&good(), Version::new(0, 6, 3)));
        assert!(!is_newer_than(&good(), Version::new(0, 7, 0)));
        assert!(!is_newer_than(&good(), Version::new(0, 8, 0)));
    }

    /// The replay defence. A genuine, correctly signed, *older* manifest must be refused, or an
    /// attacker who can serve bytes can put a known-vulnerable version back.
    #[test]
    fn a_serial_that_is_not_newer_is_refused() {
        for floor in [7u64, 8, 100, u64::MAX] {
            let t = Trust {
                serial_floor: floor,
                ..trust()
            };
            assert!(
                matches!(check_trust(&good(), &t), Err(Reject::SerialNotNewer { .. })),
                "floor {floor}"
            );
        }
    }

    /// And the other direction: one absurd signed manifest must not be able to raise the floor
    /// past anything a real release could use, which would lock the client out for good.
    #[test]
    fn a_serial_implausibly_far_ahead_is_refused() {
        let m = Manifest {
            serial: 5000,
            ..good()
        };
        assert!(matches!(
            check_trust(&m, &trust()),
            Err(Reject::SerialTooFarAhead { .. })
        ));
        // The edge is inclusive: exactly the window is fine, one past it is not.
        let edge = Manifest {
            serial: 6 + SERIAL_WINDOW,
            ..good()
        };
        assert_eq!(check_trust(&edge, &trust()), Ok(()));
        let over = Manifest {
            serial: 6 + SERIAL_WINDOW + 1,
            ..good()
        };
        assert!(matches!(
            check_trust(&over, &trust()),
            Err(Reject::SerialTooFarAhead { .. })
        ));
    }

    #[test]
    fn an_expired_manifest_is_refused_and_the_boundary_is_exact() {
        let m = good();
        let t = Trust {
            now: m.expires,
            ..trust()
        };
        assert!(matches!(check_trust(&m, &t), Err(Reject::Expired { .. })));
        let t = Trust {
            now: m.expires - 1,
            ..trust()
        };
        assert_eq!(check_trust(&m, &t), Ok(()));
        let t = Trust {
            now: m.expires + 86_400,
            ..trust()
        };
        assert!(matches!(check_trust(&m, &t), Err(Reject::Expired { .. })));
    }

    /// `min_version` is how a release says "you cannot get here from there" — a build too old to
    /// apply this update safely must be told, not upgraded into a mess.
    #[test]
    fn a_build_below_the_minimum_is_refused() {
        let t = Trust {
            running: Version::new(0, 6, 2),
            ..trust()
        };
        assert!(matches!(
            check_trust(&good(), &t),
            Err(Reject::RunningTooOld { .. })
        ));
        // Exactly the minimum is allowed.
        let t = Trust {
            running: Version::new(0, 6, 3),
            ..trust()
        };
        assert_eq!(check_trust(&good(), &t), Ok(()));
    }

    // ------------------------------------------------------------------ totality

    /// Flip every byte of the golden manifest, one at a time, to every one of a set of awkward
    /// values, and assert the parser never panics.
    ///
    /// This input arrives over a network from a host that may be lying, and it is parsed *before*
    /// any signature is checked — the signature is over these bytes, so they have to be read to
    /// be verified. A panic here is a crash on hostile input.
    #[test]
    fn no_single_byte_change_can_make_the_parser_panic() {
        let bytes = GOOD.as_bytes().to_vec();
        let mut parsed = 0usize;
        let mut rejected = 0usize;
        for i in 0..bytes.len() {
            for b in [
                0u8, b'\n', b'\r', b'=', b'#', b' ', b'\t', 0x7f, 0xff, b'9', b'z', b'/',
            ] {
                let mut m = bytes.clone();
                m[i] = b;
                match core::str::from_utf8(&m) {
                    Err(_) => continue,
                    Ok(s) => match parse(s) {
                        Ok(man) => {
                            parsed += 1;
                            // Anything that still parses must be internally consistent.
                            assert!(!man.files.is_empty());
                            assert_eq!(man.schema, 1);
                            check_base(&man.base).expect("a parsed base is a valid base");
                        }
                        Err(_) => rejected += 1,
                    },
                }
            }
        }
        // Both outcomes must actually occur, or this test is asserting nothing.
        assert!(
            rejected > 1000,
            "only {rejected} rejections — too few to be meaningful"
        );
        assert!(
            parsed > 0,
            "nothing parsed — the sweep is not exercising success"
        );
    }

    /// Truncation at every length, for the same reason: a censored or interrupted download hands
    /// this function a prefix.
    #[test]
    fn no_truncation_can_make_the_parser_panic() {
        for n in 0..GOOD.len() {
            if let Some(s) = GOOD.get(..n) {
                let _ = parse(s);
            }
        }
    }
}
