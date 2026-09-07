//! **The claim three places in this repository make, finally checked.**
//!
//! `update/Cargo.toml`, `update/src/lib.rs` and `docs/18-auto-update.md` all say that `vigil-update`
//! is the only crate that links rustls and a signature verifier, that neither ever reaches
//! `vigil-app.exe` or `vigil-repair.exe`, and — in two of the three — that *a test asserts it*.
//! No such test existed. The third names a mechanism, "a test over `cargo tree`", that appears
//! nowhere in the tree.
//!
//! Nothing is wrong today; `ui` and `platform` are both clean. The defect was the unkept promise
//! and the missing guard, and the exposure is wider than it looks: adding `vigil-update` to
//! `proxy/` or `core/` reaches `vigil-app.exe` just as surely as adding it to `ui/`, and that is
//! the cheaper edit for somebody to make by accident.
//!
//! # Why a graph walk and not a grep
//!
//! Checking `ui/Cargo.toml` and `platform/Cargo.toml` for the strings "rustls" and "vigil-update"
//! is green under the `proxy -> update` edge — a test written where the symptom would be noticed
//! rather than where the decision lives. It would also match on *comment* text, so the day somebody
//! explains in a comment why rustls is absent, the guard fails for the wrong reason.
//!
//! So: parse every member manifest, build the edge set, and walk it. Pure, no OS, no nested cargo,
//! runs on Linux in microseconds.

use std::collections::{BTreeMap, BTreeSet};

/// Every workspace member, by the name it is referred to as a path dependency.
const MEMBERS: &[(&str, &str)] = &[
    ("vigil-core", include_str!("../../core/Cargo.toml")),
    ("vigil-platform", include_str!("../../platform/Cargo.toml")),
    ("probe", include_str!("../../probe/Cargo.toml")),
    ("vigil-proxy", include_str!("../../proxy/Cargo.toml")),
    ("vigil-scan", include_str!("../../scan/Cargo.toml")),
    ("vigil-ui", include_str!("../../ui/Cargo.toml")),
    ("vigil-update", include_str!("../../update/Cargo.toml")),
];

/// **Exactly** what the safety net is allowed to reach.
///
/// An allowlist and not a forbidden list. A forbidden list is the set of things somebody
/// remembered; this is the set that is true. `vigil-repair.exe` is built from `platform/` and is
/// what gets a machine's internet back when everything else has gone wrong — it must stay small
/// and it must keep building when nothing else does.
///
/// The byte size is *not* asserted by this: the `windows` crate's feature list can grow the binary
/// with this set unchanged. That number belongs to the release gate.
const SAFETY_NET_MAY_REACH: &[&str] = &["windows", "winreg"];

/// The crates that may name rustls as a **direct** dependency.
///
/// Three doors, and no fourth. `vigil-ui` and `vigil-scan` reach TLS through `vigil-proxy` — that
/// is the intended path since the tax was paid on 2026-09-07 — but a fourth crate naming rustls
/// itself would be somebody writing a fifth TLS loop, and this project already has three.
const RUSTLS_DOORS: &[&str] = &["probe", "vigil-proxy", "vigil-update"];

/// The crates that may name the signature verifier. One, and there is no argument for a second.
///
/// The rule this file replaced listed `minisign-verify` among the forbidden names, and the
/// replacement nearly dropped it: the new rules covered the safety net exactly and rustls by door,
/// and nothing would have caught a `minisign-verify` added to `proxy/`, which reaches
/// `vigil-app.exe`. Noticed while writing the mutations for the new rules, which is what mutations
/// are for.
const MINISIGN_DOORS: &[&str] = &["vigil-update"];

/// Direct dependencies of one manifest: both `name = { path = ... }` and `name = "1.2"` /
/// `name.workspace = true` forms, from every `[dependencies]`-family table.
///
/// Comment lines are dropped first, which is the whole reason this is a parser and not a `contains`.
fn direct_deps(manifest: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut in_deps = false;
    for raw in manifest.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            // `[dependencies]`, `[dev-dependencies]`, `[target.'cfg(windows)'.dependencies]`, …
            let header = line.trim_start_matches('[').trim_end_matches(']').trim();
            in_deps = header.ends_with("dependencies");
            // **Cargo's dotted-table form, invisible here until 2026-09-07.**
            //
            // `[dependencies.rustls]` followed by `workspace = true` is exactly equivalent to
            // `rustls.workspace = true`, and this parser walked straight past it: the old test was
            // `line.contains("dependencies]")`, which is false for `[dependencies.rustls]` — so the
            // crate was never recorded *and* the section was closed, hiding everything after it
            // too. Every mutation anybody would think to write uses the one form the parser saw,
            // which is how a guard stays green whether or not it works.
            if let Some((_, name)) = header.rsplit_once("dependencies.") {
                let name = name.trim().trim_matches('"');
                if !name.is_empty() {
                    out.insert(name.to_string());
                }
            }
            continue;
        }
        if !in_deps {
            continue;
        }
        let Some((lhs, _)) = line.split_once('=') else {
            continue;
        };
        // `rustls.workspace = true` names the crate before the dot.
        let name = lhs.trim().split('.').next().unwrap_or("").trim();
        if !name.is_empty() {
            out.insert(name.to_string());
        }
    }
    out
}

fn graph() -> BTreeMap<String, BTreeSet<String>> {
    MEMBERS
        .iter()
        .map(|(name, src)| (name.to_string(), direct_deps(src)))
        .collect()
}

/// Everything `root` reaches, at any depth.
fn reachable(g: &BTreeMap<String, BTreeSet<String>>, root: &str) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut stack = vec![root.to_string()];
    while let Some(n) = stack.pop() {
        for d in g.get(&n).into_iter().flatten() {
            if seen.insert(d.clone()) {
                stack.push(d.clone());
            }
        }
    }
    seen
}

/// The parser has to actually see the edges, or every assertion below is vacuously true.
#[test]
fn the_manifests_parse_into_the_graph_we_expect() {
    let g = graph();
    assert!(
        g["vigil-proxy"].contains("rustls"),
        "the tax was paid on 2026-09-07: {:?}",
        g["vigil-proxy"]
    );
    assert!(
        g["vigil-update"].contains("rustls") && g["vigil-update"].contains("minisign-verify"),
        "update should link both: {:?}",
        g["vigil-update"]
    );
    assert!(g["vigil-proxy"].contains("vigil-platform"));
    assert!(g["vigil-ui"].contains("vigil-proxy"));
    assert!(
        g["vigil-core"].is_empty(),
        "core is supposed to have no dependencies at all: {:?}",
        g["vigil-core"]
    );
}

/// **The safety net reaches exactly two crates, and they are Windows API bindings.**
///
/// `vigil-repair.exe` is built from `platform/`. Asserted as an exact set rather than as an
/// absence of known-bad names: the day somebody adds a TLS stack, a logging framework or an
/// async runtime to `platform/`, this goes red without anybody having predicted that particular
/// crate. The old version could only refuse the three names it had been told about.
#[test]
fn the_safety_net_reaches_exactly_what_it_is_allowed_to() {
    let g = graph();
    let got = reachable(&g, "vigil-platform");
    let want: BTreeSet<String> = SAFETY_NET_MAY_REACH.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        got, want,
        "vigil-repair.exe is built from platform/ and is the thing that gets a machine's internet \
         back. Its dependency set changed."
    );
}

/// **The updater is reachable from nothing but itself.**
///
/// One assertion over every member, so a single mutation names every crate it reaches rather than
/// stopping at the first. `update → proxy → platform` is the one direction this layering has;
/// reversing it anywhere drags rustls and minisign into every binary built from that crate,
/// including `vigil-app.exe` and `vigil-repair.exe`.
#[test]
fn only_the_updater_reaches_the_updater() {
    let g = graph();
    let offenders: Vec<&str> = MEMBERS
        .iter()
        .map(|(n, _)| *n)
        .filter(|n| *n != "vigil-update")
        .filter(|n| reachable(&g, n).contains("vigil-update"))
        .collect();
    assert!(
        offenders.is_empty(),
        "these reach vigil-update: {offenders:?}. That reverses the layering and puts rustls and \
         a signature verifier into every binary built from them."
    );
}

/// **rustls has exactly three doors.**
///
/// Since 2026-09-07 `vigil-proxy` is one of them, deliberately: the resolver speaks DoH and DoH is
/// TLS. `vigil-ui` and `vigil-scan` reach it *through* the proxy, which is the intended path and
/// is why this checks direct dependencies rather than reachability. A fourth door would be a
/// fourth hand-rolled TLS loop, and three is already two more than anybody wants to maintain.
#[test]
fn rustls_has_exactly_three_doors() {
    let g = graph();
    for (name, _) in MEMBERS {
        let direct = g[*name].contains("rustls");
        let expected = RUSTLS_DOORS.contains(name);
        assert_eq!(
            direct, expected,
            "{name} names rustls directly = {direct}, expected {expected}. The doors are \
             {RUSTLS_DOORS:?} — everything else reaches TLS through vigil-proxy."
        );
    }
}

/// The signature verifier has exactly one door, for the same reason rustls has three.
#[test]
fn the_signature_verifier_has_exactly_one_door() {
    let g = graph();
    for (name, _) in MEMBERS {
        let direct = g[*name].contains("minisign-verify");
        let expected = MINISIGN_DOORS.contains(name);
        assert_eq!(
            direct, expected,
            "{name} names minisign-verify directly = {direct}, expected {expected}"
        );
    }
    // And nothing reaches it but the updater itself.
    let offenders: Vec<&str> = MEMBERS
        .iter()
        .map(|(n, _)| *n)
        .filter(|n| *n != "vigil-update")
        .filter(|n| reachable(&g, n).contains("minisign-verify"))
        .collect();
    assert!(
        offenders.is_empty(),
        "these reach minisign-verify: {offenders:?}"
    );
}

/// The parser must see Cargo's dotted-table form, or every rule above is vacuously true for
/// anybody who writes their dependency the other way. It could not until 2026-09-07.
#[test]
fn the_parser_sees_cargos_dotted_table_form() {
    let dotted = "[dependencies.rustls]\nworkspace = true\n";
    assert!(
        direct_deps(dotted).contains("rustls"),
        "`[dependencies.rustls]` is exactly equivalent to `rustls.workspace = true` and must be \
         seen as the same edge: {:?}",
        direct_deps(dotted)
    );
    let targeted = "[target.'cfg(windows)'.dependencies.rustls]\nworkspace = true\n";
    assert!(
        direct_deps(targeted).contains("rustls"),
        "{:?}",
        direct_deps(targeted)
    );
    // And the plain forms still work, or the fix broke what it was protecting.
    assert!(direct_deps("[dependencies]\nrustls.workspace = true\n").contains("rustls"));
    assert!(direct_deps("[dependencies]\nfoo = { path = \"../foo\" }\n").contains("foo"));
    // A table that is not a dependency table must not contribute a name.
    assert!(direct_deps("[package.metadata.rustls]\nx = 1\n").is_empty());
}

/// Every workspace member is in the graph, so a crate added tomorrow cannot be invisible to every
/// rule above by simply not being listed.
#[test]
fn every_workspace_member_is_in_the_graph() {
    let root = include_str!("../../Cargo.toml");
    let line = root
        .lines()
        .find(|l| l.trim_start().starts_with("members"))
        .expect("the workspace lists its members");
    for member in line
        .split('[')
        .nth(1)
        .unwrap_or("")
        .trim_end_matches(']')
        .split(',')
    {
        let dir = member.trim().trim_matches('"');
        if dir.is_empty() {
            continue;
        }
        assert!(
            MEMBERS
                .iter()
                .any(|(_, src)| src.contains(&format!("path = \"../{dir}\""))
                    || crate_dir_matches(dir)),
            "workspace member {dir:?} is not represented in MEMBERS, so no rule in this file \
             covers it"
        );
    }
}

/// `MEMBERS` names crates; the workspace names directories. This maps the ones that differ.
fn crate_dir_matches(dir: &str) -> bool {
    let want = match dir {
        "core" => "vigil-core",
        "platform" => "vigil-platform",
        "probe" => "probe",
        "proxy" => "vigil-proxy",
        "scan" => "vigil-scan",
        "ui" => "vigil-ui",
        "update" => "vigil-update",
        _ => return false,
    };
    MEMBERS.iter().any(|(n, _)| *n == want)
}

/// `core/` and `probe/` are required to have no OS-specific dependencies, because the fast test
/// loop runs on Linux. `core` is stricter still: no dependencies at all.
#[test]
fn core_stays_dependency_free() {
    let g = graph();
    assert!(
        reachable(&g, "vigil-core").is_empty(),
        "vigil-core gained a dependency: {:?}",
        reachable(&g, "vigil-core")
    );
}
