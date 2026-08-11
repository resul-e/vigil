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

/// The crates that must not be reachable from a binary every user runs.
const FORBIDDEN: &[&str] = &["vigil-update", "rustls", "minisign-verify"];

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
            in_deps = line.contains("dependencies]");
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

/// **`vigil-app.exe` and `vigil-repair.exe` must not link rustls, minisign, or the updater.**
///
/// `vigil-repair.exe` is the safety net — the thing that gets a machine's internet back when
/// everything else has gone wrong — and `vigil-app.exe` is what every user runs. Neither has any
/// business carrying a TLS stack or a signature verifier.
#[test]
fn the_shipped_gui_and_the_safety_net_do_not_reach_the_updater() {
    let g = graph();
    for crate_name in ["vigil-ui", "vigil-platform"] {
        let r = reachable(&g, crate_name);
        for bad in FORBIDDEN {
            assert!(
                !r.contains(*bad),
                "{crate_name} reaches {bad}. That is what `update/Cargo.toml`, `update/src/lib.rs` \
                 and docs/18-auto-update.md all promise it does not — vigil-app.exe and \
                 vigil-repair.exe are built from it. Reached: {r:?}"
            );
        }
    }
}

/// The direction is `update → proxy → platform`, never the reverse. Stated in two comments and,
/// until now, asserted nowhere.
#[test]
fn nothing_below_the_updater_depends_on_it() {
    let g = graph();
    for crate_name in ["vigil-core", "vigil-platform", "vigil-proxy"] {
        assert!(
            !reachable(&g, crate_name).contains("vigil-update"),
            "{crate_name} depends on vigil-update, which reverses the one direction this layering \
             has — and drags rustls and minisign into every binary built from it"
        );
    }
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
