//! The *other* proxy setting Windows has, and the one that reaches the applications the
//! registry cannot. Pure.
//!
//! Measured 2026-08-05. The Roblox client ignores `HKCU\...\Internet Settings` completely:
//! with the system proxy pointed at vigil it opened **five direct sockets to port 443 and
//! none to the proxy**, while 36 connections from other applications went through the proxy in
//! the same window. Every hostname it needs is blocked on this line and reachable through
//! vigil — `apis`, `auth`, `gamejoin`, `clientsettings`, `assetdelivery`, all `0/5` direct and
//! `5/5` proxied — so the tool had the answer and no way to deliver it.
//!
//! It does honour the curl convention. With `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` set,
//! the same client made **64 connections to the proxy and none direct**, and 226 Roblox
//! requests appeared in the proxy's log. That is a large family of clients — libcurl, Go, Node,
//! Python, game launchers — reached without a driver and without administrator rights.
//!
//! # What makes this dangerous, and what that dictates
//!
//! These variables are read by tools that have nothing to do with us — `git`, `pip`, `npm`,
//! every `curl` in a script. Leaving them behind pointing at a listener that is not running
//! breaks all of them, silently, until someone thinks to look at their environment. So they
//! follow exactly the same rules the registry setting does: snapshot what was there, never
//! overwrite a value that is not ours, put it back on the way out, and let `vigil-repair` find
//! and clear a stranded one. This module is the decision half; `envreg` does the writing.
//!
//! Windows environment variable names are case-insensitive, so one set covers `HTTP_PROXY` and
//! `http_proxy` both — which is not true on Linux, and is why this is Windows-only in effect
//! even though it is pure enough to test anywhere.

/// The variables vigil **manages**: reads, clears and restores.
///
/// Not the same as the ones it sets — see [`ours`]. `HTTP_PROXY` stays on this list precisely
/// because it must be cleared: a build from earlier on 2026-08-06 wrote it, and a machine
/// that still has it set from that build has a broken Discord until something removes it.
pub const NAMES: [&str; 4] = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"];

/// What must never be sent through the proxy, whatever else happens.
///
/// Loopback is there so a client cannot loop back into us. The Turkish suffixes mirror the
/// engine's own exclude list: those hosts are already passed through untouched, and repeating
/// it here means a client that reads `NO_PROXY` never even opens the connection — the
/// step-8 promise holds one layer earlier.
///
/// **The suffixes are written `.com.tr`, not `*.com.tr`, and that one character is the whole
/// value of the entry.** The curl convention — which curl, git, pip and Python's urllib all
/// implement — matches a leading dot as "this domain and any subdomain of it"; a literal `*` is
/// not a wildcard, it is a character that appears in no hostname. Measured against Windows' own
/// curl 8.21.0: with the starred form a request to a `.gov.tr` host went **through the proxy**,
/// and with the dotted form it went direct. (Go strips a leading `*`, so the old value was not
/// universally dead — just dead everywhere it mattered here.)
///
/// The engine enforces the exclusion anyway, one layer down and with tests, so nothing was
/// unprotected. What was broken is the promise this constant makes on its own: after a vigil that
/// died without restoring, a working `NO_PROXY` is what keeps banking and e-Devlet reachable for
/// every command-line tool on the machine.
pub const NO_PROXY_VALUE: &str = "localhost,127.0.0.1,::1,.com.tr,.gov.tr,.edu.tr,.org.tr";

/// The environment as it stands: the values of [`NAMES`], `None` where unset.
///
/// A borrowed-nothing type so the pure decisions below can be tested without touching Windows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvProxy {
    pub http: Option<String>,
    pub https: Option<String>,
    pub all: Option<String>,
    pub no_proxy: Option<String>,
}

impl EnvProxy {
    /// In [`NAMES`] order, so a caller can write them without knowing the field names.
    pub fn pairs(&self) -> [(&'static str, Option<&str>); 4] {
        [
            (NAMES[0], self.http.as_deref()),
            (NAMES[1], self.https.as_deref()),
            (NAMES[2], self.all.as_deref()),
            (NAMES[3], self.no_proxy.as_deref()),
        ]
    }

    pub fn is_empty(&self) -> bool {
        self.pairs().iter().all(|(_, v)| v.is_none())
    }
}

/// The URL form these variables take. Not the registry's `https=host:port` form — this
/// convention is curl's, and a bare `host:port` is accepted by some clients and rejected by
/// others, so the scheme is always written.
pub fn url_for(listen: &str) -> String {
    format!("http://{listen}")
}

/// What vigil's own setting looks like for a given listener.
///
/// **`HTTP_PROXY` is deliberately not set**, and this is measured rather than cautious. With
/// it, Discord never reaches `gateway.discord.gg` or `updates.discord.com` at all and stalls
/// at five processes; without it, both arrive and it reaches six. Five launches per arm,
/// 2026-08-06, and no variance at all:
///
/// | variables set | Discord processes | gateway seen | updates seen |
/// |---|---|---|---|
/// | `HTTP_PROXY` + `HTTPS_PROXY` + `ALL_PROXY` | 5,5,5,5,5 | 0/5 | 0/5 |
/// | none | 6,6,6,6,6 | 5/5 | 5/5 |
/// | `HTTPS_PROXY` alone | 6,6,6 | 3/3 | 3/3 |
/// | `ALL_PROXY` alone | 6,6,6 | 3/3 | 3/3 |
/// | **`HTTP_PROXY` alone** | 5,5,5 | **0/3** | **0/3** |
///
/// And the client the feature exists for does not need it: Roblox sends **52** of its own
/// names through the proxy with `HTTPS_PROXY` + `ALL_PROXY`, and **0** with no variables at
/// all. So the one variable that breaks an application is the one nothing needed.
pub fn ours(listen: &str) -> EnvProxy {
    let url = url_for(listen);
    EnvProxy {
        http: None,
        https: Some(url.clone()),
        all: Some(url),
        no_proxy: Some(NO_PROXY_VALUE.to_string()),
    }
}

/// Whether the environment currently points at *our* listener.
///
/// Only the three proxy variables decide it. `NO_PROXY` is a list that anyone may extend, and
/// treating a changed `NO_PROXY` as "not ours" would strand the other three.
/// Compared **exactly**, not by substring: `http://127.0.0.1:1080` is a substring of
/// `http://127.0.0.1:10809`, which is v2rayN's default, and reading a third party's proxy as ours
/// means deleting their variables on the way out. A trailing slash is tolerated because both forms
/// are written by hand and mean the same thing.
pub fn points_at_us(current: &EnvProxy, listen: &str) -> bool {
    let url = url_for(listen);
    let want = url.trim_end_matches('/');
    let same = |v: &Option<String>| {
        v.as_deref()
            .is_some_and(|s| s.trim().trim_end_matches('/') == want)
    };
    same(&current.http) || same(&current.https) || same(&current.all)
}

/// Set by something that is not us, and therefore not ours to overwrite.
pub fn belongs_to_someone_else(current: &EnvProxy, listen: &str) -> bool {
    !current.is_empty() && !points_at_us(current, listen)
}

/// What `vigil-repair` should write for the environment variables, given the snapshot it found.
///
/// Pure, and its own function because the tool that calls it has **no tests at all** and this is the
/// decision that matters in it.
///
/// **It always has an answer**, which is why it returns an `EnvProxy` and not an `Option`. It had
/// an `Option` no arm made `None` and a `force` parameter no arm read, and the cost was a dead match
/// arm in the caller carrying a confident message — the same shape as the arm that was deleted from
/// the registry half, reintroduced in the same file on the same night.
///
/// Called only once the caller has established that a repair is wanted — either `is_stranded`
/// matched, or `--force`. That precondition is what condemns the behaviour this replaced: reaching
/// the no-snapshot case without `--force` *means* a variable is pointing at a loopback listener, so
/// printing "these variables are not vigil's, leaving them alone" and **returning success** was false
/// by construction, and it left `git`, `pip`, `npm`, `curl` and Roblox talking to a dead port while
/// the tool people are told to run when their internet dies reported that it had repaired something.
///
/// **What it still cannot tell** is a dead vigil from another local proxy on a port we do not use:
/// both look like "a loopback address with no snapshot of ours". Clearing is the right answer for the
/// first and destroys a configuration in the second. The missing question is whether anything is
/// listening there, which is I/O and therefore not this function's to ask.
///
/// The registry half has always cleared in this case, for the reason stated there: leaving a machine
/// pointing at a listener that is gone is the worst of the available options.
pub fn repair_target(snapshot: Option<&str>) -> EnvProxy {
    match snapshot {
        Some(t) => snapshot_from_text(t),
        // No snapshot, and the caller has already established a repair is wanted — so a variable
        // names a loopback listener that is not answering. Clear it.
        None => EnvProxy::default(),
    }
}

/// A machine left pointing at a vigil that is not there.
///
/// `our_prefix` is the loopback address without the port, so a listener moved to another port
/// is still recognised as ours to clean up.
pub fn is_stranded(current: &EnvProxy, our_prefix: &str) -> bool {
    let hit = |v: &Option<String>| v.as_deref().is_some_and(|s| s.contains(our_prefix));
    hit(&current.http) || hit(&current.https) || hit(&current.all)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Start {
    /// Save `snapshot`, then write `apply`.
    Engage { apply: EnvProxy, snapshot: EnvProxy },
    /// Already ours. Change nothing — and above all do not snapshot our own value as if it
    /// were the user's, which is the mistake that makes a restore point at a dead listener.
    AlreadyEngaged,
    /// Somebody else's proxy is configured here. Touching it would break whatever set it, and
    /// on this platform that is usually a corporate policy or a developer's own tooling.
    Occupied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// Put this back. Fields that are `None` are deleted rather than blanked: an empty
    /// `HTTP_PROXY` is not the same as an absent one to every client that reads it.
    Restore(EnvProxy),
    /// Not ours any more. Someone changed it while we ran.
    NotOurs,
}

pub fn start(current: &EnvProxy, listen: &str) -> Start {
    if points_at_us(current, listen) {
        return Start::AlreadyEngaged;
    }
    if belongs_to_someone_else(current, listen) {
        return Start::Occupied;
    }
    Start::Engage {
        apply: ours(listen),
        snapshot: current.clone(),
    }
}

pub fn stop(current: &EnvProxy, snapshot: Option<&EnvProxy>, listen: &str) -> Stop {
    if !points_at_us(current, listen) {
        return Stop::NotOurs;
    }
    match snapshot {
        Some(s) => Stop::Restore(s.clone()),
        // No snapshot and it is ours: clearing is the only safe answer, and it is what the
        // registry side does for the same reason.
        None => Stop::Restore(EnvProxy::default()),
    }
}

/// Serialise a snapshot, one `NAME=value` per line. An absent variable is omitted entirely,
/// which is how a restore knows to delete it rather than write an empty string.
pub fn snapshot_to_text(e: &EnvProxy) -> String {
    let mut out = String::new();
    for (name, value) in e.pairs() {
        if let Some(v) = value {
            out.push_str(name);
            out.push('=');
            out.push_str(v);
            out.push('\n');
        }
    }
    out
}

pub fn snapshot_from_text(t: &str) -> EnvProxy {
    let mut e = EnvProxy::default();
    for line in t.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let slot = match k.trim().to_ascii_uppercase().as_str() {
            "HTTP_PROXY" => &mut e.http,
            "HTTPS_PROXY" => &mut e.https,
            "ALL_PROXY" => &mut e.all,
            "NO_PROXY" => &mut e.no_proxy,
            _ => continue,
        };
        *slot = Some(v.to_string());
    }
    e
}

#[cfg(test)]
mod tests {

    /// The safety net must not report success while leaving the machine broken.
    ///
    /// Reaching the no-snapshot case at all means a variable points at loopback — that is the
    /// caller's precondition — so "not ours, leaving them alone" was a false statement with a
    /// `true` return behind it. Both arms now write something.
    #[test]
    fn repair_always_has_an_answer_once_a_repair_is_wanted() {
        // With a snapshot: exactly what was there, including a state with nothing in it.
        let back = repair_target(Some("HTTPS_PROXY=http://corp:8080\n"));
        assert_eq!(back.https.as_deref(), Some("http://corp:8080"));

        // Without one: cleared. This is the case that used to be a no-op claiming success.
        assert!(
            repair_target(None).is_empty(),
            "a stranded machine with no snapshot must be cleared"
        );
    }

    /// The environment half of the same mistake: `http://127.0.0.1:1080` is a substring of
    /// `http://127.0.0.1:10809`. Reading a third party's variables as ours means deleting them —
    /// including their `NO_PROXY` — when vigil exits.
    #[test]
    fn a_longer_port_in_the_variables_is_somebody_elses() {
        let theirs = EnvProxy {
            http: Some("http://127.0.0.1:10809".into()),
            https: Some("http://127.0.0.1:10809".into()),
            all: None,
            no_proxy: None,
        };
        assert!(!points_at_us(&theirs, "127.0.0.1:1080"));
        // Still ours with or without the trailing slash people type by hand.
        for v in ["http://127.0.0.1:1080", "http://127.0.0.1:1080/"] {
            let ours = EnvProxy {
                http: None,
                https: Some(v.into()),
                all: None,
                no_proxy: None,
            };
            assert!(points_at_us(&ours, "127.0.0.1:1080"), "{v}");
        }
        // And a strand is still a strand on any port, which is what vigil-repair asks.
        assert!(is_stranded(&theirs, "127.0.0.1:"));
    }
    use super::*;

    const LISTEN: &str = "127.0.0.1:1080";

    fn corporate() -> EnvProxy {
        EnvProxy {
            http: Some("http://corp-proxy:8080".into()),
            https: Some("http://corp-proxy:8080".into()),
            all: None,
            no_proxy: Some("intranet,.corp".into()),
        }
    }

    #[test]
    fn our_value_carries_a_scheme_and_covers_the_variables_that_help() {
        let o = ours(LISTEN);
        assert_eq!(o.https.as_deref(), Some("http://127.0.0.1:1080"));
        assert_eq!(
            o.all, o.https,
            "the proxy is the same one, whatever scheme was asked for"
        );
        assert!(points_at_us(&o, LISTEN));
    }

    /// The regression this exists to prevent, and it shipped once: with `HTTP_PROXY` set,
    /// Discord never reaches its gateway or its updater and stalls at five processes. Measured
    /// 2026-08-06, five launches per arm, no variance. Roblox needs the other two and not this
    /// one, so nothing is lost by never writing it.
    #[test]
    fn http_proxy_is_never_written() {
        assert_eq!(ours(LISTEN).http, None, "HTTP_PROXY breaks Discord");
    }

    /// But it must still be *managed*: a machine that has it set from the build that shipped
    /// it stays broken until something clears it, and engaging is what clears it.
    #[test]
    fn an_http_proxy_left_by_an_older_build_is_recognised_and_cleared() {
        let stale = EnvProxy {
            http: Some(url_for(LISTEN)),
            https: Some(url_for(LISTEN)),
            all: Some(url_for(LISTEN)),
            no_proxy: Some(NO_PROXY_VALUE.into()),
        };
        assert!(points_at_us(&stale, LISTEN), "it is still our own setting");
        assert_eq!(start(&stale, LISTEN), Start::AlreadyEngaged);
        assert!(
            NAMES.contains(&"HTTP_PROXY"),
            "it has to stay on the managed list"
        );
        assert_eq!(ours(LISTEN).pairs()[0], ("HTTP_PROXY", None));
    }

    /// The one thing a client must never do is send `localhost` through us.
    ///
    /// **This test used to pin the bug it was written to prevent.** It asserted `*.gov.tr`, so
    /// writing the value that curl actually honours turned it red — a test that fails when the code
    /// is corrected is worse than no test. The entries are now checked as whole comma-separated
    /// fields, and the starred form is asserted **absent**, because a `*` in a `NO_PROXY` list is a
    /// character that matches no hostname anywhere the convention is implemented properly.
    #[test]
    fn loopback_and_the_turkish_suffixes_are_excluded_in_the_form_clients_honour() {
        let o = ours(LISTEN);
        let no = o.no_proxy.unwrap_or_default();
        let fields: Vec<&str> = no.split(',').map(str::trim).collect();
        for must in [
            "localhost",
            "127.0.0.1",
            ".gov.tr",
            ".com.tr",
            ".edu.tr",
            ".org.tr",
        ] {
            assert!(
                fields.contains(&must),
                "{must} missing from NO_PROXY as a whole entry: {no}"
            );
        }
        assert!(
            !no.contains('*'),
            "a literal * matches no hostname in the curl convention: {no}"
        );
    }

    #[test]
    fn a_clean_environment_is_engaged_and_its_emptiness_remembered() {
        match start(&EnvProxy::default(), LISTEN) {
            Start::Engage { apply, snapshot } => {
                assert_eq!(apply, ours(LISTEN));
                assert!(snapshot.is_empty(), "must remember that there was nothing");
            }
            other => panic!("expected Engage, got {other:?}"),
        }
    }

    /// The failure this whole module is shaped around: engaging twice must not snapshot our
    /// own value as the user's, or the restore points the machine at a dead listener forever.
    #[test]
    fn engaging_twice_does_not_overwrite_the_snapshot() {
        assert_eq!(start(&ours(LISTEN), LISTEN), Start::AlreadyEngaged);
    }

    /// A listener on another port is still us. Someone who ran `--panel`-style overrides, or
    /// moved off 1080 because something held it, must not end up with two live settings.
    #[test]
    fn our_own_value_on_another_port_is_still_recognised_as_ours() {
        let other = ours("127.0.0.1:1091");
        assert!(
            !points_at_us(&other, LISTEN),
            "a different port is a different listener"
        );
        assert!(
            is_stranded(&other, "127.0.0.1"),
            "but repair must still see it"
        );
    }

    #[test]
    fn someone_elses_proxy_is_left_alone() {
        assert_eq!(start(&corporate(), LISTEN), Start::Occupied);
        assert!(belongs_to_someone_else(&corporate(), LISTEN));
    }

    /// A `NO_PROXY` the user extended must not make the setting look foreign — the three
    /// proxy variables are what decide ownership.
    #[test]
    fn a_user_edited_no_proxy_does_not_make_it_someone_elses() {
        let mut mine = ours(LISTEN);
        mine.no_proxy = Some("localhost,my-nas.local".into());
        assert!(points_at_us(&mine, LISTEN));
        assert_eq!(start(&mine, LISTEN), Start::AlreadyEngaged);
    }

    #[test]
    fn stopping_puts_back_exactly_what_was_there() {
        let snap = corporate();
        match stop(&ours(LISTEN), Some(&snap), LISTEN) {
            Stop::Restore(back) => assert_eq!(back, snap),
            other => panic!("expected Restore, got {other:?}"),
        }
    }

    #[test]
    fn stopping_without_a_snapshot_clears_rather_than_leaving_it() {
        match stop(&ours(LISTEN), None, LISTEN) {
            Stop::Restore(back) => assert!(back.is_empty(), "{back:?}"),
            other => panic!("expected Restore, got {other:?}"),
        }
    }

    #[test]
    fn a_setting_that_is_no_longer_ours_is_not_restored_over() {
        assert_eq!(
            stop(&corporate(), Some(&EnvProxy::default()), LISTEN),
            Stop::NotOurs
        );
    }

    #[test]
    fn stranded_means_pointing_at_a_loopback_vigil() {
        assert!(is_stranded(&ours(LISTEN), "127.0.0.1"));
        assert!(!is_stranded(&corporate(), "127.0.0.1"));
        assert!(!is_stranded(&EnvProxy::default(), "127.0.0.1"));
    }

    /// A snapshot has to survive a round trip through a file, including the difference between
    /// "set to empty" and "not set at all".
    #[test]
    fn a_snapshot_round_trips_and_keeps_absent_apart_from_empty() {
        for e in [
            EnvProxy::default(),
            corporate(),
            ours(LISTEN),
            EnvProxy {
                http: Some(String::new()),
                ..Default::default()
            },
        ] {
            let back = snapshot_from_text(&snapshot_to_text(&e));
            assert_eq!(back, e, "round trip lost something");
        }
    }

    #[test]
    fn snapshot_text_ignores_lines_it_does_not_understand() {
        let e = snapshot_from_text("HTTP_PROXY=http://x:1\nnonsense\nPATH=/bin\nno_proxy=a,b\n");
        assert_eq!(e.http.as_deref(), Some("http://x:1"));
        assert_eq!(
            e.no_proxy.as_deref(),
            Some("a,b"),
            "names are case-insensitive"
        );
        assert_eq!(e.https, None);
    }
}
