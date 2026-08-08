//! Turning the system proxy on when vigil starts, and off when it stops. Pure.
//!
//! `sysproxy` decides *what* a setting should say. This decides *whether to touch it at all*,
//! which is a different question and the one that strands machines.
//!
//! Three cases matter, and every one of them has left someone without internet in some tool:
//!
//! 1. **We are already engaged.** vigil crashed and was restarted while its own setting was
//!    still live. Snapshotting `https=127.0.0.1:1080` as "what was there before" and later
//!    restoring it points the machine at a proxy that is not running — permanently, and the
//!    restore *looks* like it worked. The existing snapshot must be kept instead.
//! 2. **Someone else's proxy is configured.** A corporate or another tool's setting must be
//!    snapshotted and put back exactly, including a disabled-but-populated state.
//! 3. **The user changed it while we ran.** If the live setting is no longer ours, restoring
//!    our snapshot would undo their change. We leave it alone.

use crate::sysproxy::{disabled, points_at_us, settings_for, ProxySettings};

/// What to do at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Start {
    /// Save `snapshot`, then write `apply`.
    Engage {
        apply: ProxySettings,
        snapshot: ProxySettings,
    },
    /// The system already points at our listener. Change nothing, and — critically — do not
    /// overwrite whatever snapshot is already on disk.
    AlreadyEngaged,
}

/// What to do at shutdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// Write this back.
    Restore(ProxySettings),
    /// The live setting is not ours any more. Someone changed it while we ran; putting our
    /// snapshot back would silently undo them.
    NotOurs,
}

/// Decide what startup should do, given what is configured now.
pub fn start(current: &ProxySettings, listen: &str) -> Start {
    if points_at_us(current, listen) {
        return Start::AlreadyEngaged;
    }
    Start::Engage {
        apply: settings_for(listen),
        snapshot: current.clone(),
    }
}

/// Decide what shutdown should do.
///
/// A missing snapshot is not a reason to leave the proxy engaged: without one we cannot know
/// what was there before, but we do know that leaving the machine pointing at a listener that
/// is about to stop is the worst of the available options. Disabling is the same fallback
/// `vigil-repair` uses.
pub fn stop(current: &ProxySettings, snapshot: Option<&ProxySettings>, listen: &str) -> Stop {
    if !points_at_us(current, listen) {
        return Stop::NotOurs;
    }
    match snapshot {
        Some(s) => Stop::Restore(s.clone()),
        None => Stop::Restore(disabled()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTEN: &str = "127.0.0.1:1080";

    fn nothing() -> ProxySettings {
        ProxySettings::default()
    }

    fn ours() -> ProxySettings {
        settings_for(LISTEN)
    }

    fn corporate() -> ProxySettings {
        ProxySettings {
            enabled: true,
            server: "http=corp-proxy:8080;https=corp-proxy:8080".into(),
            bypass: "intranet;*.corp".into(),
        }
    }

    // ------------------------------------------------------------------ startup

    #[test]
    fn a_clean_machine_is_engaged_and_its_emptiness_is_snapshotted() {
        match start(&nothing(), LISTEN) {
            Start::Engage { apply, snapshot } => {
                assert_eq!(apply, settings_for(LISTEN));
                assert_eq!(snapshot, nothing(), "must remember that there was nothing");
            }
            other => panic!("expected Engage, got {other:?}"),
        }
    }

    #[test]
    fn someone_elses_proxy_is_snapshotted_before_being_replaced() {
        match start(&corporate(), LISTEN) {
            Start::Engage { apply, snapshot } => {
                assert_eq!(apply, settings_for(LISTEN));
                assert_eq!(snapshot, corporate());
            }
            other => panic!("expected Engage, got {other:?}"),
        }
    }

    /// The one that strands a machine forever. Restarting while our own setting is live must
    /// not record `https=127.0.0.1:1080` as "what was there before" — restoring that later
    /// points the machine at a proxy that is not running, and the restore looks successful.
    #[test]
    fn restarting_while_already_engaged_never_snapshots_our_own_setting() {
        assert_eq!(start(&ours(), LISTEN), Start::AlreadyEngaged);
    }

    /// Same trap, reached through an older build's value.
    #[test]
    fn a_legacy_setting_of_ours_is_also_recognised_as_already_engaged() {
        for server in ["socks=127.0.0.1:1080", "127.0.0.1:1080"] {
            let legacy = ProxySettings {
                enabled: true,
                server: server.into(),
                bypass: String::new(),
            };
            assert_eq!(start(&legacy, LISTEN), Start::AlreadyEngaged, "{server}");
        }
    }

    /// Disabled but still naming us is *not* engaged: nothing is being routed, so this is a
    /// leftover value and the honest thing is to snapshot it and turn ourselves on.
    #[test]
    fn a_disabled_setting_naming_us_is_not_treated_as_engaged() {
        let leftover = ProxySettings {
            enabled: false,
            server: "https=127.0.0.1:1080".into(),
            bypass: String::new(),
        };
        match start(&leftover, LISTEN) {
            Start::Engage { snapshot, .. } => assert_eq!(snapshot, leftover),
            other => panic!("expected Engage, got {other:?}"),
        }
    }

    /// A different vigil on a different port is somebody else as far as we are concerned.
    #[test]
    fn another_instance_on_another_port_is_not_us() {
        let other = ProxySettings {
            enabled: true,
            server: "https=127.0.0.1:9999".into(),
            bypass: String::new(),
        };
        match start(&other, LISTEN) {
            Start::Engage { snapshot, .. } => assert_eq!(snapshot, other),
            other => panic!("expected Engage, got {other:?}"),
        }
    }

    // ----------------------------------------------------------------- shutdown

    #[test]
    fn shutdown_restores_exactly_what_was_snapshotted() {
        for previous in [nothing(), corporate()] {
            assert_eq!(
                stop(&ours(), Some(&previous), LISTEN),
                Stop::Restore(previous.clone()),
                "{previous:?}"
            );
        }
    }

    /// Losing the snapshot must not mean leaving the machine pointing at a dead listener.
    #[test]
    fn a_lost_snapshot_falls_back_to_disabling_rather_than_leaving_it_engaged() {
        assert_eq!(stop(&ours(), None, LISTEN), Stop::Restore(disabled()));
    }

    /// If the user pointed the machine somewhere else while we were running, restoring our
    /// snapshot would silently undo them.
    #[test]
    fn shutdown_leaves_a_setting_that_is_no_longer_ours_alone() {
        assert_eq!(stop(&corporate(), Some(&nothing()), LISTEN), Stop::NotOurs);
        assert_eq!(stop(&nothing(), Some(&corporate()), LISTEN), Stop::NotOurs);
    }

    // ------------------------------------------------------------- round trips

    /// The property that matters: start then stop puts the machine back exactly as found,
    /// whatever it was found as.
    #[test]
    fn start_then_stop_is_the_identity() {
        for before in [
            nothing(),
            corporate(),
            ProxySettings {
                enabled: false,
                server: "leftover:9999".into(),
                bypass: String::new(),
            },
            ProxySettings {
                enabled: true,
                server: "https=10.0.0.1:3128".into(),
                bypass: "<local>".into(),
            },
        ] {
            let Start::Engage { apply, snapshot } = start(&before, LISTEN) else {
                panic!("{before:?} should engage");
            };
            // `apply` is now live; shutting down from there must reproduce `before`.
            assert_eq!(
                stop(&apply, Some(&snapshot), LISTEN),
                Stop::Restore(before.clone()),
                "round trip changed {before:?}"
            );
        }
    }

    /// And a crash-restart-stop cycle must also land on the original, not on our own setting.
    #[test]
    fn crash_restart_then_stop_still_restores_the_original() {
        let before = corporate();
        let Start::Engage { apply, snapshot } = start(&before, LISTEN) else {
            panic!("should engage");
        };
        // vigil dies here; the snapshot survives on disk. It starts again:
        assert_eq!(start(&apply, LISTEN), Start::AlreadyEngaged);
        // and the snapshot on disk is still the original, so shutdown restores it.
        assert_eq!(stop(&apply, Some(&snapshot), LISTEN), Stop::Restore(before));
    }
}
