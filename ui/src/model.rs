//! What the interface says, and where its pieces go. Pure — no windows, no pixels, no clock.
//!
//! Everything a person sees is decided here and tested on Linux: which menu items exist and
//! when they are usable, what the tooltip reads, how a popup is placed so it cannot fall off
//! a screen, and which command a click means. The Win32 layer does none of that thinking; it
//! creates a window at the coordinates this module hands it.

use core::fmt;

use crate::lang::{t, tf, Lang};

/// Everything the interface shows, taken from the running proxy in one go.
///
/// A snapshot rather than live references, so the interface can never hold a lock while it
/// paints — and so every rendering function below is a pure function of its input.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// The proxy's own address, e.g. `127.0.0.1:1080`.
    pub listen: String,
    /// Whether the system proxy currently points at us.
    pub engaged: bool,
    /// Whether the listener is actually up. Engaged-but-not-listening is the state that
    /// strands a machine, and it is the one the interface must shout about.
    pub listening: bool,
    pub mode: Mode,
    pub accepted: usize,
    pub completed: usize,
    pub transformed: usize,
    pub excluded: usize,
    pub handshake_errors: usize,
    pub upstream_errors: usize,
    pub dns_failures: usize,
    /// First flights re-sent after a reset. See `proxy::Stats::first_flight_retries`.
    pub first_flight_retries: usize,
    /// Whether vigil is answering DNS on loopback at all.
    pub dns_serving: bool,
    /// Whether Windows' own resolver is pointed at us.
    pub dns_engaged: bool,
    pub by_socks5: usize,
    pub by_socks4: usize,
    pub by_http_connect: usize,
    /// Whether vigil is registered to start with Windows.
    pub autostart: bool,
    /// `(host, strategy)` pairs the calibrator has settled on.
    pub learned: Vec<(String, String)>,
    pub exclude_patterns: Vec<String>,
    /// The running version, as a string — `env!("CARGO_PKG_VERSION")` from whoever built the
    /// snapshot. Held rather than read here so this module stays a pure function of its input.
    pub version: String,
    /// Where the update machinery has got to.
    pub update: UpdateState,
    /// Whether automatic checking is switched on. Separate from [`UpdateState::Off`] because the
    /// menu tick has to reflect the preference even while a manual check is running.
    pub auto_update: bool,
    /// When a check last completed, already rendered — the model has no clock.
    pub last_check: String,
    /// Which language to say all of it in. Decided once at startup from the operating system
    /// (`vigil_platform::locale`), carried in the snapshot so every rendering function below
    /// stays a pure function of its input — including the language.
    pub lang: Lang,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Mode {
    /// Learning a strategy per host.
    #[default]
    Auto,
    /// One strategy for everything.
    Fixed(String),
}

impl Mode {
    /// How the mode is named on screen. `Auto` is a word and gets translated; a strategy spec
    /// is a strategy spec in every language.
    pub fn label(&self, lang: Lang) -> String {
        match self {
            Mode::Auto => t(lang, "mode.auto").to_string(),
            Mode::Fixed(s) => s.clone(),
        }
    }
}

impl fmt::Display for Mode {
    /// The machine-readable form, used in logs and by the command line. Never shown in the
    /// interface — that is [`Mode::label`], which knows what language the user reads.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mode::Auto => f.write_str("auto"),
            Mode::Fixed(s) => f.write_str(s),
        }
    }
}

/// How the tool is doing, in one word. Drives the icon and the first line of every view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// Engaged and listening.
    Protecting,
    /// Listening, but the system is not pointed at us. Harmless.
    Idle,
    /// The system points at us and we are **not** listening. This is the state that leaves a
    /// machine with no internet, and it must never be displayed as merely "off".
    Stranded,
}

impl Health {
    pub fn of(s: &Snapshot) -> Health {
        match (s.engaged, s.listening) {
            (true, true) => Health::Protecting,
            (true, false) => Health::Stranded,
            (false, _) => Health::Idle,
        }
    }

    pub fn label(self, lang: Lang) -> &'static str {
        match self {
            Health::Protecting => t(lang, "health.protecting"),
            Health::Idle => t(lang, "health.idle"),
            Health::Stranded => t(lang, "health.stranded"),
        }
    }
}

/// Where the update machinery has got to.
///
/// Ten states, and the reason there are ten rather than three is that the interesting ones are the
/// failures. "No update" and "could not look" are the same to a naive design and completely
/// different to a user on a line that may be blocking the download — one means nothing to do, the
/// other means the tool has quietly stopped receiving fixes. Every one of these says something a
/// person could act on.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum UpdateState {
    /// The user switched checking off.
    Off,
    #[default]
    NeverChecked,
    Checking,
    UpToDate,
    /// Newer version offered, not yet downloaded.
    Available {
        version: String,
        critical: bool,
    },
    /// Downloaded, signature verified, waiting for the user to say yes.
    ///
    /// Carries `critical` because a staged urgent update is still urgent. It did not, so an update
    /// marked critical lost that fact the moment it finished downloading — which is the only moment
    /// it matters, since that is when the user is asked.
    Staged {
        version: String,
        critical: bool,
    },
    /// The check itself failed. On this line that is a finding, not a shrug.
    Unreachable {
        why: String,
    },
    /// The program folder cannot be written to — a zip opened in Explorer, a read-only directory.
    /// The honest answer is "download it yourself", and it should be said early.
    FolderNotWritable,
    /// A build with no keys compiled in. Reported as its own thing: "cannot verify" is not the same
    /// claim as "not genuine".
    NoKeys,
    /// An apply stopped part-way. The folder is safe — the ordering guarantees that — and the next
    /// start offers to finish.
    Interrupted,
}

impl UpdateState {
    /// Is there something the user can click to move this forward?
    pub fn actionable(&self) -> bool {
        matches!(
            self,
            UpdateState::Available { .. } | UpdateState::Staged { .. } | UpdateState::Interrupted
        )
    }

    /// Should the tray icon draw attention to itself? Only for the one case that is genuinely
    /// urgent — a critical update — because an indicator that is always on is an indicator nobody
    /// reads.
    pub fn wants_attention(&self) -> bool {
        matches!(
            self,
            UpdateState::Available { critical: true, .. }
                | UpdateState::Staged { critical: true, .. }
        )
    }

    /// The one line the details window shows.
    pub fn line(&self, lang: Lang) -> String {
        match self {
            UpdateState::Off => t(lang, "update.off").into(),
            UpdateState::NeverChecked => t(lang, "update.never_checked").into(),
            UpdateState::Checking => t(lang, "update.checking").into(),
            UpdateState::UpToDate => t(lang, "update.up_to_date").into(),
            UpdateState::Available { version, critical } => tf(
                lang,
                if *critical {
                    "update.critical"
                } else {
                    "update.available"
                },
                &[("version", version)],
            ),
            UpdateState::Staged { version, critical } => tf(
                lang,
                if *critical {
                    "update.staged_critical"
                } else {
                    "update.staged"
                },
                &[("version", version)],
            ),
            UpdateState::Unreachable { why } => tf(lang, "update.unreachable", &[("why", why)]),
            UpdateState::FolderNotWritable => t(lang, "update.folder_readonly").into(),
            UpdateState::NoKeys => t(lang, "update.no_keys").into(),
            UpdateState::Interrupted => t(lang, "update.interrupted").into(),
        }
    }

    /// Read the one line `vigil-update.exe --check` prints.
    ///
    /// The two programs are deliberately separate — linking the updater into the tray application
    /// would put rustls inside the binary every user runs — so this line of text is the whole
    /// contract between them, and this is the parser for it.
    ///
    /// Anything it does not recognise becomes [`UpdateState::Unreachable`] carrying what was said.
    /// Not `UpToDate`: a status this build cannot read is a reason to tell the user something is
    /// wrong, and the one thing it must never do is quietly claim everything is fine.
    pub fn from_status_line(line: &str) -> UpdateState {
        let mut status = "";
        let mut version = String::new();
        let mut critical = false;
        let mut why = String::new();
        for field in line.split_whitespace() {
            match field.split_once('=') {
                Some(("status", v)) => status = v,
                Some(("version", v)) => version = v.to_string(),
                Some(("critical", v)) => critical = v == "1",
                Some(("why", v)) => why = v.replace('_', " "),
                _ => {}
            }
        }
        match status {
            "current" => UpdateState::UpToDate,
            "available" if !version.is_empty() => UpdateState::Available { version, critical },
            "staged" if !version.is_empty() => UpdateState::Staged { version, critical },
            // An apply that stopped part way. The bytes are staged and verified and some files are
            // already replaced, so the only useful thing to offer is "finish it" — and until this
            // arm existed, `Interrupted` was a state the interface could display and nothing could
            // ever produce, so a half-updated folder reported itself up to date instead.
            "interrupted" => UpdateState::Interrupted,
            "readonly" => UpdateState::FolderNotWritable,
            "nokeys" => UpdateState::NoKeys,
            "unreachable" | "badsig" | "badmanifest" | "untrusted" => UpdateState::Unreachable {
                why: if why.is_empty() {
                    status.to_string()
                } else {
                    why
                },
            },
            // Including the empty string, which is what a crashed or missing updater leaves.
            other => UpdateState::Unreachable {
                why: if other.is_empty() {
                    "no answer from the updater".into()
                } else {
                    other.to_string()
                },
            },
        }
    }

    /// The label for the menu item that acts on this state, when there is one.
    pub fn action_label(&self, lang: Lang) -> Option<String> {
        match self {
            UpdateState::Available { version, .. } | UpdateState::Staged { version, .. } => {
                Some(tf(lang, "update.install_now", &[("version", version)]))
            }
            UpdateState::Interrupted => Some(t(lang, "update.interrupted").into()),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------- commands

/// Everything a click can mean. The Win32 layer turns a menu id or a button into one of
/// these and hands it back; it never decides what a click does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Read the interface in another language, and remember the choice.
    SetLang(Lang),
    /// Look for an update now.
    CheckForUpdates,
    /// Install what is staged, or resume an interrupted apply.
    InstallUpdate,
    /// Switch automatic checking on or off, and remember it.
    ToggleAutoUpdate,
    /// Engage or disengage the system proxy.
    Toggle,
    ShowMini,
    ShowFull,
    /// Put the system proxy back the way it was found.
    Repair,
    Quit,
    /// Drop one learned strategy so the calibrator starts over for that host.
    Forget(String),
    ForgetAll,
    /// Register or unregister vigil to start with Windows.
    ToggleAutostart,
    /// Switch what the proxy does with the first flight, from now on.
    SetMode(Mode),
    /// Point Windows' own resolver at vigil, or put it back. Needs administrator rights, and
    /// Windows asks for them.
    ToggleSystemDns,
}

/// What the menu offers, in order: a label and the strategy spec behind it, `None` meaning
/// "learn per host".
///
/// Every entry is a measured position rather than a knob for its own sake. `tlsrec:64+split:1`
/// is 10/10 on both networks measured so far and is the shipped default; `split:1` is 20/20 on
/// Türk Telekom and **0/10** on Superonline; `tlsrec:64` is the one Superonline yields to. The
/// last entry turns the transform off without stopping the proxy, which is what tells a user
/// whether vigil is the thing breaking a site.
pub const MODES: &[(&str, Option<&str>)] = &[
    ("menu.mode_auto", None),
    ("menu.mode_default", Some("tlsrec:64+split:1")),
    ("menu.mode_split", Some("split:1")),
    ("menu.mode_tlsrec", Some("tlsrec:64")),
    ("menu.mode_passthrough", Some("none")),
];

/// The languages the menu offers, in order. Ticked like the modes are, because it is the same
/// kind of choice: one of a short list, and the tick is the only thing that says which.
///
/// Each entry is a key and the language it selects. Both labels are written in their **own**
/// language and never translated — a person looking for English should not have to already read
/// Turkish to find it, and the reverse.
pub const LANGS: &[(&str, Lang)] = &[("lang.tr", Lang::Turkish), ("lang.en", Lang::English)];

/// The language an entry of [`LANGS`] means.
pub fn lang_at(i: usize) -> Option<Lang> {
    LANGS.get(i).map(|(_, l)| *l)
}

/// The mode an entry of [`MODES`] means.
pub fn mode_at(i: usize) -> Option<Mode> {
    MODES.get(i).map(|(_, spec)| match spec {
        None => Mode::Auto,
        Some(s) => Mode::Fixed((*s).to_string()),
    })
}

/// Menu item ids. Fixed numbers because Win32 menus speak in `u16`, and because a test can
/// then assert that the mapping never drifts.
pub mod id {
    pub const TOGGLE: u16 = 0x100;
    pub const MINI: u16 = 0x101;
    pub const FULL: u16 = 0x102;
    pub const REPAIR: u16 = 0x103;
    pub const QUIT: u16 = 0x104;
    pub const FORGET_ALL: u16 = 0x105;
    pub const AUTOSTART: u16 = 0x106;
    pub const SYSDNS: u16 = 0x107;
    pub const CHECK_UPDATE: u16 = 0x108;
    pub const INSTALL_UPDATE: u16 = 0x109;
    pub const AUTO_UPDATE: u16 = 0x10A;
    /// The language entries, in [`super::LANGS`] order. Between the modes and the learned
    /// hosts, and like the modes it must stay below `FORGET_BASE`.
    pub const LANG_BASE: u16 = 0x120;
    /// The mode entries take ids from here upward, in `MODES` order. Deliberately **below**
    /// `FORGET_BASE`: the forget ids are unbounded (one per learned host), so anything placed
    /// above them could collide once enough hosts are learned.
    pub const MODE_BASE: u16 = 0x110;
    /// Learned hosts get ids from here upward, in the order they appear.
    pub const FORGET_BASE: u16 = 0x200;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuItem {
    pub id: u16,
    pub label: String,
    pub enabled: bool,
    pub checked: bool,
    /// A separator carries no id and cannot be clicked.
    pub separator: bool,
}

impl MenuItem {
    fn item(id: u16, label: impl Into<String>, enabled: bool) -> MenuItem {
        MenuItem {
            id,
            label: label.into(),
            enabled,
            checked: false,
            separator: false,
        }
    }

    fn sep() -> MenuItem {
        MenuItem {
            id: 0,
            label: String::new(),
            enabled: false,
            checked: false,
            separator: true,
        }
    }
}

/// The tray icon's right-click menu.
pub fn context_menu(s: &Snapshot) -> Vec<MenuItem> {
    let health = Health::of(s);
    vec![
        MenuItem {
            checked: s.engaged,
            ..MenuItem::item(
                id::TOGGLE,
                if s.engaged {
                    t(s.lang, "menu.protect_off")
                } else {
                    t(s.lang, "menu.protect_on")
                },
                // Engaging is pointless when nothing is listening, and would be the very act
                // that strands the machine.
                s.listening,
            )
        },
        MenuItem::sep(),
        MenuItem::item(id::MINI, t(s.lang, "section.status"), true),
        MenuItem::item(id::FULL, t(s.lang, "menu.details"), true),
        MenuItem::sep(),
    ]
    .into_iter()
    // The current mode is ticked rather than written out somewhere else, so the one place
    // that says what the proxy is doing is the same place that changes it.
    .chain(MODES.iter().enumerate().map(|(i, (label, _))| MenuItem {
        checked: mode_at(i).as_ref() == Some(&s.mode),
        ..MenuItem::item(id::MODE_BASE + i as u16, t(s.lang, label), true)
    }))
    // The update block. The action item only exists when there is something to act on, so the menu
    // never offers a button that does nothing — and it is placed above the language and startup
    // entries because it is the only item here that can be time-sensitive.
    .chain(
        s.update
            .action_label(s.lang)
            .map(|label| MenuItem::item(id::INSTALL_UPDATE, label, true))
            .into_iter()
            .chain([
                MenuItem {
                    // Disabled while a check is in flight: pressing it again would start a second
                    // one, and two checks racing is how a manifest gets applied twice.
                    ..MenuItem::item(
                        id::CHECK_UPDATE,
                        if s.update == UpdateState::Checking {
                            t(s.lang, "update.checking")
                        } else {
                            t(s.lang, "update.check_now")
                        },
                        s.update != UpdateState::Checking,
                    )
                },
                MenuItem {
                    checked: s.auto_update,
                    ..MenuItem::item(id::AUTO_UPDATE, t(s.lang, "update.toggle_auto"), true)
                },
                MenuItem::sep(),
            ]),
    )
    .chain(LANGS.iter().enumerate().map(|(i, (key, l))| MenuItem {
        checked: *l == s.lang,
        ..MenuItem::item(id::LANG_BASE + i as u16, t(s.lang, key), true)
    }))
    .chain([
        MenuItem::sep(),
        MenuItem {
            checked: s.autostart,
            ..MenuItem::item(id::AUTOSTART, t(s.lang, "menu.autostart"), true)
        },
        // Offered only when we are actually answering DNS. Pointing the machine at a resolver
        // that is not listening is the one change here that takes *all* name resolution down,
        // and an item that can do that must not be clickable when it would.
        MenuItem {
            checked: s.dns_engaged,
            ..MenuItem::item(
                id::SYSDNS,
                if s.dns_engaged {
                    t(s.lang, "menu.dns_take_back")
                } else {
                    t(s.lang, "menu.dns_give")
                },
                s.dns_serving,
            )
        },
        MenuItem::sep(),
        // Only offered when there is something to repair, so it cannot be used to undo
        // settings vigil never touched.
        MenuItem::item(
            id::REPAIR,
            t(s.lang, "menu.repair"),
            health == Health::Stranded,
        ),
        MenuItem::sep(),
        MenuItem::item(id::QUIT, t(s.lang, "menu.quit"), true),
    ])
    .collect()
}

/// Which command a menu id means. `None` for ids we did not put there.
pub fn command_for(id: u16, learned: &[(String, String)]) -> Option<Command> {
    match id {
        id::TOGGLE => Some(Command::Toggle),
        id::MINI => Some(Command::ShowMini),
        id::FULL => Some(Command::ShowFull),
        id::REPAIR => Some(Command::Repair),
        id::QUIT => Some(Command::Quit),
        id::FORGET_ALL => Some(Command::ForgetAll),
        id::AUTOSTART => Some(Command::ToggleAutostart),
        id::SYSDNS => Some(Command::ToggleSystemDns),
        id::CHECK_UPDATE => Some(Command::CheckForUpdates),
        id::INSTALL_UPDATE => Some(Command::InstallUpdate),
        id::AUTO_UPDATE => Some(Command::ToggleAutoUpdate),
        n if n >= id::MODE_BASE && (n as usize) < id::MODE_BASE as usize + MODES.len() => {
            mode_at((n - id::MODE_BASE) as usize).map(Command::SetMode)
        }
        n if n >= id::LANG_BASE && (n as usize) < id::LANG_BASE as usize + LANGS.len() => {
            lang_at((n - id::LANG_BASE) as usize).map(Command::SetLang)
        }
        n if n >= id::FORGET_BASE => {
            let i = (n - id::FORGET_BASE) as usize;
            learned.get(i).map(|(h, _)| Command::Forget(h.clone()))
        }
        _ => None,
    }
}

// ------------------------------------------------------------------------------- text

/// Windows truncates a tray tooltip at 128 characters, silently. Anything we might say has
/// to fit, so it is cut here where a test can see it happen.
pub const TOOLTIP_MAX: usize = 127;

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

pub fn tooltip(s: &Snapshot) -> String {
    let body = match Health::of(s) {
        Health::Stranded => format!("vigil — {}", Health::Stranded.label(s.lang)),
        Health::Idle => tf(s.lang, "tooltip.off", &[("listen", &s.listen)]),
        Health::Protecting => tf(
            s.lang,
            "tooltip.on",
            &[
                ("strategy", &s.mode.label(s.lang)),
                ("connections", &s.accepted.to_string()),
                ("transformed", &s.transformed.to_string()),
            ],
        ),
    };
    // The one place `wants_attention` is consumed. It had none: the method existed, one test asserted
    // it, and no interface element ever asked — so a `critical=1` release, the whole point of the
    // flag, reached the user as an ordinary "there is an update" and nothing more. The tooltip is the
    // right consumer because it is what a user sees without clicking anything.
    let body = if s.update.wants_attention() {
        format!("{body}\n{}", t(s.lang, "tooltip.critical"))
    } else {
        body
    };
    clip(&body, TOOLTIP_MAX)
}

/// The one-line summary at the top of both windows.
pub fn status_line(s: &Snapshot) -> String {
    match Health::of(s) {
        Health::Stranded => Health::Stranded.label(s.lang).to_string(),
        Health::Idle => tf(s.lang, "status.off", &[("listen", &s.listen)]),
        Health::Protecting => tf(
            s.lang,
            "status.on",
            &[("listen", &s.listen), ("strategy", &s.mode.label(s.lang))],
        ),
    }
}

/// Label, value. What the mini window shows.
pub fn counters(s: &Snapshot) -> Vec<(String, String)> {
    vec![
        (
            t(s.lang, "section.connection").into(),
            s.accepted.to_string(),
        ),
        (
            t(s.lang, "counter.transformed").into(),
            s.transformed.to_string(),
        ),
        (
            t(s.lang, "section.learned_host").into(),
            s.learned.len().to_string(),
        ),
    ]
}

/// The fuller breakdown, for the details window. Anything that is zero and uninteresting is
/// still shown, because a counter that vanishes when it is zero is a counter nobody trusts.
pub fn detail_counters(s: &Snapshot) -> Vec<(String, String)> {
    let l = s.lang;
    vec![
        (t(l, "counter.accepted").into(), s.accepted.to_string()),
        (t(l, "counter.completed").into(), s.completed.to_string()),
        (
            t(l, "counter.transformed").into(),
            s.transformed.to_string(),
        ),
        (t(l, "counter.untouched").into(), s.excluded.to_string()),
        (t(l, "counter.socks5").into(), s.by_socks5.to_string()),
        (t(l, "counter.socks4").into(), s.by_socks4.to_string()),
        (
            t(l, "counter.http_connect").into(),
            s.by_http_connect.to_string(),
        ),
        (
            t(l, "counter.handshake_errors").into(),
            s.handshake_errors.to_string(),
        ),
        (
            t(l, "counter.upstream_errors").into(),
            s.upstream_errors.to_string(),
        ),
        (
            t(l, "counter.dns_failures").into(),
            s.dns_failures.to_string(),
        ),
        (
            t(l, "counter.retries").into(),
            s.first_flight_retries.to_string(),
        ),
    ]
}

/// The longest hostname a row will show before it is cut. Long enough for anything real,
/// short enough that one absurd name cannot stretch the window.
pub const HOST_MAX: usize = 42;

/// One row of the learned-strategies list.
pub fn learned_row(host: &str, strategy: &str) -> String {
    format!("{}  —  {}", clip(host, HOST_MAX), strategy)
}

// --------------------------------------------------------------------------- geometry

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl Rect {
    pub fn new(left: i32, top: i32, right: i32, bottom: i32) -> Rect {
        Rect {
            left,
            top,
            right,
            bottom,
        }
    }
    pub fn width(&self) -> i32 {
        self.right - self.left
    }
    pub fn height(&self) -> i32 {
        self.bottom - self.top
    }
    pub fn contains(&self, x: i32, y: i32) -> bool {
        x >= self.left && y >= self.top && x <= self.right && y <= self.bottom
    }
}

/// Where to put the mini window so it sits beside the tray icon and stays on screen.
///
/// The taskbar can be on any of the four edges and the icon can be at either end of it, so
/// the popup is placed on whichever side of the tray has room and then pushed back inside the
/// work area. Getting this wrong puts a window half off the screen, which on a multi-monitor
/// machine means half of it is on the *other* monitor.
///
/// `work` is the monitor's work area (the screen minus the taskbar).
pub fn popup_position(tray: Rect, work: Rect, size: (i32, i32)) -> (i32, i32) {
    let (w, h) = size;

    // Which edge is the taskbar on? The tray icon sits in it, so whichever side of the work
    // area the icon is nearest to is the answer.
    let gap_left = tray.left - work.left;
    let gap_right = work.right - tray.right;
    let gap_top = tray.top - work.top;
    let gap_bottom = work.bottom - tray.bottom;
    let vertical_taskbar = gap_left.min(gap_right) < gap_top.min(gap_bottom);

    let (mut x, mut y) = if vertical_taskbar {
        // Taskbar on the left or right: place beside the icon, aligned to its top.
        let x = if gap_left < gap_right {
            tray.right
        } else {
            tray.left - w
        };
        (x, tray.top)
    } else {
        // Taskbar top or bottom: place above or below, right-aligned to the icon, which is
        // what every Windows tray popup does.
        let y = if gap_top < gap_bottom {
            tray.bottom
        } else {
            tray.top - h
        };
        (tray.right - w, y)
    };

    // Then keep it entirely inside the work area. `max` after `min` so that a popup larger
    // than the work area is pinned to the top-left rather than pushed off the other side.
    x = x.min(work.right - w).max(work.left);
    y = y.min(work.bottom - h).max(work.top);
    (x, y)
}

// ------------------------------------------------------------------------------- icon

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconState {
    On,
    Off,
    Warning,
}

impl IconState {
    pub fn of(s: &Snapshot) -> IconState {
        match Health::of(s) {
            Health::Protecting => IconState::On,
            Health::Idle => IconState::Off,
            Health::Stranded => IconState::Warning,
        }
    }
}

/// The tray icon, as ARGB pixels, drawn rather than shipped as a file.
///
/// A filled disc: solid when protecting, hollow when off, and a different colour when
/// something is wrong. Generating it means no resource compiler, no `.ico` to keep in sync
/// with the source, and — because it is a pure function — a test can assert that the three
/// states are actually distinguishable, which is the only thing about an icon that matters.
pub fn icon_argb(state: IconState, size: usize) -> Vec<u32> {
    let (r, g, b) = match state {
        IconState::On => (0x2E, 0xC2, 0x7E),
        IconState::Off => (0x8A, 0x8A, 0x8A),
        IconState::Warning => (0xE0, 0x5A, 0x3C),
    };
    let mut px = vec![0u32; size * size];
    // Measured from pixel *centres*, with a radius of half the bitmap. Taking the radius as
    // `(size - 1) / 2` and the distance from pixel corners instead leaves every pixel of a
    // 2x2 or 3x3 bitmap outside the disc, and the icon comes out completely blank — which is
    // exactly the sort of thing that is invisible until somebody's display scaling asks for
    // an unusual size.
    let c = size as f32 / 2.0;
    let outer = c;
    let inner = c * 0.55;
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 + 0.5 - c;
            let dy = y as f32 + 0.5 - c;
            let d = (dx * dx + dy * dy).sqrt();
            // Hollow when off, so the state reads at a glance even in monochrome.
            let lit = if state == IconState::Off {
                d <= outer && d >= inner
            } else {
                d <= outer
            };
            if lit {
                // Feather the last pixel of the edge so the disc is not visibly stepped.
                let a = if d > outer - 1.0 {
                    (((outer - d) + 1.0).clamp(0.0, 1.0) * 255.0) as u32
                } else {
                    255
                };
                px[y * size + x] = (a << 24) | ((r as u32) << 16) | ((g as u32) << 8) | (b as u32);
            }
        }
    }
    px
}

// ------------------------------------------------------------------------ interop

/// A NUL-terminated UTF-16 string, which is the only kind Win32 accepts.
///
/// Pure, and tested, because getting it wrong is quiet: a missing terminator makes Windows
/// read past the end of the buffer and paint whatever it finds, and Turkish text is exactly
/// where a naive byte-wise conversion falls apart.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

/// Scale a length designed at 96 DPI to the display's actual DPI.
///
/// Windows reports DPI as a number where 96 is 100 %. A tray popup laid out in fixed pixels
/// is unreadable at 150 % and comically small at 200 %, and the arithmetic is easy to get
/// subtly wrong in a direction nobody notices on the machine it was written on.
pub fn scale(px: i32, dpi: u32) -> i32 {
    if dpi == 0 {
        return px;
    }
    ((px as i64 * dpi as i64) / 96) as i32
}

// -------------------------------------------------------------------------- full view

/// One line of the details window. A row with an action is clickable; a header is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub text: String,
    /// What clicking this row means. `None` for anything that is only there to be read.
    pub action: Option<Command>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub title: String,
    pub rows: Vec<Row>,
}

fn reading(text: impl Into<String>) -> Row {
    Row {
        text: text.into(),
        action: None,
    }
}

/// Everything the details window shows, in order.
/// What the DNS half is doing, in one phrase.
///
/// Three states and not two: *serving but unused* is the ordinary one — vigil answers on
/// loopback and nothing points at it — and a reader who cannot tell it apart from *off* has no
/// way to understand why the menu item is available.
pub fn dns_line(s: &Snapshot) -> &'static str {
    match (s.dns_serving, s.dns_engaged) {
        (false, _) => t(s.lang, "dns.off"),
        (true, false) => t(s.lang, "dns.ready_unused"),
        (true, true) => t(s.lang, "dns.in_use"),
    }
}

pub fn full_view(s: &Snapshot) -> Vec<Section> {
    let mut out = vec![
        Section {
            title: t(s.lang, "section.status").into(),
            rows: vec![
                reading(status_line(s)),
                reading(tf(s.lang, "line.address", &[("listen", &s.listen)])),
                reading(tf(
                    s.lang,
                    "line.strategy",
                    &[("strategy", &s.mode.label(s.lang))],
                )),
                reading(tf(s.lang, "line.dns", &[("state", dns_line(s))])),
            ],
        },
        Section {
            title: t(s.lang, "section.counters").into(),
            rows: detail_counters(s)
                .into_iter()
                .map(|(k, v)| reading(format!("{k}: {v}")))
                .collect(),
        },
    ];

    let mut learned: Vec<Row> = s
        .learned
        .iter()
        .map(|(h, st)| Row {
            text: learned_row(h, st),
            action: Some(Command::Forget(h.clone())),
        })
        .collect();
    if learned.is_empty() {
        // A section that vanishes when empty makes a user wonder whether it ever existed.
        learned.push(reading(t(s.lang, "placeholder.nothing_learned")));
    } else {
        learned.push(Row {
            text: t(s.lang, "menu.forget_all").into(),
            action: Some(Command::ForgetAll),
        });
    }
    out.push(Section {
        title: t(s.lang, "section.learned").into(),
        rows: learned,
    });

    out.push(Section {
        title: t(s.lang, "section.excluded").into(),
        rows: if s.exclude_patterns.is_empty() {
            vec![reading(t(s.lang, "placeholder.list_empty"))]
        } else {
            s.exclude_patterns.iter().map(reading).collect()
        },
    });

    // What version this is, what the update machinery is doing, and when it last looked. The last
    // of those is what lets a user tell "nothing to update" from "not looking", which on a line that
    // may be blocking the download are very different situations.
    out.push(Section {
        title: t(s.lang, "update.section").into(),
        rows: {
            let mut rows = vec![
                reading(tf(
                    s.lang,
                    "update.version_line",
                    &[("version", &s.version)],
                )),
                Row {
                    text: s.update.line(s.lang),
                    // The state line is the button when there is something to do, so a user who
                    // reads "ready — click to install" can click the thing they just read.
                    action: s.update.actionable().then_some(Command::InstallUpdate),
                },
            ];
            if !s.last_check.is_empty() {
                rows.push(reading(tf(
                    s.lang,
                    "update.last_check",
                    &[("when", &s.last_check)],
                )));
            }
            rows
        },
    });
    out
}

/// A laid-out line: where it goes, what it says, and what clicking it does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub y: i32,
    pub text: String,
    pub header: bool,
    pub action: Option<Command>,
}

/// Row height at 96 DPI. Everything else is derived from it so there is one number to change.
pub const ROW_H: i32 = 20;

/// Turn sections into positioned lines.
///
/// Kept separate from painting so that hit-testing and drawing cannot disagree: both are
/// driven from the same list, and a test can check that a click at a given y lands on the row
/// that was drawn there.
pub fn layout_lines(sections: &[Section], dpi: u32, top: i32) -> Vec<Line> {
    let row = scale(ROW_H, dpi);
    let gap = scale(10, dpi);
    let mut y = top;
    let mut out = Vec::new();
    for (i, sec) in sections.iter().enumerate() {
        if i > 0 {
            y += gap;
        }
        out.push(Line {
            y,
            text: sec.title.clone(),
            header: true,
            action: None,
        });
        y += row;
        for r in &sec.rows {
            out.push(Line {
                y,
                text: r.text.clone(),
                header: false,
                action: r.action.clone(),
            });
            y += row;
        }
    }
    out
}

/// The total height the laid-out lines need, so the window can be sized to fit them.
pub fn content_height(lines: &[Line], dpi: u32) -> i32 {
    lines.last().map(|l| l.y + scale(ROW_H, dpi)).unwrap_or(0)
}

/// Which command a click at `y` means, if any.
///
/// A click lands on a line when it falls within that line's own row height. Headers and
/// read-only rows return `None` — clicking a counter must not do anything, and the failure
/// mode of getting this wrong is forgetting the wrong host.
pub fn hit_test(lines: &[Line], y: i32, dpi: u32) -> Option<Command> {
    let row = scale(ROW_H, dpi);
    lines
        .iter()
        .find(|l| y >= l.y && y < l.y + row)
        .and_then(|l| l.action.clone())
}

/// Keep a scroll offset within what there is to scroll.
///
/// Returned as a non-negative distance to shift the content *up* by. Content shorter than the
/// window scrolls to zero however hard the wheel is turned, which is the difference between a
/// window that refuses to move and one that scrolls its own text off the top.
pub fn clamp_scroll(offset: i32, content: i32, view: i32) -> i32 {
    let max = (content - view).max(0);
    offset.clamp(0, max)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same snapshot in a chosen language. Text assertions below say which language they
    /// are about rather than depending on whatever `Default` happens to be — and most of them
    /// run in both, because the bug this guards against is a string that was only wired up in
    /// one.
    fn snap_in(lang: Lang) -> Snapshot {
        Snapshot { lang, ..snap() }
    }

    fn snap() -> Snapshot {
        Snapshot {
            listen: "127.0.0.1:1080".into(),
            engaged: true,
            listening: true,
            mode: Mode::Auto,
            accepted: 42,
            transformed: 40,
            learned: vec![
                ("discord.com".into(), "tlsrec:64+split:1".into()),
                ("roblox.com".into(), "tlsrec:64".into()),
            ],
            ..Default::default()
        }
    }

    // ------------------------------------------------------------------------ health

    #[test]
    fn engaged_and_listening_is_protecting() {
        assert_eq!(Health::of(&snap()), Health::Protecting);
    }

    #[test]
    fn not_engaged_is_merely_idle() {
        let s = Snapshot {
            engaged: false,
            ..snap()
        };
        assert_eq!(Health::of(&s), Health::Idle);
    }

    /// The state that leaves a machine with no internet. It must never be reported as "off",
    /// because a user who reads "off" will not go looking for the repair button.
    #[test]
    fn engaged_without_listening_is_stranded_not_off() {
        let s = Snapshot {
            engaged: true,
            listening: false,
            ..snap()
        };
        assert_eq!(Health::of(&s), Health::Stranded);
        assert_ne!(Health::of(&s), Health::Idle);
        for lang in [Lang::Turkish, Lang::English] {
            let s = Snapshot { lang, ..s.clone() };
            assert_eq!(status_line(&s), t(lang, "health.stranded"));
        }
    }

    /// A listener that is down while nothing points at us is not an emergency.
    #[test]
    fn not_listening_and_not_engaged_is_still_only_idle() {
        let s = Snapshot {
            engaged: false,
            listening: false,
            ..snap()
        };
        assert_eq!(Health::of(&s), Health::Idle);
    }

    // -------------------------------------------------------------------------- menu

    #[test]
    fn the_menu_offers_the_opposite_of_the_current_state() {
        for lang in [Lang::Turkish, Lang::English] {
            let on = context_menu(&snap_in(lang));
            let toggle = on.iter().find(|i| i.id == id::TOGGLE).unwrap();
            assert_eq!(toggle.label, t(lang, "menu.protect_off"));
            assert!(toggle.checked);

            let off = context_menu(&Snapshot {
                engaged: false,
                ..snap_in(lang)
            });
            let toggle = off.iter().find(|i| i.id == id::TOGGLE).unwrap();
            assert_eq!(toggle.label, t(lang, "menu.protect_on"));
            assert!(!toggle.checked);
        }
    }

    /// Engaging while nothing is listening is the act that strands a machine. The menu must
    /// not offer it.
    #[test]
    fn the_toggle_is_disabled_when_nothing_is_listening() {
        let s = Snapshot {
            listening: false,
            engaged: false,
            ..snap()
        };
        let m = context_menu(&s);
        assert!(!m.iter().find(|i| i.id == id::TOGGLE).unwrap().enabled);
    }

    /// Repair exists to undo a state vigil left behind. Offering it otherwise invites a user
    /// to "fix" settings that were never ours.
    #[test]
    fn repair_is_offered_only_when_there_is_something_to_repair() {
        assert!(
            !context_menu(&snap())
                .iter()
                .find(|i| i.id == id::REPAIR)
                .unwrap()
                .enabled
        );
        let stranded = Snapshot {
            listening: false,
            engaged: true,
            ..snap()
        };
        assert!(
            context_menu(&stranded)
                .iter()
                .find(|i| i.id == id::REPAIR)
                .unwrap()
                .enabled
        );
    }

    #[test]
    fn quit_is_always_available() {
        for s in [
            snap(),
            Snapshot {
                engaged: false,
                ..snap()
            },
            Snapshot {
                listening: false,
                ..snap()
            },
        ] {
            let q = context_menu(&s).into_iter().find(|i| i.id == id::QUIT);
            assert!(q.map(|i| i.enabled).unwrap_or(false), "no way out");
        }
    }

    /// Every offered mode must be a spec the engine actually parses, and must round-trip to
    /// the same text the proxy reports — the tick is decided by comparing those two strings,
    /// so a mismatch would leave the menu with nothing ticked and no error anywhere.
    #[test]
    fn every_offered_mode_parses_and_round_trips() {
        for (i, (label, spec)) in MODES.iter().enumerate() {
            assert!(!label.is_empty(), "mode {i} has no label");
            let Some(spec) = spec else {
                assert_eq!(mode_at(i), Some(Mode::Auto));
                continue;
            };
            let parsed = vigil_core::strategy::Strategy::parse(spec)
                .unwrap_or_else(|e| panic!("{label}: {spec:?} does not parse: {e}"));
            assert_eq!(
                parsed.to_string(),
                *spec,
                "{label}: the proxy would report a different string than the menu compares"
            );
            assert_eq!(mode_at(i), Some(Mode::Fixed((*spec).to_string())));
        }
        assert_eq!(mode_at(MODES.len()), None, "past the end must be nothing");
    }

    /// The one the shipped default has to be, so switching away and back lands where it began.
    #[test]
    fn the_measured_default_is_one_of_the_offered_modes() {
        let d = vigil_core::strategy::Strategy::measured_default().to_string();
        assert!(
            MODES.iter().any(|(_, s)| *s == Some(d.as_str())),
            "the shipped default {d:?} is not in the menu"
        );
    }

    /// The same promise the modes make: exactly one language is ticked, and it is the one being
    /// read. Without the tick there is nothing on screen that says which language is in force,
    /// and a person who cannot read the current one has no way to tell.
    #[test]
    fn exactly_one_language_is_ticked_and_it_is_the_current_one() {
        for want in [Lang::Turkish, Lang::English] {
            let menu = context_menu(&snap_in(want));
            let on: Vec<u16> = menu
                .iter()
                .filter(|m| {
                    m.checked
                        && m.id >= id::LANG_BASE
                        && (m.id as usize) < id::LANG_BASE as usize + LANGS.len()
                })
                .map(|m| m.id)
                .collect();
            assert_eq!(on.len(), 1, "{want:?}");
            assert_eq!(command_for(on[0], &[]), Some(Command::SetLang(want)));
        }
    }

    /// Both languages are named in their own language, always. Somebody looking for English must
    /// not have to read Turkish to find it, and the reverse.
    #[test]
    fn each_language_is_named_in_its_own_language() {
        for reading in [Lang::Turkish, Lang::English] {
            let menu = context_menu(&snap_in(reading));
            let labels: Vec<&str> = menu
                .iter()
                .filter(|m| {
                    m.id >= id::LANG_BASE && (m.id as usize) < id::LANG_BASE as usize + LANGS.len()
                })
                .map(|m| m.label.as_str())
                .collect();
            assert_eq!(labels, vec!["Türkçe", "English"], "reading {reading:?}");
        }
    }

    /// The language ids must not collide with the modes below them or the learned hosts above.
    #[test]
    fn the_language_ids_sit_in_their_own_gap() {
        assert!(id::MODE_BASE as usize + MODES.len() <= id::LANG_BASE as usize);
        assert!(id::LANG_BASE as usize + LANGS.len() <= id::FORGET_BASE as usize);
        for i in 0..LANGS.len() {
            let id = id::LANG_BASE + i as u16;
            assert_eq!(
                command_for(id, &[]),
                Some(Command::SetLang(lang_at(i).unwrap()))
            );
        }
        // One past the end is nobody's.
        assert_eq!(command_for(id::LANG_BASE + LANGS.len() as u16, &[]), None);
    }

    /// Exactly one mode is ticked, whichever the proxy reports.
    #[test]
    fn exactly_one_mode_is_ticked_for_any_mode_the_proxy_can_report() {
        for i in 0..MODES.len() {
            let mut s = snap();
            s.mode = mode_at(i).expect("mode");
            let menu = context_menu(&s);
            let on: Vec<u16> = menu
                .iter()
                .filter(|m| {
                    m.checked
                        && m.id >= id::MODE_BASE
                        && (m.id as usize) < id::MODE_BASE as usize + MODES.len()
                })
                .map(|m| m.id)
                .collect();
            assert_eq!(on, vec![id::MODE_BASE + i as u16], "mode {i}");
        }

        // A strategy nobody offers — the calibrator can settle on one — ticks nothing rather
        // than ticking the wrong entry.
        let mut s = snap();
        s.mode = Mode::Fixed("split:1,2,3".into());
        assert!(context_menu(&s).iter().all(|m| {
            !m.checked
                || m.id < id::MODE_BASE
                || (m.id as usize) >= id::MODE_BASE as usize + MODES.len()
        }));
    }

    /// A learned-host id must never be read as a mode, however many hosts are learned.
    #[test]
    fn mode_ids_and_forget_ids_cannot_collide() {
        assert!(
            (id::MODE_BASE as usize) + MODES.len() <= id::FORGET_BASE as usize,
            "the mode block runs into the forget block"
        );
        let learned: Vec<(String, String)> = (0..300)
            .map(|i| (format!("h{i}.example"), "none".into()))
            .collect();
        for i in 0..MODES.len() {
            assert_eq!(
                command_for(id::MODE_BASE + i as u16, &learned),
                mode_at(i).map(Command::SetMode),
                "mode {i} was shadowed"
            );
        }
        assert_eq!(
            command_for(id::FORGET_BASE, &learned),
            Some(Command::Forget("h0.example".into()))
        );
    }

    #[test]
    fn every_clickable_item_has_a_label_and_a_known_command() {
        for item in context_menu(&snap()) {
            if item.separator {
                assert!(item.label.is_empty());
                continue;
            }
            assert!(!item.label.is_empty(), "an unlabelled item is unclickable");
            assert!(
                command_for(item.id, &[]).is_some(),
                "id {:#x} maps to no command",
                item.id
            );
        }
    }

    #[test]
    fn separators_are_never_between_nothing() {
        let m = context_menu(&snap());
        assert!(
            !m.first().unwrap().separator,
            "menu starts with a separator"
        );
        assert!(!m.last().unwrap().separator, "menu ends with a separator");
        for w in m.windows(2) {
            assert!(
                !(w[0].separator && w[1].separator),
                "two separators in a row"
            );
        }
    }

    // ---------------------------------------------------------------------- commands

    #[test]
    fn ids_map_to_the_commands_they_are_named_for() {
        let l = snap().learned;
        assert_eq!(command_for(id::TOGGLE, &l), Some(Command::Toggle));
        assert_eq!(command_for(id::MINI, &l), Some(Command::ShowMini));
        assert_eq!(command_for(id::FULL, &l), Some(Command::ShowFull));
        assert_eq!(command_for(id::REPAIR, &l), Some(Command::Repair));
        assert_eq!(command_for(id::QUIT, &l), Some(Command::Quit));
        assert_eq!(command_for(id::FORGET_ALL, &l), Some(Command::ForgetAll));
    }

    #[test]
    fn a_forget_id_names_the_host_at_that_position() {
        let l = snap().learned;
        assert_eq!(
            command_for(id::FORGET_BASE, &l),
            Some(Command::Forget("discord.com".into()))
        );
        assert_eq!(
            command_for(id::FORGET_BASE + 1, &l),
            Some(Command::Forget("roblox.com".into()))
        );
    }

    /// A stale window sending a forget for a row that no longer exists must do nothing, not
    /// forget the wrong host.
    #[test]
    fn a_forget_id_past_the_end_forgets_nothing() {
        let l = snap().learned;
        assert_eq!(command_for(id::FORGET_BASE + 2, &l), None);
        assert_eq!(command_for(id::FORGET_BASE + 999, &l), None);
        assert_eq!(command_for(id::FORGET_BASE, &[]), None);
    }

    #[test]
    fn unknown_ids_mean_nothing() {
        for n in [0u16, 1, 0x99, 0x1FF, u16::MAX - 1] {
            if n >= id::FORGET_BASE {
                continue;
            }
            assert_eq!(command_for(n, &snap().learned), None, "id {n:#x}");
        }
    }

    // -------------------------------------------------------------------------- text

    #[test]
    fn the_tooltip_says_what_state_it_is_in() {
        for (lang, on, off, bad) in [
            (Lang::Turkish, "açık", "kapalı", "SORUN"),
            (Lang::English, " on,", "off", "PROBLEM"),
        ] {
            assert!(tooltip(&snap_in(lang)).contains(on), "{lang:?}");
            assert!(
                tooltip(&Snapshot {
                    engaged: false,
                    ..snap_in(lang)
                })
                .contains(off),
                "{lang:?}"
            );
            assert!(
                tooltip(&Snapshot {
                    listening: false,
                    ..snap_in(lang)
                })
                .contains(bad),
                "{lang:?}"
            );
        }
    }

    /// Windows silently truncates a tooltip at 128 characters. Ours must fit whatever it is
    /// handed, including an absurd strategy string.
    #[test]
    fn the_tooltip_always_fits_what_windows_will_show() {
        for lang in [Lang::Turkish, Lang::English] {
            let s = Snapshot {
                mode: Mode::Fixed("x".repeat(500)),
                accepted: usize::MAX,
                transformed: usize::MAX,
                listen: "y".repeat(200),
                ..snap_in(lang)
            };
            let tip = tooltip(&s);
            assert!(
                tip.chars().count() <= TOOLTIP_MAX,
                "{lang:?}: {} chars is longer than Windows will show",
                tip.chars().count()
            );
            assert!(tip.ends_with('…'), "truncation should be visible: {tip}");
        }
    }

    #[test]
    fn a_short_tooltip_is_not_mangled() {
        let t = tooltip(&Snapshot {
            engaged: false,
            ..snap()
        });
        assert!(!t.ends_with('…'));
        assert!(t.contains("127.0.0.1:1080"));
    }

    /// Truncation counts characters, not bytes. Cutting Turkish text mid-codepoint would
    /// panic or produce mojibake.
    #[test]
    fn truncation_does_not_split_multibyte_characters() {
        let s = "şğüöçİĞÜÖÇ".repeat(40);
        for n in 1..40 {
            let out = clip(&s, n);
            assert!(out.chars().count() <= n, "n={n}");
            assert!(out.len() >= out.chars().count(), "n={n}");
        }
    }

    #[test]
    fn counters_are_labelled_and_never_empty() {
        let c = counters(&snap());
        assert_eq!(c.len(), 3);
        for (label, value) in &c {
            assert!(!label.is_empty());
            assert!(!value.is_empty());
        }
        assert_eq!(c[0].1, "42");
        assert_eq!(c[2].1, "2", "learned count should follow the list length");
    }

    /// A counter that disappears at zero is a counter nobody trusts.
    #[test]
    fn detail_counters_show_zeroes_rather_than_hiding_them() {
        let d = detail_counters(&Snapshot::default());
        assert_eq!(d.len(), 11);
        assert!(d.iter().all(|(_, v)| v == "0"));
    }

    /// The DNS item can take a machine's whole name resolution down, so it must be
    /// unclickable exactly when it would: when nothing is answering on loopback.
    #[test]
    fn the_dns_item_is_only_offered_when_something_answers() {
        let mut s = snap();
        s.dns_serving = false;
        let item = context_menu(&s)
            .into_iter()
            .find(|m| m.id == id::SYSDNS)
            .expect("the item must exist even when it is unusable");
        assert!(
            !item.enabled,
            "pointing a machine at a resolver that is not there"
        );
        assert!(!item.checked);

        s.dns_serving = true;
        let item = context_menu(&s)
            .into_iter()
            .find(|m| m.id == id::SYSDNS)
            .expect("item");
        assert!(item.enabled);
        assert_eq!(item.label, t(s.lang, "menu.dns_give"));

        s.dns_engaged = true;
        let item = context_menu(&s)
            .into_iter()
            .find(|m| m.id == id::SYSDNS)
            .expect("item");
        assert!(
            item.checked,
            "the tick is the only thing that says it is on"
        );
        assert_eq!(item.label, t(s.lang, "menu.dns_take_back"));
    }

    #[test]
    fn the_dns_id_means_what_it_says() {
        assert_eq!(command_for(id::SYSDNS, &[]), Some(Command::ToggleSystemDns));
        // Checked at compile time rather than asserted at run time: both are constants, so a
        // runtime assertion here could never fail on a build that got this far — which is the
        // definition of a test that proves nothing.
        const { assert!(id::SYSDNS < id::MODE_BASE) };
    }

    /// Serving-but-unused is its own state. Collapsing it into "off" leaves a user unable to
    /// tell a resolver that is ready from one that is not running.
    #[test]
    fn the_dns_line_distinguishes_ready_from_off_and_from_in_use() {
        let mut s = snap_in(Lang::Turkish);
        s.dns_serving = false;
        s.dns_engaged = false;
        assert_eq!(dns_line(&s), t(Lang::Turkish, "dns.off"));
        s.dns_serving = true;
        assert_eq!(dns_line(&s), t(Lang::Turkish, "dns.ready_unused"));
        s.dns_engaged = true;
        assert_eq!(dns_line(&s), t(Lang::Turkish, "dns.in_use"));
        // The three states must be three distinct phrases in English too, or the distinction
        // exists only for Turkish readers.
        let en: Vec<&str> = [(false, false), (true, false), (true, true)]
            .iter()
            .map(|(serving, engaged)| {
                dns_line(&Snapshot {
                    dns_serving: *serving,
                    dns_engaged: *engaged,
                    ..snap_in(Lang::English)
                })
            })
            .collect();
        assert_eq!(en.len(), 3);
        assert_ne!(en[0], en[1]);
        assert_ne!(en[1], en[2]);

        // and it reaches the window
        let text: String = full_view(&s)[0]
            .rows
            .iter()
            .map(|r| r.text.clone())
            .collect::<Vec<_>>()
            .join("|");
        assert!(text.contains("DNS:"), "{text}");
    }

    #[test]
    fn a_learned_row_shows_both_host_and_strategy() {
        let r = learned_row("discord.com", "tlsrec:64+split:1");
        assert!(r.contains("discord.com"));
        assert!(r.contains("tlsrec:64+split:1"));
    }

    #[test]
    fn an_absurd_hostname_cannot_stretch_a_row() {
        let r = learned_row(&"a".repeat(500), "split:1");
        assert!(r.chars().count() < HOST_MAX + 30, "{}", r.chars().count());
        assert!(r.contains("split:1"), "the strategy must survive the cut");
    }

    // ---------------------------------------------------------------------- geometry

    const SCREEN: Rect = Rect {
        left: 0,
        top: 0,
        right: 1920,
        bottom: 1040,
    }; // 1080 minus a 40px taskbar
    const SIZE: (i32, i32) = (320, 240);

    fn inside(p: (i32, i32), work: Rect, size: (i32, i32)) -> bool {
        p.0 >= work.left
            && p.1 >= work.top
            && p.0 + size.0 <= work.right
            && p.1 + size.1 <= work.bottom
    }

    /// The ordinary case: taskbar at the bottom, icon at the right.
    #[test]
    fn a_bottom_taskbar_puts_the_popup_above_the_icon() {
        let tray = Rect::new(1850, 1040, 1870, 1060);
        let p = popup_position(tray, SCREEN, SIZE);
        assert!(p.1 + SIZE.1 <= SCREEN.bottom, "popup overlaps the taskbar");
        assert!(inside(p, SCREEN, SIZE));
    }

    #[test]
    fn a_top_taskbar_puts_the_popup_below_the_icon() {
        let work = Rect::new(0, 40, 1920, 1080);
        let tray = Rect::new(1850, 10, 1870, 30);
        let p = popup_position(tray, work, SIZE);
        assert!(p.1 >= work.top);
        assert!(inside(p, work, SIZE));
    }

    #[test]
    fn a_left_taskbar_puts_the_popup_to_its_right() {
        let work = Rect::new(60, 0, 1920, 1080);
        let tray = Rect::new(10, 900, 30, 920);
        let p = popup_position(tray, work, SIZE);
        assert!(p.0 >= work.left);
        assert!(inside(p, work, SIZE));
    }

    #[test]
    fn a_right_taskbar_puts_the_popup_to_its_left() {
        let work = Rect::new(0, 0, 1860, 1080);
        let tray = Rect::new(1890, 900, 1910, 920);
        let p = popup_position(tray, work, SIZE);
        assert!(p.0 + SIZE.0 <= work.right);
        assert!(inside(p, work, SIZE));
    }

    /// The property that matters more than which side it lands on: it is never off screen.
    /// On a multi-monitor machine "off screen" means "on the other monitor", which looks like
    /// the window failed to open.
    #[test]
    fn the_popup_is_always_fully_inside_the_work_area() {
        let works = [
            SCREEN,
            Rect::new(0, 40, 1920, 1080),
            Rect::new(60, 0, 1920, 1080),
            Rect::new(0, 0, 1860, 1080),
            Rect::new(-1920, 0, 0, 1040), // a monitor to the left of the primary
        ];
        for work in works {
            for x in [work.left, (work.left + work.right) / 2, work.right - 20] {
                for y in [work.top, (work.top + work.bottom) / 2, work.bottom - 20] {
                    let tray = Rect::new(x, y, x + 20, y + 20);
                    let p = popup_position(tray, work, SIZE);
                    assert!(
                        inside(p, work, SIZE),
                        "tray at ({x},{y}) in {work:?} put the popup at {p:?}"
                    );
                }
            }
        }
    }

    /// A popup bigger than the work area cannot fit; it must pin to the top-left rather than
    /// hang off the bottom-right where its buttons would be unreachable.
    #[test]
    fn a_popup_larger_than_the_screen_pins_to_the_corner() {
        let work = Rect::new(0, 0, 200, 200);
        let tray = Rect::new(180, 180, 200, 200);
        let p = popup_position(tray, work, (320, 240));
        assert_eq!(p, (work.left, work.top));
    }

    #[test]
    fn rect_helpers_agree_with_themselves() {
        let r = Rect::new(10, 20, 110, 220);
        assert_eq!(r.width(), 100);
        assert_eq!(r.height(), 200);
        assert!(r.contains(10, 20));
        assert!(r.contains(110, 220));
        assert!(r.contains(60, 100));
        assert!(!r.contains(9, 100));
        assert!(!r.contains(60, 221));
    }

    // -------------------------------------------------------------------------- icon

    #[test]
    fn the_icon_is_the_size_it_was_asked_for() {
        for n in [16usize, 20, 24, 32, 48, 64] {
            assert_eq!(icon_argb(IconState::On, n).len(), n * n);
        }
    }

    /// The only thing that matters about an icon: the states must not look the same.
    #[test]
    fn the_three_states_are_visibly_different() {
        let on = icon_argb(IconState::On, 32);
        let off = icon_argb(IconState::Off, 32);
        let warn = icon_argb(IconState::Warning, 32);
        assert_ne!(on, off);
        assert_ne!(on, warn);
        assert_ne!(off, warn);
    }

    #[test]
    fn the_icon_is_a_disc_and_not_a_square() {
        let px = icon_argb(IconState::On, 32);
        let alpha = |x: usize, y: usize| px[y * 32 + x] >> 24;
        assert_eq!(alpha(0, 0), 0, "the corners must be transparent");
        assert_eq!(alpha(31, 0), 0);
        assert_eq!(alpha(0, 31), 0);
        assert_eq!(alpha(31, 31), 0);
        assert!(alpha(16, 16) > 0, "the middle must be drawn");
    }

    /// Off is hollow, which is what makes it readable without colour.
    #[test]
    fn the_off_icon_is_hollow_and_the_on_icon_is_not() {
        let on = icon_argb(IconState::On, 32);
        let off = icon_argb(IconState::Off, 32);
        assert!(on[16 * 32 + 16] >> 24 > 0, "on should be filled");
        assert_eq!(off[16 * 32 + 16] >> 24, 0, "off should be hollow");
        // but its ring is drawn
        assert!(off[16 * 32 + 1] >> 24 > 0 || off[32 + 16] >> 24 > 0);
    }

    #[test]
    fn a_tiny_icon_does_not_panic_or_come_out_empty() {
        for n in [1usize, 2, 3, 4] {
            let px = icon_argb(IconState::On, n);
            assert_eq!(px.len(), n * n);
            assert!(px.iter().any(|p| p >> 24 > 0), "{n}x{n} came out blank");
        }
    }

    // ---------------------------------------------------------------------- interop

    #[test]
    fn a_wide_string_is_terminated() {
        let w = wide("ok");
        assert_eq!(w, vec![0x6F, 0x6B, 0x00]);
        assert_eq!(*w.last().unwrap(), 0, "Windows reads until the NUL");
    }

    #[test]
    fn an_empty_wide_string_is_still_terminated() {
        assert_eq!(wide(""), vec![0u16]);
    }

    /// Turkish is where a careless conversion breaks, and every label in this interface is
    /// Turkish.
    #[test]
    fn turkish_survives_the_conversion() {
        for s in [
            "Korumayı kapat",
            "Ayrıntılar…",
            "Proxy ayarlarını onar",
            "Çıkış",
        ] {
            let w = wide(s);
            assert_eq!(*w.last().unwrap(), 0);
            let back = String::from_utf16(&w[..w.len() - 1]).expect("round trips");
            assert_eq!(back, s);
        }
    }

    /// Characters outside the basic plane become two units. A conversion that assumed one
    /// unit per character would truncate them.
    #[test]
    fn astral_characters_become_surrogate_pairs() {
        let w = wide("a🔒b");
        assert_eq!(w.len(), 5, "1 + 2 + 1 + terminator");
        assert_eq!(String::from_utf16(&w[..4]).unwrap(), "a🔒b");
    }

    #[test]
    fn scaling_is_the_identity_at_96_dpi() {
        for px in [0, 1, 100, 320, -40] {
            assert_eq!(scale(px, 96), px);
        }
    }

    #[test]
    fn scaling_follows_the_display() {
        assert_eq!(scale(100, 144), 150); // 150 %
        assert_eq!(scale(100, 192), 200); // 200 %
        assert_eq!(scale(320, 120), 400); // 125 %
    }

    /// A bogus DPI must not divide by zero or silently produce a zero-sized window.
    #[test]
    fn a_nonsense_dpi_leaves_the_size_alone() {
        assert_eq!(scale(320, 0), 320);
    }

    #[test]
    fn scaling_does_not_overflow_on_absurd_input() {
        let big = scale(i32::MAX, 192);
        assert!(big != 0, "an overflow to zero would collapse the window");
    }

    #[test]
    fn the_icon_state_follows_health() {
        assert_eq!(IconState::of(&snap()), IconState::On);
        assert_eq!(
            IconState::of(&Snapshot {
                engaged: false,
                ..snap()
            }),
            IconState::Off
        );
        assert_eq!(
            IconState::of(&Snapshot {
                listening: false,
                ..snap()
            }),
            IconState::Warning
        );
    }

    // --------------------------------------------------------------------- full view

    #[test]
    fn the_full_view_shows_every_section() {
        for lang in [Lang::Turkish, Lang::English] {
            let v = full_view(&snap_in(lang));
            let titles: Vec<&str> = v.iter().map(|s| s.title.as_str()).collect();
            assert_eq!(titles.len(), 5, "{lang:?}");
            assert_eq!(titles[0], t(lang, "section.status"));
            assert_eq!(titles[1], t(lang, "section.counters"));
            assert_eq!(titles[2], t(lang, "section.learned"));
            assert_eq!(titles[3], t(lang, "section.excluded"));
            // Last, because it is about the program rather than about the traffic — and appended
            // rather than inserted, so the sections above it keep the positions the rest of the
            // interface and its tests already refer to.
            assert_eq!(titles[4], t(lang, "update.section"));
        }
    }

    #[test]
    fn each_learned_host_is_clickable_and_forgets_itself() {
        let v = full_view(&snap());
        let learned = &v[2];
        assert_eq!(
            learned.rows[0].action,
            Some(Command::Forget("discord.com".into()))
        );
        assert_eq!(
            learned.rows[1].action,
            Some(Command::Forget("roblox.com".into()))
        );
        assert_eq!(
            learned.rows.last().unwrap().action,
            Some(Command::ForgetAll)
        );
    }

    /// Nothing that is only there to be read may be clickable. Getting this wrong means a
    /// click on a counter forgets a host.
    #[test]
    fn counters_and_status_are_not_clickable() {
        let v = full_view(&snap());
        for sec in [&v[0], &v[1], &v[3]] {
            for r in &sec.rows {
                assert_eq!(r.action, None, "{:?} should not be clickable", r.text);
            }
        }
    }

    /// A section that disappears when empty makes a user wonder whether it ever existed.
    #[test]
    fn empty_sections_say_so_rather_than_vanishing() {
        for lang in [Lang::Turkish, Lang::English] {
            let v = full_view(&Snapshot {
                lang,
                ..Default::default()
            });
            assert_eq!(v.len(), 5);
            assert!(!v[2].rows.is_empty());
            assert_eq!(v[2].rows[0].text, t(lang, "placeholder.nothing_learned"));
            assert_eq!(
                v[2].rows[0].action, None,
                "the placeholder must not be clickable"
            );
            assert_eq!(v[3].rows[0].text, t(lang, "placeholder.list_empty"));
        }
    }

    /// With nothing learned there is nothing to forget, so the button must not be offered.
    #[test]
    fn forget_all_is_absent_when_nothing_is_learned() {
        let v = full_view(&Snapshot::default());
        let any = v
            .iter()
            .flat_map(|s| s.rows.iter())
            .any(|r| r.action == Some(Command::ForgetAll));
        assert!(!any);
    }

    // ----------------------------------------------------------------------- layout

    #[test]
    fn lines_are_laid_out_in_order_and_never_overlap() {
        let lines = layout_lines(&full_view(&snap()), 96, 10);
        assert!(!lines.is_empty());
        for w in lines.windows(2) {
            assert!(w[1].y > w[0].y, "lines out of order: {:?}", w);
            assert!(
                w[1].y - w[0].y >= ROW_H,
                "lines overlap: {} then {}",
                w[0].y,
                w[1].y
            );
        }
    }

    #[test]
    fn layout_starts_where_it_was_told_to() {
        for top in [0, 10, 100] {
            let lines = layout_lines(&full_view(&snap()), 96, top);
            assert_eq!(lines[0].y, top);
        }
    }

    #[test]
    fn layout_scales_with_the_display() {
        let a = layout_lines(&full_view(&snap()), 96, 0);
        let b = layout_lines(&full_view(&snap()), 192, 0);
        assert_eq!(a.len(), b.len());
        assert!(
            content_height(&b, 192) > content_height(&a, 96),
            "a 200% display needs more room, not the same"
        );
    }

    #[test]
    fn the_content_height_covers_the_last_line() {
        let lines = layout_lines(&full_view(&snap()), 96, 0);
        let h = content_height(&lines, 96);
        assert!(h >= lines.last().unwrap().y + ROW_H);
    }

    #[test]
    fn an_empty_layout_has_no_height() {
        assert_eq!(content_height(&[], 96), 0);
        assert!(layout_lines(&[], 96, 0).is_empty());
    }

    // -------------------------------------------------------------------- hit tests

    /// The property that keeps drawing and clicking from disagreeing: a click anywhere inside
    /// a row's own band hits that row, and both come from the same list.
    #[test]
    fn a_click_inside_a_row_hits_that_row() {
        let lines = layout_lines(&full_view(&snap()), 96, 0);
        for l in &lines {
            for dy in [0, ROW_H / 2, ROW_H - 1] {
                assert_eq!(
                    hit_test(&lines, l.y + dy, 96),
                    l.action,
                    "y={} (line at {}) did not hit its own row",
                    l.y + dy,
                    l.y
                );
            }
        }
    }

    #[test]
    fn a_click_on_a_header_does_nothing() {
        let lines = layout_lines(&full_view(&snap()), 96, 0);
        let header = lines.iter().find(|l| l.header).unwrap();
        assert_eq!(hit_test(&lines, header.y, 96), None);
    }

    #[test]
    fn a_click_outside_every_row_does_nothing() {
        let lines = layout_lines(&full_view(&snap()), 96, 20);
        assert_eq!(hit_test(&lines, 0, 96), None, "above the first line");
        let last = lines.last().unwrap();
        assert_eq!(
            hit_test(&lines, last.y + ROW_H + 1, 96),
            None,
            "below the last"
        );
        assert_eq!(hit_test(&lines, -50, 96), None);
    }

    /// A click must never land on the row *next* to the one under the cursor, because the
    /// action is destructive.
    #[test]
    fn clicks_never_bleed_into_the_neighbouring_row() {
        let lines = layout_lines(&full_view(&snap()), 96, 0);
        for w in lines.windows(2) {
            let boundary = w[0].y + ROW_H;
            assert_eq!(hit_test(&lines, boundary - 1, 96), w[0].action);
            if w[1].y == boundary {
                assert_eq!(hit_test(&lines, boundary, 96), w[1].action);
            }
        }
    }

    #[test]
    fn hit_testing_scales_with_the_display_too() {
        let lines = layout_lines(&full_view(&snap()), 192, 0);
        let row = lines
            .iter()
            .find(|l| matches!(l.action, Some(Command::Forget(_))))
            .unwrap()
            .clone();
        assert_eq!(
            hit_test(&lines, row.y + scale(ROW_H, 192) - 1, 192),
            row.action
        );
        assert_ne!(hit_test(&lines, row.y + scale(ROW_H, 192), 192), row.action);
    }

    // ----------------------------------------------------------------- scrolling

    #[test]
    fn content_that_fits_does_not_scroll() {
        for o in [-100, 0, 50, 10_000] {
            assert_eq!(clamp_scroll(o, 300, 500), 0, "offset {o}");
        }
    }

    #[test]
    fn scrolling_stops_at_the_bottom_of_the_content() {
        assert_eq!(clamp_scroll(10_000, 900, 400), 500);
        assert_eq!(clamp_scroll(500, 900, 400), 500);
        assert_eq!(clamp_scroll(499, 900, 400), 499);
    }

    #[test]
    fn scrolling_stops_at_the_top() {
        assert_eq!(clamp_scroll(-1, 900, 400), 0);
        assert_eq!(clamp_scroll(-10_000, 900, 400), 0);
    }

    /// Exactly-fitting content must not gain a pixel of slack, or the last line jitters.
    #[test]
    fn content_exactly_the_window_height_does_not_scroll() {
        assert_eq!(clamp_scroll(1, 400, 400), 0);
    }

    // --------------------------------------------------------------------- autostart

    #[test]
    fn the_autostart_item_reflects_whether_it_is_registered() {
        let off = context_menu(&snap());
        let i = off.iter().find(|i| i.id == id::AUTOSTART).unwrap();
        assert!(!i.checked);
        assert!(i.enabled, "it must be togglable in both directions");

        let on = context_menu(&Snapshot {
            autostart: true,
            ..snap()
        });
        assert!(on.iter().find(|i| i.id == id::AUTOSTART).unwrap().checked);
    }

    #[test]
    fn the_autostart_id_maps_to_its_command() {
        assert_eq!(
            command_for(id::AUTOSTART, &[]),
            Some(Command::ToggleAutostart)
        );
    }

    /// Autostart is about the next logon, not about this run: it must stay usable whatever
    /// the proxy is doing right now.
    #[test]
    fn autostart_stays_usable_even_when_stranded() {
        let s = Snapshot {
            listening: false,
            engaged: true,
            ..snap()
        };
        assert!(
            context_menu(&s)
                .iter()
                .find(|i| i.id == id::AUTOSTART)
                .unwrap()
                .enabled
        );
    }
}

#[cfg(test)]
mod update_tests {
    use super::*;

    fn snap_with(u: UpdateState, lang: Lang) -> Snapshot {
        Snapshot {
            listen: "127.0.0.1:1080".into(),
            engaged: true,
            listening: true,
            version: "0.6.3".into(),
            update: u,
            auto_update: true,
            ..Default::default()
        }
        .tap_lang(lang)
    }

    trait TapLang {
        fn tap_lang(self, lang: Lang) -> Snapshot;
    }
    impl TapLang for Snapshot {
        fn tap_lang(mut self, lang: Lang) -> Snapshot {
            self.lang = lang;
            self
        }
    }

    fn all_states() -> Vec<UpdateState> {
        vec![
            UpdateState::Off,
            UpdateState::NeverChecked,
            UpdateState::Checking,
            UpdateState::UpToDate,
            UpdateState::Available {
                version: "0.7.0".into(),
                critical: false,
            },
            UpdateState::Available {
                version: "0.7.0".into(),
                critical: true,
            },
            UpdateState::Staged {
                version: "0.7.0".into(),
                critical: false,
            },
            UpdateState::Staged {
                version: "0.7.0".into(),
                critical: true,
            },
            UpdateState::Unreachable {
                why: "silently dropped".into(),
            },
            UpdateState::FolderNotWritable,
            UpdateState::NoKeys,
            UpdateState::Interrupted,
        ]
    }

    /// Every state says something, in both languages, and no two of them say the same thing.
    ///
    /// The last part is the one that matters: "no update" and "could not look" are the same to a
    /// naive design and completely different to a user whose line may be blocking the download.
    #[test]
    fn every_update_state_reads_distinctly_in_both_languages() {
        for lang in [Lang::Turkish, Lang::English] {
            let mut seen: Vec<String> = Vec::new();
            for st in all_states() {
                let line = st.line(lang);
                assert!(!line.trim().is_empty(), "{st:?} in {lang:?} says nothing");
                assert!(
                    !line.contains("{{"),
                    "{st:?} in {lang:?} left a placeholder showing: {line}"
                );
                assert!(
                    !seen.contains(&line),
                    "{st:?} in {lang:?} reads the same as an earlier state: {line}"
                );
                seen.push(line);
            }
        }
    }

    /// The menu never offers a button that does nothing, and offers one whenever there is something
    /// to do.
    #[test]
    fn the_install_item_exists_exactly_when_there_is_something_to_install() {
        for st in all_states() {
            let s = snap_with(st.clone(), Lang::Turkish);
            let menu = context_menu(&s);
            let has = menu.iter().any(|m| m.id == id::INSTALL_UPDATE);
            assert_eq!(
                has,
                st.actionable(),
                "{st:?}: actionable={} but the item is {}",
                st.actionable(),
                if has { "present" } else { "absent" }
            );
            if has {
                assert_eq!(
                    command_for(id::INSTALL_UPDATE, &[]),
                    Some(Command::InstallUpdate)
                );
            }
        }
    }

    /// Pressing "check" while a check is running would start a second one, and two checks racing is
    /// how a manifest gets applied twice.
    #[test]
    fn checking_is_unclickable_while_a_check_is_in_flight() {
        let s = snap_with(UpdateState::Checking, Lang::English);
        let item = context_menu(&s)
            .into_iter()
            .find(|m| m.id == id::CHECK_UPDATE)
            .expect("the item must exist even while it is unusable");
        assert!(!item.enabled);
        assert_eq!(item.label, t(Lang::English, "update.checking"));

        let s = snap_with(UpdateState::UpToDate, Lang::English);
        let item = context_menu(&s)
            .into_iter()
            .find(|m| m.id == id::CHECK_UPDATE)
            .expect("item");
        assert!(item.enabled);
        assert_eq!(item.label, t(Lang::English, "update.check_now"));
    }

    /// The tick reflects the preference, not the momentary state — a manual check running does not
    /// mean automatic checking is on.
    #[test]
    fn the_automatic_tick_follows_the_preference_only() {
        for (auto, state) in [
            (true, UpdateState::Checking),
            (false, UpdateState::Checking),
            (true, UpdateState::Off),
            (false, UpdateState::UpToDate),
        ] {
            let s = Snapshot {
                auto_update: auto,
                ..snap_with(state.clone(), Lang::Turkish)
            };
            let item = context_menu(&s)
                .into_iter()
                .find(|m| m.id == id::AUTO_UPDATE)
                .expect("item");
            assert_eq!(item.checked, auto, "auto={auto} state={state:?}");
            assert!(item.enabled, "it must always be togglable");
        }
    }

    /// Only a critical update may draw attention. An indicator that is always on is one nobody
    /// reads, and this project has to spend that attention carefully.
    #[test]
    fn only_a_critical_update_asks_for_attention() {
        for st in all_states() {
            let want = matches!(
                st,
                UpdateState::Available { critical: true, .. }
                    | UpdateState::Staged { critical: true, .. }
            );
            assert_eq!(st.wants_attention(), want, "{st:?}");
        }
    }

    /// The state line in the details window is itself the button when there is something to do, so
    /// somebody who reads "ready — click to install" can click the thing they just read.
    #[test]
    fn the_details_line_is_clickable_exactly_when_the_state_is_actionable() {
        for st in all_states() {
            let s = snap_with(st.clone(), Lang::English);
            let v = full_view(&s);
            let section = v.last().expect("the update section is last");
            assert_eq!(section.title, t(Lang::English, "update.section"));
            // Row 0 is the version, row 1 is the state.
            assert_eq!(section.rows[0].text, "Version: 0.6.3");
            assert_eq!(section.rows[0].action, None, "the version is not a button");
            assert_eq!(section.rows[1].action.is_some(), st.actionable(), "{st:?}");
            if st.actionable() {
                assert_eq!(section.rows[1].action, Some(Command::InstallUpdate));
            }
        }
    }

    /// "Last checked" appears only when there is something to say. Its absence is what tells a user
    /// the tool has never looked, which on a line that may be blocking the download is the single
    /// most useful thing on the screen.
    #[test]
    fn the_last_check_row_appears_only_when_a_check_has_happened() {
        let never = snap_with(UpdateState::NeverChecked, Lang::Turkish);
        let rows = full_view(&never).last().expect("section").rows.len();
        assert_eq!(rows, 2, "version and state only");

        let checked = Snapshot {
            last_check: "2026-08-08 12:00:00 UTC".into(),
            ..snap_with(UpdateState::UpToDate, Lang::Turkish)
        };
        let section = full_view(&checked).last().expect("section").clone();
        assert_eq!(section.rows.len(), 3);
        assert!(section.rows[2].text.contains("2026-08-08"));
        assert_eq!(section.rows[2].action, None);
    }

    /// The three new ids must not collide with anything, and each must map to its own command.
    #[test]
    fn the_update_ids_are_their_own() {
        let ids = [id::CHECK_UPDATE, id::INSTALL_UPDATE, id::AUTO_UPDATE];
        for id in ids {
            assert!(id < id::MODE_BASE, "{id:#x} must sit below the mode block");
        }
        assert_eq!(
            command_for(id::CHECK_UPDATE, &[]),
            Some(Command::CheckForUpdates)
        );
        assert_eq!(
            command_for(id::INSTALL_UPDATE, &[]),
            Some(Command::InstallUpdate)
        );
        assert_eq!(
            command_for(id::AUTO_UPDATE, &[]),
            Some(Command::ToggleAutoUpdate)
        );
        // And no two of them are the same number.
        assert_eq!(
            ids.iter().collect::<std::collections::BTreeSet<_>>().len(),
            3
        );
    }
}

#[cfg(test)]
mod status_line_tests {
    use super::*;

    /// The happy shapes, exactly as `vigil-update.exe --check` prints them.
    #[test]
    fn the_statuses_the_updater_prints_are_understood() {
        assert_eq!(
            UpdateState::from_status_line("vigil-update-status status=current"),
            UpdateState::UpToDate
        );
        assert_eq!(
            UpdateState::from_status_line(
                "vigil-update-status status=available version=0.7.0 critical=0"
            ),
            UpdateState::Available {
                version: "0.7.0".into(),
                critical: false
            }
        );
        assert_eq!(
            UpdateState::from_status_line(
                "vigil-update-status status=available version=0.7.1 critical=1"
            ),
            UpdateState::Available {
                version: "0.7.1".into(),
                critical: true
            }
        );
        assert_eq!(
            UpdateState::from_status_line(
                "vigil-update-status status=staged version=0.7.0 critical=0"
            ),
            UpdateState::Staged {
                version: "0.7.0".into(),
                critical: false
            }
        );
        // A staged update keeps its urgency. It used to lose it here: the `staged` status line
        // carried `critical=` and this arm dropped it on the floor.
        assert_eq!(
            UpdateState::from_status_line(
                "vigil-update-status status=staged version=0.7.1 critical=1"
            ),
            UpdateState::Staged {
                version: "0.7.1".into(),
                critical: true
            }
        );
        assert_eq!(
            UpdateState::from_status_line("vigil-update-status status=nokeys"),
            UpdateState::NoKeys
        );
        assert_eq!(
            UpdateState::from_status_line("vigil-update-status status=readonly why=access_denied"),
            UpdateState::FolderNotWritable
        );
    }

    /// Underscores come back as spaces, because the updater replaces spaces to keep one field one
    /// token and the user should read a sentence.
    #[test]
    fn a_reason_survives_the_round_trip_through_underscores() {
        let st = UpdateState::from_status_line(
            "vigil-update-status status=unreachable why=no_endpoint_answered",
        );
        assert_eq!(
            st,
            UpdateState::Unreachable {
                why: "no endpoint answered".into()
            }
        );
    }

    /// **The one that matters.** Anything unreadable must never become "up to date" — a build that
    /// cannot understand the answer has to say so, not quietly claim everything is fine. That is the
    /// difference between a user who knows they have stopped receiving fixes and one who does not.
    #[test]
    fn nothing_unreadable_is_ever_mistaken_for_up_to_date() {
        for line in [
            "",
            "   ",
            "garbage",
            "status=",
            "status=who_knows",
            "vigil-update-status",
            "vigil-update-status status=available", // no version
            "vigil-update-status status=staged",    // no version
            "thread 'main' panicked at src/main.rs",
            "status=current extra", // right status, wrong shape overall
        ] {
            let st = UpdateState::from_status_line(line);
            if line == "status=current extra" {
                // A status field that *is* there is honoured; the stray token is ignored, which is
                // the forgiving direction and cannot cause a false "fine".
                assert_eq!(st, UpdateState::UpToDate, "{line:?}");
                continue;
            }
            assert!(
                matches!(st, UpdateState::Unreachable { .. }),
                "{line:?} became {st:?}, which is not a complaint"
            );
            assert_ne!(st, UpdateState::UpToDate, "{line:?}");
        }
    }

    /// An apply that stopped part way must arrive as `Interrupted`, and `Interrupted` must be
    /// actionable — otherwise a half-updated folder has no route back to being whole.
    ///
    /// This state existed in the interface from the first commit and **nothing produced it**: the
    /// updater printed no such status and this parser had no arm for it, so a folder with some files
    /// replaced and some not reported itself up to date. Four of six adversarial reviewers found that
    /// independently, which is a fair measure of how invisible a dead enum variant is.
    #[test]
    fn an_interrupted_apply_is_actionable_rather_than_up_to_date() {
        let st = UpdateState::from_status_line(
            "vigil-update-status status=interrupted version=0.7.0 outstanding=2",
        );
        assert_eq!(st, UpdateState::Interrupted);
        assert_ne!(st, UpdateState::UpToDate, "the whole point");
        assert!(st.actionable(), "there must be something to click");
        for lang in [Lang::Turkish, Lang::English] {
            assert!(st.action_label(lang).is_some(), "{lang:?}");
            assert!(!st.line(lang).is_empty(), "{lang:?}");
        }
    }

    /// The updater prints other lines before the status line; the app reads the last one it can
    /// understand, so a parser that chokes on a log line would be useless.
    #[test]
    fn a_status_line_is_found_among_ordinary_output() {
        let output = "folder: C:\\vigil\nsome progress\nvigil-update-status status=current\n";
        let last = output
            .lines()
            .rev()
            .find(|l| l.contains("vigil-update-status"))
            .expect("found");
        assert_eq!(UpdateState::from_status_line(last), UpdateState::UpToDate);
    }

    /// Every state the updater can print has a distinct sentence in both languages — the parser and
    /// the wording are two halves of one promise.
    #[test]
    fn every_parsed_state_says_something_in_both_languages() {
        let lines = [
            "vigil-update-status status=current",
            "vigil-update-status status=available version=0.7.0 critical=0",
            "vigil-update-status status=available version=0.7.0 critical=1",
            "vigil-update-status status=staged version=0.7.0",
            "vigil-update-status status=nokeys",
            "vigil-update-status status=readonly",
            "vigil-update-status status=unreachable why=silently_dropped",
        ];
        for lang in [Lang::Turkish, Lang::English] {
            for line in lines {
                let st = UpdateState::from_status_line(line);
                let text = st.line(lang);
                assert!(!text.trim().is_empty(), "{line} in {lang:?}");
                assert!(!text.contains("{{"), "{line} in {lang:?}: {text}");
            }
        }
    }
}
