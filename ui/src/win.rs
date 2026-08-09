//! The Win32 shell: a tray icon, its menu, and the small status window.
//!
//! This module deliberately decides nothing. Which menu items exist, whether each is enabled,
//! what the tooltip reads, where the popup goes and what the icon looks like all come from
//! [`crate::model`], which is pure and tested. What is left here is `CreateWindowExW`,
//! `Shell_NotifyIconW`, `TrackPopupMenu` and a paint handler — the part that cannot be unit
//! tested, so there is as little of it as possible.
//!
//! The proxy runs on its own thread and never calls into any of this. A wedged message loop
//! stops the interface and nothing else; traffic keeps flowing. That is the property two of
//! the five deleted iterations did not have.

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, CreateBitmap, CreateDIBSection, CreateSolidBrush, DeleteObject, EndPaint, FillRect,
    InvalidateRect, SetBkMode, SetTextColor, TextOutW, UpdateWindow, BITMAPINFO, BITMAPINFOHEADER,
    DIB_RGB_COLORS, HBRUSH, PAINTSTRUCT, TRANSPARENT,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::HiDpi::GetDpiForWindow;
use windows::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY,
    NOTIFYICONDATAW,
};
use windows::Win32::UI::WindowsAndMessaging::*;

use vigil_core::calibrate::Cache;
use vigil_proxy::{Config, Mode as ProxyMode, Server, Stats};

use crate::lang::{t, tf, Lang};
use crate::model::UpdateState;
use crate::model::{self, Command, Snapshot};

/// Where the update machinery has got to, shared with the background thread that checks.
///
/// A `Mutex` rather than the atomic the language uses, because this one carries a version string and
/// a reason. Held only long enough to read or replace it — never across a syscall, and never while
/// painting.
static UPDATE: std::sync::Mutex<Option<UpdateState>> = std::sync::Mutex::new(None);

fn update_state() -> UpdateState {
    UPDATE
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or(UpdateState::NeverChecked)
}

fn set_update_state(s: UpdateState) {
    if let Ok(mut g) = UPDATE.lock() {
        *g = Some(s);
    }
}

/// `vigil-update.exe`, beside us.
fn updater_path() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("vigil-update.exe")))
        .unwrap_or_else(|| std::path::PathBuf::from("vigil-update.exe"))
}

/// Run `vigil-update.exe --check` and read the one line it prints.
///
/// Shelled out rather than linked, deliberately: linking the updater would put rustls inside this
/// binary, and keeping it out is the whole reason the updater is a separate program. The contract is
/// one line of text and the parser for it is in `model`, tested on Linux.
///
/// Runs on its own thread. A wedged updater on a silently-dropping line is then a separate process
/// with its own deadlines, and closing the application does not wait for it.
fn check_for_updates_in_background(owner: HWND) {
    let exe = updater_path();
    if !exe.exists() {
        set_update_state(UpdateState::Unreachable {
            why: "vigil-update.exe is missing".into(),
        });
        return;
    }
    set_update_state(UpdateState::Checking);
    let hwnd = owner.0 as isize;
    std::thread::spawn(move || {
        let out = no_window(std::process::Command::new(&exe).arg("--check")).output();
        let state = match out {
            Err(e) => UpdateState::Unreachable {
                why: format!("could not run the updater: {e}"),
            },
            Ok(o) => {
                let text = String::from_utf8_lossy(&o.stdout);
                let line = text
                    .lines()
                    .rev()
                    .find(|l| l.contains("vigil-update-status"))
                    .unwrap_or("");
                UpdateState::from_status_line(line)
            }
        };
        set_update_state(state);
        // Remember that we looked, so the details window can tell "nothing to update" from
        // "not looking" — on a line that may be blocking the download those are very different.
        let mut prefs = vigil_platform::prefs::read();
        prefs.last_check = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs());
        let _ = vigil_platform::prefs::write(&prefs);
        // Repaint from the message thread rather than from here.
        unsafe {
            let _ = PostMessageW(
                Some(HWND(hwnd as *mut _)),
                WM_APP_UPDATE,
                WPARAM(0),
                LPARAM(0),
            );
        }
    });
}

/// Our own messages: "start a check" and "a check finished".
///
/// Two rather than one because both ends have to happen on the message thread — the thread that
/// sleeps must not touch a window, and the thread that fetches must not paint.
const WM_APP_START_CHECK: u32 = 0x0400 + 16;
const WM_APP_UPDATE: u32 = 0x0400 + 17;
/// A system-DNS change finished. See [`DNS_RESULT`].
const WM_APP_DNS_DONE: u32 = 0x0400 + 18;

/// The outcome of the system-DNS change now running on a worker thread, if one is.
///
/// The change asks for administrator rights, and the consent dialog blocks until the user answers
/// it — which could be a minute, or never. Doing that inside the `WM_COMMAND` handler froze the
/// tray for exactly that long and left Windows free to paint the app as "not responding". So the
/// work runs on a thread and posts [`WM_APP_DNS_DONE`] back.
static DNS_RESULT: Mutex<Option<Result<bool, DnsFailure>>> = Mutex::new(None);
/// True while a change is in flight, so a second click cannot start a second consent dialog.
///
/// Also read by [`restore_host`]: while this is true the snapshot has been written and an elevated
/// change may already have landed, so "we never engaged" is not something the exit path may assume.
static DNS_BUSY: AtomicBool = AtomicBool::new(false);

/// Why a DNS change did not happen.
///
/// `Refused` is the person answering **No** to the consent dialog. That is an answer, and the one
/// place this product asks for administrator rights is the last place it should punish the careful
/// answer with a box saying something went wrong. It was being flattened into a string one layer
/// too early and shown as `DNS ayarlanamadı:`.
enum DnsFailure {
    Refused,
    Failed(String),
}

impl core::fmt::Display for DnsFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DnsFailure::Refused => f.write_str("declined"),
            DnsFailure::Failed(e) => f.write_str(e),
        }
    }
}

impl From<vigil_platform::dnsclient::Error> for DnsFailure {
    fn from(e: vigil_platform::dnsclient::Error) -> Self {
        match e {
            vigil_platform::dnsclient::Error::Refused => DnsFailure::Refused,
            other => DnsFailure::Failed(other.to_string()),
        }
    }
}

/// Ask, then hand over to the updater and get out of the way.
///
/// The order is the whole safety argument: disengage, **read it back**, and only then spawn. A
/// process that replaces these binaries while the system still points at this one is the 2026-08-06
/// stranding failure with extra steps.
/// How often the background thread wakes to ask whether a check is due.
///
/// Short enough that a machine left on picks up a release the same day, long enough that the thread
/// is doing nothing measurable. The wake is not the check — `prefs.last_check` decides that.
const CHECK_TICK: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// How long between checks, wall-clock, across restarts.
///
/// Six hours rather than a day: on this line a release can be the difference between a program
/// working and not, and a check is one small request through a proxy that is already running. Rather
/// than per-launch, because "once per start" punishes exactly the machines that stay on and rewards
/// the ones that reboot constantly, which is backwards.
const CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(6 * 60 * 60);

/// Start a child process without a console window.
///
/// `vigil-app.exe` is a `windows_subsystem = "windows"` binary, so it has no console of its own — and
/// that means every console child it spawns **allocates a new one**, which appears on the user's
/// desktop as a black rectangle that flashes up and vanishes. The automatic update check does this
/// once or twice a minute after startup, unasked, and a tool whose whole promise is "it sits quietly
/// in the background" cannot be blinking a terminal at people.
///
/// `CREATE_NO_WINDOW` is the documented flag for exactly this. It does not affect stdout capture,
/// which is how the status line still gets read.
fn no_window(cmd: &mut std::process::Command) -> &mut std::process::Command {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW)
}

fn install_update(lang: Lang) {
    let state = update_state();
    let version = match &state {
        UpdateState::Available { version, .. } | UpdateState::Staged { version, .. } => {
            version.clone()
        }
        UpdateState::Interrupted => String::new(),
        _ => return,
    };
    if !confirm(
        &tf(lang, "update.confirm_body", &[("version", &version)]),
        t(lang, "update.confirm_title"),
    ) {
        return;
    }

    // 1. Give the settings back, and check that they went — **both** of them, and against our own
    //    listen address rather than against "any loopback address".
    //
    //    The old test was `c.enabled && c.server.contains("127.0.0.1")`. That is not "the machine
    //    still points at us", it is "the machine points at something on this host", and the two
    //    differ for exactly the people who most need this to work: a user with their own local proxy
    //    (Clash, v2rayN, Fiddler, ByeDPI) has a restored, correct, *foreign* setting that matches
    //    the old predicate, so the update aborted every time with a dialog accusing their machine of
    //    being stranded. `points_at_us` compares the listen address, and it is already tested.
    //
    //    The environment arm was missing entirely, while `docs/18` §6 claimed both were read back —
    //    and the environment is the half that matters for Roblox, which ignores the registry
    //    setting. A `HTTPS_PROXY` left naming a vigil that is about to be replaced is the 2026-08-06
    //    failure in the variables instead of the registry.
    let listen = with_app(|a| a.listen.clone()).unwrap_or_default();
    let _ = engage(false, &listen);
    set_engaged(false);

    let registry_ours = vigil_platform::registry::read_current()
        .map(|c| vigil_platform::sysproxy::points_at_us(&c, &listen))
        .unwrap_or(false);
    let env_ours = vigil_platform::envreg::read_current()
        .map(|e| vigil_platform::envproxy::points_at_us(&e, &listen))
        .unwrap_or(false);
    if registry_ours || env_ours {
        let which = match (registry_ours, env_ours) {
            (true, true) => "the proxy setting and the environment variables would not come back",
            (true, false) => "the proxy setting would not come back",
            _ => "the proxy environment variables would not come back",
        };
        message_box(&tf(lang, "update.failed", &[("why", which)]));
        // Nothing has been replaced and nothing is staged differently, so the honest thing is to go
        // back to protecting the user rather than leaving them disengaged after a refused update.
        let _ = engage(true, &listen);
        set_engaged(true);
        return;
    }

    // 1b. Give the resolver back too, **before** the runner exists.
    //
    //     This is the one operation in the shutdown path that can block on a UAC prompt, and the
    //     runner starts a 30-second wait for this process to exit the moment it is spawned. Doing it
    //     afterwards — which is what `restore_host()` on the way out amounts to — puts a consent
    //     dialog the user may not answer inside that window: the runner gives up, changes nothing,
    //     and the user is left disengaged with an update that did not happen. Doing it here costs the
    //     same prompt at a moment when nothing is waiting on it.
    if with_app(|a| a.dns_engaged).unwrap_or(false) {
        if let Err(e) = set_system_dns(false) {
            message_box(&tf(lang, "update.failed", &[("why", &e.to_string())]));
            let _ = engage(true, &listen);
            set_engaged(true);
            return;
        }
        APP.with(|a| {
            if let Some(app) = a.borrow_mut().as_mut() {
                app.dns_engaged = false;
            }
        });
    }

    // 2. Copy the updater into the staging folder and run *that*, so the one beside us is idle and
    //    can be replaced like any other file.
    let folder = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_default();
    let me = updater_path();
    let runner = match std::fs::create_dir_all(folder.join(".vigil-update")).and_then(|_| {
        let dst = folder.join(".vigil-update").join("runner.exe");
        std::fs::copy(&me, &dst).map(|_| dst)
    }) {
        Ok(p) => p,
        Err(e) => {
            message_box(&tf(lang, "update.failed", &[("why", &e.to_string())]));
            return;
        }
    };

    // 3. Hand over. It waits for this process to exit before it touches anything.
    let pid = std::process::id().to_string();
    match std::process::Command::new(&runner)
        // `--listen` so the runner's independent guard can ask whether the machine points at *us*
        // rather than at any loopback address. Only this process knows what it was serving on.
        .args(["--apply", "--parent", &pid, "--listen", &listen])
        .spawn()
    {
        Ok(_) => {
            // 4. Leave. Everything after this belongs to the runner, and the ordering means every
            //    way it can fail leaves the machine disengaged — which means the internet works.
            unsafe {
                PostQuitMessage(0);
            }
        }
        Err(e) => message_box(&tf(lang, "update.failed", &[("why", &e.to_string())])),
    }
}

/// A yes/no question. Used once, for the one action that closes the application.
fn confirm(text: &str, title: &str) -> bool {
    let msg = model::wide(text);
    let title = model::wide(title);
    unsafe {
        MessageBoxW(
            None,
            PCWSTR(msg.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_YESNO | MB_ICONQUESTION,
        ) == IDYES
    }
}

/// The language the interface speaks, decided once and then remembered.
///
/// Windows' UI language cannot change under a running process, so asking the operating system
/// on every repaint would be a syscall in the message loop for a constant. `VIGIL_LANG`
/// overrides it, which is how the other language gets tested without changing Windows' own
/// settings.
fn lang() -> Lang {
    match CURRENT_LANG.load(std::sync::atomic::Ordering::Relaxed) {
        LANG_UNSET => {
            let chosen = decide_lang();
            set_lang(chosen);
            chosen
        }
        LANG_TURKISH => Lang::Turkish,
        _ => Lang::English,
    }
}

/// Where the language decision is made, in precedence order:
///
/// 1. `VIGIL_LANG`, an explicit override for this run — a developer or a curious user.
/// 2. What the user last picked from the menu, remembered on disk.
/// 3. Windows' own UI language.
///
/// The environment wins over the saved choice on purpose: it is the escape hatch, and an escape
/// hatch that a stored preference can veto is not one.
fn decide_lang() -> Lang {
    Lang::decide(
        vigil_platform::locale::ui_langid(),
        vigil_platform::locale::saved_lang().as_deref(),
        vigil_platform::locale::lang_override().as_deref(),
    )
}

/// The language in force right now. An atomic rather than a `OnceLock`, because the menu can
/// change it while the program runs and every window has to start reading the other language
/// from the next repaint onward.
static CURRENT_LANG: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(LANG_UNSET);
const LANG_UNSET: u8 = 0;
const LANG_TURKISH: u8 = 1;
const LANG_ENGLISH: u8 = 2;

fn set_lang(l: Lang) {
    let v = match l {
        Lang::Turkish => LANG_TURKISH,
        Lang::English => LANG_ENGLISH,
    };
    CURRENT_LANG.store(v, std::sync::atomic::Ordering::Relaxed);
}

/// The message the tray icon sends us. Anything at or above `WM_APP` is ours to define.
const WM_TRAY: u32 = WM_APP + 1;
/// Refresh on a timer, so the numbers stay alive without the proxy ever having to know the
/// interface exists.
const TIMER_REFRESH: usize = 1;
/// `VK_ESCAPE`. Spelled out rather than pulling in the whole keyboard-input feature for one
/// constant that has not changed since Windows 3.
const VK_ESCAPE: usize = 0x1B;

const MINI_W: i32 = 300;
const MINI_H: i32 = 170;
const FULL_W: i32 = 460;
const FULL_H: i32 = 560;

struct App {
    listen: String,
    /// The running proxy, so the menu can change what it does rather than only report it.
    /// Held as the engine's own handle: the mode the interface shows and the mode connections
    /// are served with are then the same value, not two copies that can drift.
    server: Arc<Server>,
    stats: Arc<Stats>,
    cache: Arc<Mutex<Cache>>,
    /// Created once, then shown and hidden. Rebuilding it per click would flicker.
    mini: HWND,
    full: HWND,
    tray_owner: HWND,
    engaged: bool,
    /// Where the learned strategies live, so forgetting one survives a restart. Forgetting a
    /// host in memory only would come back the next time the app started, which reads as the
    /// button not working.
    cache_path: Option<std::path::PathBuf>,
    /// How far the details window is scrolled, in pixels.
    scroll: i32,
    /// Cleared when the accept loop returns. Read rather than assumed: the whole `Stranded`
    /// health state — and with it the Repair menu item and the warning icon — is unreachable
    /// if this is a constant, which is exactly what it was until it was measured.
    serving: Arc<AtomicBool>,
    /// Our own path, so the autostart entry can name it and be recognised again later.
    exe: std::path::PathBuf,
    /// The DNS server's counters, or `None` if the port could not be bound at all.
    ///
    /// Held rather than a `bool`, because a `bool` computed at bind time is a claim about the past.
    /// `serve` can return — a socket that really has died, 64 unrecognised errors in a row — and
    /// the tray used to keep saying "DNS is served" for the life of the process. Every website
    /// failing while the tool looks healthy is the worst shape a failure can take.
    dns: Option<Arc<vigil_proxy::dnsserver::DnsStats>>,
    /// Whether Windows' own resolver is pointed at us. Cached rather than read per refresh: the
    /// tray refreshes once a second, and this only changes when the user asks it to.
    dns_engaged: bool,
}

thread_local! {
    static APP: RefCell<Option<App>> = const { RefCell::new(None) };
}

impl App {
    fn snapshot(&self) -> Snapshot {
        use std::sync::atomic::Ordering::Relaxed;
        let learned: Vec<(String, String)> = self
            .cache
            .lock()
            .map(|c| {
                c.hosts()
                    .map(|h| {
                        let s = c.get(h).map(|s| s.to_string()).unwrap_or_default();
                        (h.to_string(), s)
                    })
                    .collect()
            })
            .unwrap_or_default();
        let prefs = vigil_platform::prefs::read();
        Snapshot {
            lang: lang(),
            version: env!("CARGO_PKG_VERSION").into(),
            update: update_state(),
            auto_update: prefs.enabled,
            last_check: prefs
                .last_check
                .map(vigil_core::clock::iso8601)
                .unwrap_or_default(),
            listen: self.listen.clone(),
            engaged: self.engaged,
            listening: self.serving.load(AtomicOrdering::Relaxed),
            mode: match self.server.mode() {
                ProxyMode::Auto => model::Mode::Auto,
                ProxyMode::Fixed(s) => model::Mode::Fixed(s.to_string()),
            },
            accepted: self.stats.accepted.load(Relaxed),
            completed: self.stats.completed.load(Relaxed),
            transformed: self.stats.transformed.load(Relaxed),
            excluded: self.stats.excluded.load(Relaxed),
            handshake_errors: self.stats.handshake_errors.load(Relaxed),
            upstream_errors: self.stats.upstream_errors.load(Relaxed),
            dns_failures: self.stats.dns_failures.load(Relaxed),
            first_flight_retries: self.stats.first_flight_retries.load(Relaxed),
            dns_serving: self.dns.as_ref().is_some_and(|d| d.serving()),
            dns_engaged: self.dns_engaged,
            by_socks5: self.stats.by_socks5.load(Relaxed),
            by_socks4: self.stats.by_socks4.load(Relaxed),
            by_http_connect: self.stats.by_http_connect.load(Relaxed),
            autostart: vigil_platform::autostart::is_enabled(&self.exe),
            learned,
            exclude_patterns: Vec::new(),
        }
    }
}

/// Read something out of the shared state, releasing the borrow before returning.
///
/// Nothing may hold a `RefCell` borrow across a Win32 call. Several of them pump messages
/// while they run — `UpdateWindow` dispatches `WM_PAINT` synchronously, and the shell APIs
/// can too — so a borrow held over one of those re-enters a window procedure that borrows
/// again. Two shared borrows are harmless; a shared borrow taken while a mutable one is
/// alive panics, and a panic inside a window procedure takes the process with it.
///
/// So: copy out, drop the borrow, then call Windows.
fn with_app<T>(f: impl FnOnce(&App) -> T) -> Option<T> {
    APP.with(|a| a.borrow().as_ref().map(f))
}

fn snapshot_now() -> Option<Snapshot> {
    with_app(|a| a.snapshot())
}

/// The window handles and listen address, copied out so no borrow outlives this call.
fn handles() -> Option<(HWND, HWND, String)> {
    with_app(|a| (a.tray_owner, a.mini, a.listen.clone()))
}

fn full_window() -> Option<HWND> {
    with_app(|a| a.full)
}

fn set_engaged(v: bool) {
    APP.with(|a| {
        if let Some(app) = a.borrow_mut().as_mut() {
            app.engaged = v;
        }
    });
}

// ------------------------------------------------------------------------------ icon

/// Turn the model's pixels into an `HICON`.
///
/// A 32-bit top-down DIB plus a matching mask. The mask has to exist even though the alpha
/// channel does the work — omitting it produces an icon that is invisible on some Windows
/// versions and fine on others, which is the worst kind of bug to chase.
unsafe fn make_icon(state: model::IconState, size: i32) -> Option<HICON> {
    let px = model::icon_argb(state, size as usize);
    let mut bits: *mut core::ffi::c_void = core::ptr::null_mut();
    let bi = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: core::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: size,
            // Negative height means top-down, matching the model's row order.
            biHeight: -size,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    let colour = unsafe { CreateDIBSection(None, &bi, DIB_RGB_COLORS, &mut bits, None, 0) }.ok()?;
    if bits.is_null() {
        unsafe {
            let _ = DeleteObject(colour.into());
        }
        return None;
    }
    unsafe { core::ptr::copy_nonoverlapping(px.as_ptr(), bits as *mut u32, px.len()) };
    let mask = unsafe { CreateBitmap(size, size, 1, 1, None) };

    let info = ICONINFO {
        fIcon: true.into(),
        xHotspot: 0,
        yHotspot: 0,
        hbmMask: mask,
        hbmColor: colour,
    };
    let icon = unsafe { CreateIconIndirect(&info) }.ok();
    unsafe {
        let _ = DeleteObject(colour.into());
        let _ = DeleteObject(mask.into());
    }
    icon
}

// ------------------------------------------------------------------------------ tray

fn tray_data(owner: HWND, icon: Option<HICON>, tip: Option<&str>) -> NOTIFYICONDATAW {
    let mut d = NOTIFYICONDATAW {
        cbSize: core::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: owner,
        uID: 1,
        uCallbackMessage: WM_TRAY,
        uFlags: NIF_MESSAGE,
        ..Default::default()
    };
    if let Some(i) = icon {
        d.hIcon = i;
        d.uFlags |= NIF_ICON;
    }
    if let Some(t) = tip {
        d.uFlags |= NIF_TIP;
        // The model already clipped this to what Windows will show. Copying more would be
        // truncated here instead, where no test could see it happen.
        for (i, ch) in model::wide(t).into_iter().take(127).enumerate() {
            d.szTip[i] = ch;
        }
    }
    d
}

/// Takes the snapshot by value rather than reaching for it, so no `RefCell` borrow is alive
/// while the shell is called — see [`with_app`].
unsafe fn refresh_tray(owner: HWND, snap: &Snapshot) {
    let icon = unsafe { make_icon(model::IconState::of(snap), 32) };
    let d = tray_data(owner, icon, Some(&model::tooltip(snap)));
    unsafe {
        let _ = Shell_NotifyIconW(NIM_MODIFY, &d);
        if let Some(i) = icon {
            let _ = DestroyIcon(i);
        }
    }
}

// ------------------------------------------------------------------------- mini window

unsafe fn show_mini(mini: HWND) {
    let dpi = unsafe { GetDpiForWindow(mini) };
    let (w, h) = (model::scale(MINI_W, dpi), model::scale(MINI_H, dpi));

    // The cursor stands in for the icon: the tray's own rectangle is awkward to obtain
    // reliably across Windows versions, and the cursor is inside the icon when it is clicked.
    let mut pt = POINT::default();
    let _ = unsafe { GetCursorPos(&mut pt) };
    let tray = model::Rect::new(pt.x - 8, pt.y - 8, pt.x + 8, pt.y + 8);

    let mut work = RECT::default();
    let _ = unsafe {
        SystemParametersInfoW(
            SPI_GETWORKAREA,
            0,
            Some(&mut work as *mut RECT as *mut core::ffi::c_void),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
    };
    let work = model::Rect::new(work.left, work.top, work.right, work.bottom);
    let (x, y) = model::popup_position(tray, work, (w, h));

    unsafe {
        let _ = SetWindowPos(mini, None, x, y, w, h, SWP_SHOWWINDOW | SWP_NOZORDER);
        let _ = ShowWindow(mini, SW_SHOW);
        let _ = SetForegroundWindow(mini);
        // Dispatches WM_PAINT synchronously, which is exactly why no borrow may be alive here.
        let _ = UpdateWindow(mini);
    }
}

unsafe fn paint_mini(hwnd: HWND) {
    let mut ps = PAINTSTRUCT::default();
    let hdc = unsafe { BeginPaint(hwnd, &mut ps) };
    let mut rc = RECT::default();
    let _ = unsafe { GetClientRect(hwnd, &mut rc) };

    unsafe {
        let bg = CreateSolidBrush(COLORREF(0x001F1F1E));
        FillRect(hdc, &rc, bg);
        let _ = DeleteObject(bg.into());
        SetBkMode(hdc, TRANSPARENT);
    }

    if let Some(snap) = snapshot_now() {
        let dpi = unsafe { GetDpiForWindow(hwnd) };
        let pad = model::scale(14, dpi);
        let line = model::scale(22, dpi);
        let mut y = pad;

        let draw = |text: &str, colour: u32, y: i32| {
            let w = model::wide(text);
            unsafe {
                SetTextColor(hdc, COLORREF(colour));
                let _ = TextOutW(hdc, pad, y, &w[..w.len() - 1]);
            }
        };

        draw(&model::status_line(&snap), 0x00E8E8E8, y);
        y += line + model::scale(6, dpi);
        for (label, value) in model::counters(&snap) {
            draw(&format!("{label}: {value}"), 0x00B0B0B0, y);
            y += line;
        }
        y += model::scale(6, dpi);
        draw(t(lang(), "window.popup_hint"), 0x00707070, y);
    }

    let _ = unsafe { EndPaint(hwnd, &ps) };
}

// ------------------------------------------------------------------------ full window

unsafe fn show_full(full: HWND) {
    unsafe {
        let _ = ShowWindow(full, SW_SHOW);
        let _ = SetForegroundWindow(full);
        let _ = InvalidateRect(Some(full), None, true);
        let _ = UpdateWindow(full);
    }
}

/// The laid-out lines and the current scroll, computed the same way for painting and for
/// hit-testing so the two can never disagree about which row is where.
fn full_lines(hwnd: HWND) -> Option<(Vec<model::Line>, i32, u32)> {
    let snap = snapshot_now()?;
    let dpi = unsafe { GetDpiForWindow(hwnd) };
    let lines = model::layout_lines(&model::full_view(&snap), dpi, model::scale(12, dpi));
    let mut rc = RECT::default();
    let _ = unsafe { GetClientRect(hwnd, &mut rc) };
    let view = rc.bottom - rc.top;
    let content = model::content_height(&lines, dpi) + model::scale(12, dpi);
    let scroll = model::clamp_scroll(with_app(|a| a.scroll).unwrap_or(0), content, view);
    Some((lines, scroll, dpi))
}

unsafe fn paint_full(hwnd: HWND) {
    let mut ps = PAINTSTRUCT::default();
    let hdc = unsafe { BeginPaint(hwnd, &mut ps) };
    let mut rc = RECT::default();
    let _ = unsafe { GetClientRect(hwnd, &mut rc) };
    unsafe {
        let bg = CreateSolidBrush(COLORREF(0x001F1F1E));
        FillRect(hdc, &rc, bg);
        let _ = DeleteObject(bg.into());
        SetBkMode(hdc, TRANSPARENT);
    }

    if let Some((lines, scroll, dpi)) = full_lines(hwnd) {
        let pad = model::scale(14, dpi);
        for l in &lines {
            let y = l.y - scroll;
            if y < -model::scale(model::ROW_H, dpi) || y > rc.bottom {
                continue;
            }
            let colour = if l.header {
                0x00E8E8E8
            } else if l.action.is_some() {
                0x009AD8FF
            } else {
                0x00B0B0B0
            };
            let indent = if l.header {
                pad
            } else {
                pad + model::scale(12, dpi)
            };
            let w = model::wide(&l.text);
            unsafe {
                SetTextColor(hdc, COLORREF(colour));
                let _ = TextOutW(hdc, indent, y, &w[..w.len() - 1]);
            }
        }
    }
    let _ = unsafe { EndPaint(hwnd, &ps) };
}

unsafe extern "system" fn fullproc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    match msg {
        WM_PAINT => {
            unsafe { paint_full(hwnd) };
            LRESULT(0)
        }
        WM_LBUTTONUP => {
            // The y in lParam is client-relative; the lines are laid out in content
            // coordinates, so the scroll has to be added back before testing.
            let y = ((l.0 >> 16) & 0xFFFF) as i16 as i32;
            if let Some((lines, scroll, dpi)) = full_lines(hwnd) {
                if let Some(cmd) = model::hit_test(&lines, y + scroll, dpi) {
                    apply(cmd);
                }
            }
            LRESULT(0)
        }
        WM_MOUSEWHEEL => {
            let delta = ((w.0 >> 16) & 0xFFFF) as i16 as i32;
            APP.with(|a| {
                if let Some(app) = a.borrow_mut().as_mut() {
                    app.scroll -= delta / 2;
                }
            });
            unsafe {
                let _ = InvalidateRect(Some(hwnd), None, true);
            }
            LRESULT(0)
        }
        // Closing the details window must not close the application: it lives in the tray.
        WM_CLOSE => {
            let _ = unsafe { ShowWindow(hwnd, SW_HIDE) };
            LRESULT(0)
        }
        WM_KEYDOWN if w.0 == VK_ESCAPE => {
            let _ = unsafe { ShowWindow(hwnd, SW_HIDE) };
            LRESULT(0)
        }
        WM_SIZE => {
            unsafe {
                let _ = InvalidateRect(Some(hwnd), None, true);
            }
            LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, w, l) },
    }
}

// ---------------------------------------------------------------------------- commands

/// Carry out a command. Returns `false` when the application should stop.
fn apply(cmd: Command) -> bool {
    match cmd {
        Command::Quit => return false,
        Command::ShowMini => {
            if let Some((_, mini, _)) = handles() {
                unsafe { show_mini(mini) };
            }
        }
        Command::Toggle => {
            let Some((owner, _, listen)) = handles() else {
                return true;
            };
            let want = !with_app(|a| a.engaged).unwrap_or(false);
            // Every decision about *whether* to touch the registry lives in
            // `vigil_platform::engage` and is tested there; this only reports the outcome.
            if engage(want, &listen).is_ok() {
                set_engaged(want);
            }
            if let Some(snap) = snapshot_now() {
                unsafe { refresh_tray(owner, &snap) };
            }
        }
        Command::Repair => {
            let _ = repair();
            set_engaged(false);
            if let (Some((owner, _, _)), Some(snap)) = (handles(), snapshot_now()) {
                unsafe { refresh_tray(owner, &snap) };
            }
        }
        Command::SetLang(l) => {
            if l != lang() {
                set_lang(l);
                // Best effort. A preference that fails to save is a preference the user sets
                // again next time; refusing to change the language over it would be worse.
                let _ = vigil_platform::locale::save_lang(l.tag());
                // Everything on screen is now in the wrong language: the tooltip, the popup and
                // the details window all re-render from the snapshot, and the menu is rebuilt
                // the next time it is opened.
                if let (Some((owner, mini, _)), Some(snap)) = (handles(), snapshot_now()) {
                    unsafe {
                        refresh_tray(owner, &snap);
                        let _ = InvalidateRect(Some(mini), None, true);
                    }
                }
                if let Some(full) = full_window() {
                    // The details window carries its language in its title bar as well as its
                    // body, and a title is set once at creation rather than painted.
                    let title = model::wide(t(l, "window.details_title"));
                    unsafe {
                        let _ = SetWindowTextW(full, PCWSTR(title.as_ptr()));
                        let _ = InvalidateRect(Some(full), None, true);
                    }
                }
            }
        }
        Command::CheckForUpdates => {
            if let Some((owner, _, _)) = handles() {
                check_for_updates_in_background(owner);
                if let Some(snap) = snapshot_now() {
                    unsafe { refresh_tray(owner, &snap) };
                }
            }
        }
        Command::InstallUpdate => install_update(lang()),
        Command::ToggleAutoUpdate => {
            let mut prefs = vigil_platform::prefs::read();
            prefs.enabled = !prefs.enabled;
            let _ = vigil_platform::prefs::write(&prefs);
            // Switching it off says so on screen straight away rather than at the next check.
            if !prefs.enabled {
                set_update_state(UpdateState::Off);
            } else if update_state() == UpdateState::Off {
                set_update_state(UpdateState::NeverChecked);
            }
            if let (Some((owner, _, _)), Some(snap)) = (handles(), snapshot_now()) {
                unsafe { refresh_tray(owner, &snap) };
            }
        }
        Command::ToggleAutostart => {
            let Some((owner, _, _)) = handles() else {
                return true;
            };
            let (exe, on) = match with_app(|a| (a.exe.clone(), a.snapshot().autostart)) {
                Some(v) => v,
                None => return true,
            };
            if let Err(e) = vigil_platform::autostart::set(!on, &exe) {
                message_box(&tf(lang(), "err.autostart", &[("error", &e.to_string())]));
            }
            if let Some(snap) = snapshot_now() {
                unsafe { refresh_tray(owner, &snap) };
            }
        }
        Command::ShowFull => {
            if let Some(full) = full_window() {
                unsafe { show_full(full) };
            }
        }
        Command::Forget(h) => {
            forget(Some(&h));
            repaint_full();
        }
        Command::ForgetAll => {
            forget(None);
            repaint_full();
        }
        Command::ToggleSystemDns => {
            // **Off the message thread.** Reading the interfaces is fast now, but the write asks for
            // administrator rights and the consent dialog blocks until the user answers — a minute,
            // or never. Doing that here froze the tray for exactly that long, which is most of what
            // the owner reported as "it takes ages to react".
            if DNS_BUSY.swap(true, AtomicOrdering::SeqCst) {
                return true; // Already asking; a second dialog would be worse than a slow first one.
            }
            let want = !with_app(|a| a.dns_engaged).unwrap_or(false);
            // No window means nothing can be told the answer: `PostMessageW` with a null `hWnd`
            // posts to the *calling* thread, which here is a worker with no message loop, so the
            // completion would be discarded and `DNS_BUSY` would stay true for the life of the
            // process — a menu item that never works again, silently.
            let Some((owner, _, _)) = handles() else {
                DNS_BUSY.store(false, AtomicOrdering::SeqCst);
                return true;
            };
            let owner_bits = owner.0 as isize;
            std::thread::spawn(move || {
                let outcome = set_system_dns(want);
                if let Ok(mut g) = DNS_RESULT.lock() {
                    *g = Some(outcome);
                }
                unsafe {
                    let _ = PostMessageW(
                        Some(HWND(owner_bits as *mut _)),
                        WM_APP_DNS_DONE,
                        WPARAM(0),
                        LPARAM(0),
                    );
                }
            });
            // Repaint now so the menu closes and the interface stays alive while the prompt is up.
            repaint_full();
        }
        Command::SetMode(m) => {
            let want = match &m {
                model::Mode::Auto => Some(ProxyMode::Auto),
                model::Mode::Fixed(spec) => vigil_core::strategy::Strategy::parse(spec)
                    .ok()
                    .map(ProxyMode::Fixed),
            };
            // A spec that does not parse can only come from a menu entry the model made up,
            // and `model::tests::every_offered_mode_parses_and_round_trips` exists so it
            // cannot. Saying so beats silently doing nothing if that test is ever weakened.
            let Some(want) = want else {
                message_box(&tf(lang(), "err.unknown_mode", &[("mode", &m.to_string())]));
                return true;
            };
            with_app(|a| a.server.set_mode(want));
            if let (Some((owner, _, _)), Some(snap)) = (handles(), snapshot_now()) {
                unsafe { refresh_tray(owner, &snap) };
            }
            repaint_full();
        }
    }
    true
}

fn repaint_full() {
    if let Some(full) = full_window() {
        unsafe {
            let _ = InvalidateRect(Some(full), None, true);
        }
    }
}

fn engage(on: bool, listen: &str) -> Result<(), String> {
    // The environment variables go first when engaging and last when disengaging, so at no
    // point is a client told to use a proxy that the registry says is not there.
    let env = engage_env(on, listen);
    let r = engage_registry(on, listen);
    // Both are reported, but the registry's failure is the one that decides the outcome: it
    // is what the interface's engaged/stranded state is read from.
    match (&r, env) {
        (_, Err(e)) => eprintln!("environment proxy: {e}"),
        (_, Ok(())) => {}
    }
    r
}

/// The curl-convention variables, which are how applications that ignore the system proxy are
/// reached. Measured 2026-08-05: the Roblox client opens five direct sockets and none to the
/// proxy with the registry setting alone, and 64 to the proxy with these set.
fn engage_env(on: bool, listen: &str) -> Result<(), String> {
    use vigil_platform::{envproxy, envreg, paths};
    let current = envreg::read_current().map_err(|x| x.to_string())?;
    if on {
        match envproxy::start(&current, listen) {
            envproxy::Start::AlreadyEngaged => Ok(()),
            // Somebody else's proxy variables. Overwriting them would break whatever set them
            // — a corporate policy, or the user's own tooling — so vigil stays out and says so.
            envproxy::Start::Occupied => {
                Err("HTTP_PROXY is already set by something else; left alone".to_string())
            }
            envproxy::Start::Engage { apply, snapshot } => {
                if let Some(p) = paths::env_snapshot() {
                    if let Some(d) = p.parent() {
                        let _ = std::fs::create_dir_all(d);
                    }
                    std::fs::write(&p, envproxy::snapshot_to_text(&snapshot))
                        .map_err(|x| x.to_string())?;
                }
                envreg::apply(&apply).map_err(|x| x.to_string())
            }
        }
    } else {
        let snap = paths::env_snapshot()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|t| envproxy::snapshot_from_text(&t));
        match envproxy::stop(&current, snap.as_ref(), listen) {
            envproxy::Stop::NotOurs => Ok(()),
            envproxy::Stop::Restore(s) => {
                envreg::apply(&s).map_err(|x| x.to_string())?;
                if let Some(p) = paths::env_snapshot() {
                    let _ = std::fs::remove_file(p);
                }
                Ok(())
            }
        }
    }
}

fn engage_registry(on: bool, listen: &str) -> Result<(), String> {
    use vigil_platform::{engage as e, paths, registry, sysproxy};
    let current = registry::read_current().map_err(|x| x.to_string())?;
    if on {
        match e::start(&current, listen) {
            e::Start::AlreadyEngaged => Ok(()),
            e::Start::Engage { apply, snapshot } => {
                // Written before the registry changes, so a crash in between is recoverable.
                if let Some(p) = paths::snapshot() {
                    if let Some(d) = p.parent() {
                        let _ = std::fs::create_dir_all(d);
                    }
                    std::fs::write(&p, sysproxy::snapshot_to_text(&snapshot))
                        .map_err(|x| x.to_string())?;
                }
                registry::apply(&apply).map_err(|x| x.to_string())
            }
        }
    } else {
        let snap = paths::snapshot()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|t| sysproxy::snapshot_from_text(&t));
        match e::stop(&current, snap.as_ref(), listen) {
            e::Stop::NotOurs => Ok(()),
            e::Stop::Restore(s) => {
                registry::apply(&s).map_err(|x| x.to_string())?;
                // Only after the restore succeeded, so a half-finished shutdown still leaves
                // `vigil-repair` something to work with.
                if let Some(p) = paths::snapshot() {
                    let _ = std::fs::remove_file(p);
                }
                Ok(())
            }
        }
    }
}

/// Drop one learned strategy, or all of them, and write the cache back out.
fn forget(host: Option<&str>) {
    APP.with(|a| {
        let b = a.borrow();
        let Some(app) = b.as_ref() else { return };
        let Ok(mut c) = app.cache.lock() else { return };
        match host {
            Some(h) => {
                c.forget(h);
            }
            None => {
                let all: Vec<String> = c.hosts().map(|h| h.to_string()).collect();
                for h in all {
                    c.forget(&h);
                }
            }
        }
        // Persisted immediately: a forget that only happened in memory would reappear on the
        // next start, which reads as the button not working.
        if let Some(p) = &app.cache_path {
            if let Some(d) = p.parent() {
                let _ = std::fs::create_dir_all(d);
            }
            let _ = std::fs::write(p, c.to_text());
        }
    });
}

/// Point Windows' resolver at us, or put it back. Returns whether it is ours afterwards.
///
/// The elevation prompt is deliberate and visible: this is the one change vigil makes that can
/// take a machine's name resolution down, so it snapshots first and always writes a public
/// fallback after itself. Everything about *what* to write is decided in
/// `vigil_platform::sysdns`, which is pure and tested.
/// Is any interface pointed at us, right now, according to Windows?
///
/// `None` when the interfaces could not be read at all, which is the only case where there is
/// nothing better to do than keep believing what was there before.
fn read_back_dns_engaged() -> Option<bool> {
    use vigil_platform::{dnsclient, sysdns};

    dnsclient::read_interfaces()
        .ok()
        .map(|ifaces| !sysdns::stranded(&ifaces).is_empty())
}

fn set_system_dns(on: bool) -> Result<bool, DnsFailure> {
    use vigil_platform::{dnsclient, paths, sysdns};

    let apply = dnsclient::apply;

    let ifaces = dnsclient::read_interfaces()?;
    let path = paths::dns_snapshot();
    if on {
        let targets: Vec<sysdns::Interface> =
            sysdns::targets(&ifaces).into_iter().cloned().collect();
        if targets.is_empty() {
            return Ok(!sysdns::stranded(&ifaces).is_empty());
        }
        let p = path.ok_or_else(|| DnsFailure::Failed("nowhere to save a snapshot".into()))?;
        if let Some(dir) = p.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        // Before the change, always: a machine whose resolver we moved without a record of
        // where it was is one that even the repair tool can only guess about.
        std::fs::write(&p, sysdns::snapshot_to_text(&targets))
            .map_err(|e| DnsFailure::Failed(e.to_string()))?;
        let changes: Vec<(u32, Option<Vec<String>>)> = targets
            .iter()
            .map(|i| (i.index, Some(sysdns::ours())))
            .collect();
        if let Err(e) = apply(&changes) {
            // **A record that outlives the change it was taken for is a lie about the machine.**
            // The snapshot is written before the prompt, deliberately; when the prompt is declined
            // it used to stay on disk saying the resolver had been moved when it had not. Found by
            // the live gate on 2026-08-09, not by a test.
            //
            // Checked rather than assumed, because a batch can now fail with some of its interfaces
            // already done — and in *that* case the snapshot is the only way back and must survive.
            let landed = dnsclient::read_interfaces()
                .map(|now| !sysdns::stranded(&now).is_empty())
                .unwrap_or(true);
            if !landed {
                let _ = std::fs::remove_file(&p);
            }
            return Err(e.into());
        }
        Ok(true)
    } else {
        let stranded: Vec<sysdns::Interface> =
            sysdns::stranded(&ifaces).into_iter().cloned().collect();
        if stranded.is_empty() {
            return Ok(false);
        }
        let snapshot: Vec<sysdns::Interface> = path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|t| sysdns::parse(&t))
            .unwrap_or_default();
        let changes: Vec<(u32, Option<Vec<String>>)> = stranded
            .iter()
            .map(|i| {
                (
                    i.index,
                    snapshot
                        .iter()
                        .find(|s| s.index == i.index)
                        .and_then(sysdns::restore_value),
                )
            })
            .collect();
        apply(&changes)?;
        if let Some(p) = &path {
            let _ = std::fs::remove_file(p);
        }
        Ok(false)
    }
}

fn repair() -> Result<(), String> {
    let listen = with_app(|a| a.listen.clone()).unwrap_or_default();
    engage(false, &listen)
}

// ------------------------------------------------------------------------ window procs

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    match msg {
        // The background check finished. Repaint from here rather than from the thread that did the
        // work: the interface is painted by one thread and only one.
        WM_APP_START_CHECK => {
            check_for_updates_in_background(hwnd);
            if let Some(snap) = snapshot_now() {
                unsafe { refresh_tray(hwnd, &snap) };
            }
            LRESULT(0)
        }
        WM_APP_DNS_DONE => {
            DNS_BUSY.store(false, AtomicOrdering::SeqCst);
            let outcome = DNS_RESULT.lock().ok().and_then(|mut g| g.take());
            // **Read the machine, do not believe the return value.** Once a failing `netsh` inside
            // the batch could fail the whole batch, "it returned an error" stopped meaning "nothing
            // changed": a batch where one interface landed and another's index was stale reports
            // failure with the first interface really pointed at us. Believing the return value
            // there leaves `dns_engaged` false while the machine is engaged, so the exit path skips
            // the restore and the machine boots pointed at a vigil that is not running — which is
            // the one failure this whole file is organised around.
            //
            // The read costs 0.01 s now. That it is affordable is the entire point of the change
            // this handler belongs to, so there is no excuse for guessing instead.
            let live = read_back_dns_engaged();
            match outcome {
                Some(Ok(now)) => {
                    APP.with(|a| {
                        if let Some(app) = a.borrow_mut().as_mut() {
                            app.dns_engaged = live.unwrap_or(now);
                        }
                    });
                }
                // Declining the prompt is an answer, not a fault: no box. The state still comes
                // from the machine — a declined prompt changed nothing, and the read says so.
                Some(Err(DnsFailure::Refused)) => {
                    APP.with(|a| {
                        if let (Some(app), Some(live)) = (a.borrow_mut().as_mut(), live) {
                            app.dns_engaged = live;
                        }
                    });
                }
                // A failure is not "nothing happened" — see above. Say so, and then believe the
                // machine about what the state now is.
                Some(Err(DnsFailure::Failed(e))) => {
                    APP.with(|a| {
                        if let (Some(app), Some(live)) = (a.borrow_mut().as_mut(), live) {
                            app.dns_engaged = live;
                        }
                    });
                    message_box(&tf(lang(), "err.dns", &[("error", &e)]))
                }
                None => {}
            }
            if let Some(snap) = snapshot_now() {
                unsafe { refresh_tray(hwnd, &snap) };
            }
            repaint_full();
            LRESULT(0)
        }
        WM_APP_UPDATE => {
            if let Some(snap) = snapshot_now() {
                unsafe { refresh_tray(hwnd, &snap) };
            }
            if let Some(full) = full_window() {
                unsafe {
                    let _ = InvalidateRect(Some(full), None, true);
                }
            }
            LRESULT(0)
        }
        WM_TRAY => {
            match (l.0 as u32) & 0xFFFF {
                WM_LBUTTONUP => {
                    apply(Command::ShowMini);
                }
                WM_RBUTTONUP => unsafe { show_menu(hwnd) },
                _ => {}
            }
            LRESULT(0)
        }
        WM_COMMAND => {
            let id = (w.0 & 0xFFFF) as u16;
            let learned = snapshot_now().map(|s| s.learned).unwrap_or_default();
            if let Some(cmd) = model::command_for(id, &learned) {
                if !apply(cmd) {
                    unsafe { PostQuitMessage(0) };
                }
            }
            LRESULT(0)
        }
        WM_TIMER => {
            if let (Some((owner, mini, _)), Some(snap)) = (handles(), snapshot_now()) {
                unsafe {
                    refresh_tray(owner, &snap);
                    if IsWindowVisible(mini).as_bool() {
                        let _ = InvalidateRect(Some(mini), None, false);
                    }
                }
            }
            LRESULT(0)
        }
        // Windows is shutting down, restarting, or logging the user off.
        //
        // Without these two, the message loop never returns and the cleanup after it never
        // runs: Windows terminates the process where it stands, and the machine boots pointing
        // at a proxy that is not there. Measured 2026-08-06 — Resul shut his computer down
        // with protection on and had no internet at all on the next start until he ran
        // `vigil-repair`. That is the single failure this whole project is built to avoid, and
        // it arrived through the most ordinary action a person can take.
        //
        // The work is a handful of registry writes, far inside the few seconds Windows allows,
        // and doing it in QUERYENDSESSION rather than ENDSESSION means it is done before
        // anything can decide to kill us for being slow.
        WM_QUERYENDSESSION => {
            restore_host();
            // A shutdown can still be cancelled — by another application, or by the user. If
            // that happens we are already disengaged, so the interface must say so rather than
            // keep a tick next to protection that is no longer on.
            set_engaged(false);
            if let (Some((owner, _, _)), Some(snap)) = (handles(), snapshot_now()) {
                unsafe { refresh_tray(owner, &snap) };
            }
            LRESULT(1) // never veto the shutdown
        }
        WM_ENDSESSION => {
            if w.0 != 0 {
                // Ending for real. `restore_host` is idempotent, and this is the last moment
                // the process is guaranteed to be alive.
                restore_host();
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            restore_host();
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, w, l) },
    }
}

unsafe extern "system" fn miniproc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    match msg {
        WM_PAINT => {
            unsafe { paint_mini(hwnd) };
            LRESULT(0)
        }
        // A tray popup that stays up after you click elsewhere is one people learn to hate.
        WM_KILLFOCUS | WM_CLOSE => {
            let _ = unsafe { ShowWindow(hwnd, SW_HIDE) };
            LRESULT(0)
        }
        WM_KEYDOWN if w.0 == VK_ESCAPE => {
            let _ = unsafe { ShowWindow(hwnd, SW_HIDE) };
            LRESULT(0)
        }
        WM_RBUTTONUP => {
            unsafe { show_menu(hwnd) };
            LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, w, l) },
    }
}

unsafe fn show_menu(owner: HWND) {
    let Some(snap) = snapshot_now() else {
        return;
    };
    let Ok(menu) = (unsafe { CreatePopupMenu() }) else {
        return;
    };
    for it in model::context_menu(&snap) {
        if it.separator {
            let _ = unsafe { AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null()) };
            continue;
        }
        let mut flags = MF_STRING;
        if !it.enabled {
            flags |= MF_GRAYED;
        }
        if it.checked {
            flags |= MF_CHECKED;
        }
        let label = model::wide(&it.label);
        let _ = unsafe { AppendMenuW(menu, flags, it.id as usize, PCWSTR(label.as_ptr())) };
    }

    let mut pt = POINT::default();
    let _ = unsafe { GetCursorPos(&mut pt) };
    // Required, or the menu refuses to dismiss when the user clicks away from it.
    let _ = unsafe { SetForegroundWindow(owner) };
    let _ = unsafe {
        TrackPopupMenu(
            menu,
            TPM_RIGHTBUTTON | TPM_RIGHTALIGN,
            pt.x,
            pt.y,
            Some(0),
            owner,
            None,
        )
    };
    let _ = unsafe { DestroyMenu(menu) };
}

// ------------------------------------------------------------------------------- entry

fn message_box(text: &str) {
    let msg = model::wide(text);
    let title = model::wide("vigil");
    unsafe {
        MessageBoxW(
            None,
            PCWSTR(msg.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_ICONERROR,
        );
    }
}

/// Start the proxy and run the interface. Returns when the user quits.
pub fn run() {
    let listen = "127.0.0.1:1080";
    let cache_path = vigil_platform::paths::state_dir().map(|d| d.join("cache.txt"));
    let cfg = Config {
        listen: listen.parse().expect("literal"),
        mode: ProxyMode::Auto,
        cache_path: cache_path.clone(),
        ..Default::default()
    };
    let server = Arc::new(Server::new(cfg));
    let listener = match server.bind() {
        Ok(l) => l,
        Err(e) => {
            message_box(&tf(
                lang(),
                "err.listen",
                &[("listen", listen), ("error", &e.to_string())],
            ));
            // Returning *here* matters more than it looks. The restore at the end of this
            // function would otherwise run in a second copy of the application and disengage
            // the system proxy belonging to the first — and `engage::stop` cannot catch that,
            // because both copies would name the same listen address.
            //
            // The bound port is what makes one instance one instance: only the copy that owns
            // it ever reaches the code below.
            return;
        }
    };
    let actual = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| listen.into());
    let stats = Arc::clone(&server.stats);
    let cache = Arc::clone(&server.cache);
    // The proxy owns its own thread and never touches the interface, so a wedged message loop
    // cannot stop traffic. The flag is the one thing that travels back: `serve` only returns
    // when the listener is gone, and the interface has to be able to say so.
    // The machine's resolver, offered but not imposed: it answers on loopback from the moment
    // the app starts, and nothing uses it until somebody ticks the menu item. Binding it here
    // rather than on the tick means the tick is instant and cannot half-succeed.
    let dns_stats =
        match vigil_proxy::dnsserver::DnsServer::bind("127.0.0.1:53".parse().expect("literal")) {
            Ok(sock) => {
                let dns = Arc::new(vigil_proxy::dnsserver::DnsServer::new(Arc::clone(
                    &server.resolver,
                )));
                // Keep the counters. They are the only way to find out afterwards that the server
                // stopped, or that it is dropping queries because the in-flight cap is too low.
                let stats = Arc::clone(&dns.stats);
                std::thread::spawn(move || dns.serve(sock));
                Some(stats)
            }
            // Port 53 held by something else — a local DNS tool, or another vigil. Not fatal: the
            // proxy half is the product, and the menu item stays greyed out rather than lying.
            Err(_) => None,
        };

    let serving = Arc::new(AtomicBool::new(true));
    let serving_thread = Arc::clone(&serving);
    let server_thread = Arc::clone(&server);
    std::thread::spawn(move || {
        server_thread.serve(listener);
        serving_thread.store(false, AtomicOrdering::Relaxed);
    });

    unsafe {
        let hinst = GetModuleHandleW(None).expect("module handle");
        let class = model::wide("vigil_tray");
        let mini_class = model::wide("vigil_mini");
        let full_class = model::wide("vigil_full");
        let full_title = model::wide(t(lang(), "window.details_title"));

        RegisterClassW(&WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: hinst.into(),
            lpszClassName: PCWSTR(class.as_ptr()),
            ..Default::default()
        });
        RegisterClassW(&WNDCLASSW {
            lpfnWndProc: Some(miniproc),
            hInstance: hinst.into(),
            lpszClassName: PCWSTR(mini_class.as_ptr()),
            hbrBackground: HBRUSH(core::ptr::null_mut()),
            ..Default::default()
        });
        RegisterClassW(&WNDCLASSW {
            lpfnWndProc: Some(fullproc),
            hInstance: hinst.into(),
            lpszClassName: PCWSTR(full_class.as_ptr()),
            hbrBackground: HBRUSH(core::ptr::null_mut()),
            ..Default::default()
        });

        let owner = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            PCWSTR(class.as_ptr()),
            PCWSTR(class.as_ptr()),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            None,
            None,
            Some(hinst.into()),
            None,
        )
        .expect("tray owner window");

        let mini = CreateWindowExW(
            WS_EX_TOOLWINDOW | WS_EX_TOPMOST,
            PCWSTR(mini_class.as_ptr()),
            PCWSTR(mini_class.as_ptr()),
            WS_POPUP | WS_BORDER,
            0,
            0,
            MINI_W,
            MINI_H,
            None,
            None,
            Some(hinst.into()),
            None,
        )
        .expect("mini window");

        let full = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            PCWSTR(full_class.as_ptr()),
            PCWSTR(full_title.as_ptr()),
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            FULL_W,
            FULL_H,
            None,
            None,
            Some(hinst.into()),
            None,
        )
        .expect("details window");

        let engaged = vigil_platform::registry::read_current()
            .map(|c| vigil_platform::sysproxy::points_at_us(&c, &actual))
            .unwrap_or(false);

        APP.with(|a| {
            *a.borrow_mut() = Some(App {
                listen: actual,
                server,
                stats,
                cache,
                mini,
                full,
                tray_owner: owner,
                engaged,
                cache_path,
                scroll: 0,
                serving,
                exe: std::env::current_exe().unwrap_or_default(),
                dns: dns_stats,
                // Read once at startup: a machine already pointing at us — because a previous
                // run left it that way — must show as engaged rather than as a fresh start.
                dns_engaged: vigil_platform::dnsclient::read_interfaces()
                    .map(|i| !vigil_platform::sysdns::stranded(&i).is_empty())
                    .unwrap_or(false),
            })
        });

        with_app(|app| {
            let snap = app.snapshot();
            let icon = make_icon(model::IconState::of(&snap), 32);
            let d = tray_data(owner, icon, Some(&model::tooltip(&snap)));
            let _ = Shell_NotifyIconW(NIM_ADD, &d);
            if let Some(i) = icon {
                let _ = DestroyIcon(i);
            }
        });

        let _ = SetTimer(Some(owner), TIMER_REFRESH, 1000, None);

        let mut msg = MSG::default();
        // Look for an update a little after starting, not during. Startup is when a user is
        // watching, the network is the slowest thing here, and nothing about an update is urgent
        // enough to make the tray icon appear late.
        //
        // The delay is jittered by the process id so a room full of machines that all boot at nine
        // o'clock does not arrive at GitHub in the same second.
        if vigil_platform::prefs::read().enabled {
            // The handle as a plain integer: `HWND` is not `Send`, and posting to a window from
            // another thread is allowed even though holding the type across threads is not.
            let owner_bits = owner.0 as isize;
            let jitter = 60 + (std::process::id() % 60) as u64;
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(jitter));
                let _ = PostMessageW(
                    Some(HWND(owner_bits as *mut _)),
                    WM_APP_START_CHECK,
                    WPARAM(0),
                    LPARAM(0),
                );
                // And keep looking. This thread used to sleep once, post once and die, so a machine
                // that stays on — which is most of them — checked exactly once ever, at startup. A
                // release cut on Tuesday reached it on the next reboot and not before, which for a
                // tool whose whole point is delivering fixes to a censored line is most of the
                // feature missing. `prefs.last_check` was written after every check and read by
                // nothing; now it is what decides whether the interval has passed, so a machine
                // rebooted hourly does not check hourly either.
                loop {
                    std::thread::sleep(CHECK_TICK);
                    let p = vigil_platform::prefs::read();
                    if !p.enabled {
                        continue; // Switched off while running. Keep ticking; it can come back on.
                    }
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let due = match p.last_check {
                        None => true,
                        Some(t) => now.saturating_sub(t) >= CHECK_INTERVAL.as_secs(),
                    };
                    if due
                        && PostMessageW(
                            Some(HWND(owner_bits as *mut _)),
                            WM_APP_START_CHECK,
                            WPARAM(0),
                            LPARAM(0),
                        )
                        .is_err()
                    {
                        return; // The window is gone; so is the reason to keep asking.
                    }
                }
            });
        } else {
            set_update_state(UpdateState::Off);
        }

        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        // Leaving a dead icon in the tray is the most visible way to look broken.
        let d = tray_data(owner, None, None);
        let _ = Shell_NotifyIconW(NIM_DELETE, &d);
    }

    restore_host();
}

/// Put every host setting back. Idempotent, because it runs from two places that can both
/// happen: the ordinary exit, and Windows telling us the session is ending.
fn restore_host() {
    // **The proxy first.** This ordering was the other way round, justified by calling a dead
    // resolver "the loudest failure of the three" — and that reasoning does not survive contact with
    // what the two operations actually cost.
    //
    // The proxy restore is a handful of registry writes: microseconds, no prompt. The DNS restore is
    // not, and it never will be — it raises a **UAC consent dialog** and waits for a human. The
    // PowerShell that used to make it far worse is gone (two cold interpreters before the prompt even
    // appeared), but the prompt is the point of the feature and cannot be removed. Inside
    // `WM_QUERYENDSESSION`, against Windows' 5-second `HungAppTimeout`, waiting on a human is an
    // invitation to be force-terminated; and a force-terminated process gets **no** `WM_ENDSESSION`
    // and no `WM_DESTROY`, so the two second chances this function was given never run either. The
    // machine then boots with `ProxyEnable=1`, `ProxyServer=https=127.0.0.1:1080` and no vigil:
    // verbatim the 2026-08-06 failure that cost a reboot with no internet.
    //
    // So the proxy — the operation with **no** fallback — goes first and completes unconditionally,
    // and the DNS restore gets a deadline. Giving up on the wait does not cancel the change: the
    // elevated helper keeps running and usually finishes. What it buys is that this function always
    // returns, which is what the session-end path is actually for.
    //
    // The priority is right on its own terms too. A stopped vigil leaves `9.9.9.9` written after it
    // precisely so name resolution survives — the DNS half has a safety net, deliberately, and the
    // proxy half has none.
    let _ = repair();

    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(SHUTDOWN_DNS_MS);

    // A change may be in flight right now: `ToggleSystemDns` runs on a worker, and it is very
    // possibly sitting inside its own consent dialog. Give it a moment to settle rather than
    // racing it, or the session-end path stacks a *second* prompt on top of the first.
    while DNS_BUSY.load(AtomicOrdering::SeqCst) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // `dns_engaged` alone is not the question. A change started from the menu sets it only when the
    // worker's result comes back, so between the click and the answer the flag is false while the
    // snapshot is already written and the elevated change may already have landed. Asking about the
    // in-flight case too costs one registry read when nothing is engaged: `set_system_dns(false)`
    // returns without prompting when no interface points at us.
    if with_app(|a| a.dns_engaged).unwrap_or(false) || DNS_BUSY.load(AtomicOrdering::SeqCst) {
        // **On a thread, with a deadline, and it is the whole call that is bounded.** The first
        // attempt at this bounded `WaitForSingleObject` instead — which bounds nothing that matters,
        // because `ShellExecuteExW` with `runas` does not return until the human answers the consent
        // dialog, and the wait comes after it. A worker can simply be walked away from.
        //
        // Walking away does not cancel anything: the elevated helper, if it was reached, keeps
        // running and usually finishes. What this buys is that the session-end message is always
        // answered, so `WM_ENDSESSION` and `WM_DESTROY` still arrive and the proxy restore above is
        // never skipped. A DNS setting left behind by the abandoned case is survivable by design —
        // `9.9.9.9` is written after us — and `vigil-repair` fixes it. A stranded *proxy* is not.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(set_system_dns(false));
        });
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let _ = rx.recv_timeout(left);
    }
}

/// The whole session-end DNS budget: waiting for an in-flight change plus the restore itself.
///
/// Under Windows' default 5-second `HungAppTimeout`, so the message is answered before Windows
/// decides the application is hung and kills it — which would skip `WM_ENDSESSION` and `WM_DESTROY`
/// as well, the exact shape of the 2026-08-06 failure.
///
/// **Measured on this machine, 2026-08-09**, by sending a real `WM_QUERYENDSESSION` at the tray
/// window with DNS engaged and deliberately leaving the consent dialog unanswered: at a 4 s budget
/// the message was answered in **4575 ms**. That passes, by 425 ms, on an idle machine — and the
/// thing this budget exists to survive is a machine that is *not* idle, shutting down, with every
/// other application being asked the same question at the same moment. 2.5 s measured out at ~3.1 s
/// and buys back most of the margin. What the extra 1.5 s bought was a slightly better chance that
/// a human answers a dialog in the meantime, which is not worth the failure it risks.
const SHUTDOWN_DNS_MS: u64 = 2_500;
