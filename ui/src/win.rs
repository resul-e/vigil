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

use crate::model::{self, Command, Snapshot};

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
    /// Whether we are answering DNS on loopback at all.
    dns_serving: bool,
    /// Whether Windows' own resolver is pointed at us. Cached rather than read per refresh:
    /// finding out costs a PowerShell launch, and the tray refreshes once a second.
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
        Snapshot {
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
            dns_serving: self.dns_serving,
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
        draw("Sağ tık: menü  ·  Esc: kapat", 0x00707070, y);
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
        Command::ToggleAutostart => {
            let Some((owner, _, _)) = handles() else {
                return true;
            };
            let (exe, on) = match with_app(|a| (a.exe.clone(), a.snapshot().autostart)) {
                Some(v) => v,
                None => return true,
            };
            if let Err(e) = vigil_platform::autostart::set(!on, &exe) {
                message_box(&format!("Windows ile başlatma ayarlanamadı:\n{e}"));
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
            let want = !with_app(|a| a.dns_engaged).unwrap_or(false);
            match set_system_dns(want) {
                Ok(now) => {
                    APP.with(|a| {
                        if let Some(app) = a.borrow_mut().as_mut() {
                            app.dns_engaged = now;
                        }
                    });
                }
                Err(e) => message_box(&format!("DNS ayarlanamadı:\n{e}")),
            }
            if let (Some((owner, _, _)), Some(snap)) = (handles(), snapshot_now()) {
                unsafe { refresh_tray(owner, &snap) };
            }
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
                message_box(&format!("Bu mod tanınmadı: {m}"));
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
fn set_system_dns(on: bool) -> Result<bool, String> {
    use vigil_platform::{dnsclient, paths, sysdns};

    let ifaces = dnsclient::read_interfaces().map_err(|e| e.to_string())?;
    let path = paths::dns_snapshot();
    if on {
        let targets: Vec<sysdns::Interface> =
            sysdns::targets(&ifaces).into_iter().cloned().collect();
        if targets.is_empty() {
            return Ok(!sysdns::stranded(&ifaces).is_empty());
        }
        let p = path.ok_or_else(|| "nowhere to save a snapshot".to_string())?;
        if let Some(dir) = p.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        // Before the change, always: a machine whose resolver we moved without a record of
        // where it was is one that even the repair tool can only guess about.
        std::fs::write(&p, sysdns::snapshot_to_text(&targets)).map_err(|e| e.to_string())?;
        let changes: Vec<(u32, Option<Vec<String>>)> = targets
            .iter()
            .map(|i| (i.index, Some(sysdns::ours())))
            .collect();
        dnsclient::apply(&changes).map_err(|e| e.to_string())?;
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
        dnsclient::apply(&changes).map_err(|e| e.to_string())?;
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
            message_box(&format!(
                "vigil {listen} adresini dinleyemedi:\n{e}\n\nBaşka bir vigil çalışıyor olabilir."
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
    let dns_serving =
        match vigil_proxy::dnsserver::DnsServer::bind("127.0.0.1:53".parse().expect("literal")) {
            Ok(sock) => {
                let dns = vigil_proxy::dnsserver::DnsServer::new(Arc::clone(&server.resolver));
                std::thread::spawn(move || dns.serve(sock));
                true
            }
            // Port 53 held by something else — a local DNS tool, or another vigil. Not fatal: the
            // proxy half is the product, and the menu item stays greyed out rather than lying.
            Err(_) => false,
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
        let full_title = model::wide("vigil — ayrıntılar");

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
                dns_serving,
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
    // The resolver first, and then the proxy. A machine still asking a vigil that has already
    // put the proxy back cannot resolve anything at all — the loudest failure of the three,
    // and the one that must not outlive the process by even a moment.
    if with_app(|a| a.dns_engaged).unwrap_or(false) {
        let _ = set_system_dns(false);
    }
    // And leaving the system proxy pointed at a process that has exited is the least visible
    // way to break a machine, so it goes back on the way out.
    let _ = repair();
}
