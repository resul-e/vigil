//! The second half of the run: **with vigil engaged, do this machine's applications work?**
//!
//! The first half of `vigil-scan` measures the network and changes nothing. This half changes
//! the machine on purpose — it starts the proxy, points Windows and the environment variables
//! at it, and launches the applications — because that question cannot be answered any other
//! way, and answering it separately is what the two halves were for.
//!
//! It exists because the two halves disagreed. On 2026-08-05 every Roblox hostname measured
//! blocked-and-fixable by the first half, while the Roblox client was not using vigil at all:
//! five direct sockets to port 443 and none to the proxy. A tool that only measured the
//! network would have reported everything as solved.
//!
//! Everything is snapshotted before it is touched and restored afterwards; `vigil-repair`
//! covers the case where this process is killed outright.

use std::sync::Arc;
#[cfg(windows)]
use std::time::Duration;

use vigil_proxy::Server;

use crate::apps;

/// Seconds to let the machine settle after force-killing an application, before the next arm
/// launches it again.
///
/// It was two, which is not enough and is a confound rather than a delay: the control arm runs
/// first, so the arm that matters always starts against a cold cache and a Squirrel launcher
/// that was killed moments ago. The 2026-08-07 SansürOn report has "5 processes with vigil,
/// 5 without" and this is one of the reasons that comparison cannot be trusted on its own.
#[cfg(windows)]
const SETTLE: u64 = 8;

/// What happened when an application was started with the proxy engaged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppRun {
    pub app: String,
    /// `None` when the application is not installed on this machine.
    pub exe: Option<String>,
    pub started: bool,
    /// It was already running when the run began, so it was left alone.
    ///
    /// Both halves of that matter. Killing somebody's open Discord to measure it is rude on
    /// their own machine and worse on a volunteer's — and the measurement would be wrong
    /// anyway, because an application that is already up makes no new connections and would
    /// be scored as "never reached us".
    pub was_running: bool,
    /// How many of its processes were still running when the window closed.
    ///
    /// Without this the report answers "did it reach us" and gets read as "did it work", and
    /// those are different questions: Discord's Electron half can talk to us for a few names
    /// and the application still never open, because its updater gates startup.
    pub processes: usize,
    /// The same count with vigil switched off entirely.
    ///
    /// The arm that was missing on 2026-08-06, when an environment variable this project added
    /// that morning stopped Discord reaching its gateway. Every number in the report went up —
    /// names arriving, connections transformed — and the application was worse off. A tool
    /// that cannot say *"you made this worse"* will not say it.
    pub control_processes: usize,
    /// Its own names that arrived at the proxy.
    pub seen: Vec<String>,
    /// Names it cannot start without, that never arrived.
    pub missing_critical: Vec<String>,
    /// How many connections from everything else arrived meanwhile. Names deliberately absent:
    /// this runs beside somebody's whole desktop, and a report listing every site they had
    /// open would be a privacy leak dressed up as a measurement.
    pub others: usize,
    /// Its own names, with how many connections each drew, which strategy was applied and which
    /// program asked. "One name arrived" and "one name arrived thirty times" are different
    /// findings — the first is a lookup, the second is a client stuck in a retry loop — and
    /// until 2026-08-08 the report could not tell them apart.
    pub mine: Vec<(String, vigil_proxy::HostRecord)>,
    /// Which *other* programs reached the proxy meanwhile. Program names only, never what they
    /// asked for.
    ///
    /// This is the discriminator the SansürOn run needed and did not have: if a browser
    /// appears here then Windows' proxy setting was in force for WinINET clients, and an
    /// Electron application that sent us nothing did so for its own reasons. If nothing but
    /// environment-variable clients appear, the registry channel is the suspect.
    pub other_programs: std::collections::BTreeSet<String>,
}

impl AppRun {
    pub fn verdict(&self) -> &'static str {
        if self.exe.is_none() {
            return "kurulu degil";
        }
        if self.was_running {
            return "ZATEN ACIKTI — olculmedi (kapatip tekrar calistir)";
        }
        if !self.started {
            return "baslatilamadi";
        }
        // Checked before anything else, because it is the one answer that means "turn this
        // off": the application got further without us than with us.
        if self.control_processes > self.processes {
            return "VIGIL BUNU BOZUYOR (vigil kapaliyken daha iyi acildi)";
        }
        match (self.seen.is_empty(), self.processes) {
            // Nothing reached us and nothing is running: it did not start at all, which says
            // nothing about the proxy either way.
            (true, 0) => "ACILMADI (hic baglanmadi, surec de kalmadi)",
            (true, _) => "PROXY'YI KULLANMIYOR (calisiyor ama hicbir baglantisi bize gelmedi)",
            // The one that used to read as success and is not: it talked to us and then died.
            (false, 0) => "BIZE GELDI AMA ACILMADI (surec kalmadi)",
            // Some of it reached us and the part it cannot start without did not. This is the
            // SansürOn run of 2026-08-07: Discord's updater arrived, `discord.com` never
            // did, the process count was identical with vigil on and off — and the report
            // called that "opened, uses the proxy". One name arriving is not the application
            // working, and the two must not share a verdict.
            (false, _) if !self.missing_critical.is_empty() => {
                "BAZI ADLARI GELDI AMA ACILAMADI (acilis icin gereken adlar gelmedi)"
            }
            (false, _) => "acildi, proxy'yi kullaniyor",
        }
    }
}

/// One hostname, measured directly and through vigil.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViaCell {
    pub host: String,
    pub app: String,
    pub direct_ok: usize,
    pub via_ok: usize,
    pub trials: usize,
    pub note: String,
}

impl ViaCell {
    /// The line the whole half exists to produce. The bad outcome — blocked and *not* fixed —
    /// has to be impossible to skim past, because it is the one that triggers v2.
    pub fn verdict(&self) -> &'static str {
        use vigil_core::Verdict;
        match (
            vigil_core::verdict(self.direct_ok, self.trials),
            vigil_core::verdict(self.via_ok, self.trials),
        ) {
            (Verdict::Reliable, Verdict::Reliable) => "engelli degil",
            (_, Verdict::Reliable) if self.direct_ok == 0 => "ENGELLI -> vigil ACIYOR",
            (_, Verdict::Reliable) => "kismen engelli -> vigil aciyor",
            (Verdict::Blocked, Verdict::Blocked) => "ENGELLI -> vigil ACAMIYOR",
            _ => "KARARSIZ -> vigil tam acamiyor",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Outcome {
    pub listen: String,
    pub strategy: String,
    /// What auto-calibration settled on, per host. The single most useful line for a network
    /// nobody here can reach: on SansürOn every `split:*` is 0/10 and `tlsrec:64` is 10/10,
    /// so "which one did it pick" is the difference between a bug and a working tool — and the
    /// report could not answer it until somebody asked whether it could.
    pub learned: Vec<(String, String)>,
    /// The engine's own counters at the end of the run. `upstream_errors` and
    /// `first_flight_retries` say things no k/N table does.
    pub counters: Vec<(String, usize)>,
    pub cells: Vec<ViaCell>,
    pub apps: Vec<AppRun>,
    /// What WinINET reports **after** the proxy was engaged, not before.
    ///
    /// The one moment worth reading it. `registry::refresh()` did not work until 2026-08-08 —
    /// it shelled out to an `rundll32` incantation that cannot pass arguments — so on any
    /// machine where Windows had not synchronised its connection blob for itself, everything
    /// that reads WinINET saw no proxy while our own values said otherwise. Reading it here
    /// makes the fix verifiable by the report rather than by argument.
    pub engaged_proxy: Option<vigil_platform::proxydiag::Diagnosis>,
    /// Seconds each application was given to start, in each arm. Reported because the two arms
    /// are not symmetric — the control arm runs first, so a short window penalises the arm that
    /// matters — and a reader comparing process counts has to know the number.
    pub app_wait: u64,
    /// Which of the machine's own programs used vigil and which went around it.
    pub observed: Vec<crate::observe::Program>,
    pub observe_seconds: u64,
    /// **What happened to the environment-variable channel**, in the report rather than only on the
    /// console.
    ///
    /// The volunteer sends the *file*. This was an `eprintln!`, so if his `HTTPS_PROXY` belonged to
    /// something else — which is the one case where vigil deliberately refuses to touch it — then
    /// that channel pointed at nothing for the whole measurement and **nothing in the report said
    /// so**, while the registry channel got a reported line twice. It is also the channel Roblox
    /// depends on exclusively, and the plausible reason its arm has never produced anything.
    pub env_channel: String,
    /// Why the observation window did not happen, when it was asked for and did not.
    ///
    /// Empty means it ran, or was never asked for. **The section must not simply disappear**: the
    /// 180-second watch is the measurement that decides whether this project writes a kernel driver,
    /// and a missing section is byte-identical to a run that watched and saw nothing — which reads as
    /// "no program bypassed vigil", the wrong turn in the expensive direction. Tonight's earlier fix
    /// replaced a false claim with a hole; a hole in this particular number is not acceptable either.
    pub observe_failed: String,
    /// Why the application phase did not happen, when it was asked for and did not.
    ///
    /// The same rule as [`Self::observe_failed`] and the same reason: this section's verdicts are what
    /// the driver question is read from. It used to print its heading, the claim that the applications
    /// were started with protection on, **and "90 seconds was given to each arm"** — with no rows —
    /// on a run where neither arm existed. Ninety seconds attributed to two measurements that never
    /// ran, in the section that decides the most expensive question this project has.
    pub apps_failed: String,
}

/// Render this half as report sections, appended to the network half's report.
pub fn render(o: &Outcome) -> String {
    let mut s = String::new();
    s.push_str("\n\nUYGULAMA TESTI — vigil devredeyken\n");
    s.push_str(&"-".repeat(72));
    s.push_str(&format!("\nvigil {} , strateji {}\n", o.listen, o.strategy));
    // Both channels, named, before any verdict below is read. The registry half was reported twice
    // and the environment half not at all, and the environment half is the one Roblox needs.
    if !o.env_channel.is_empty() {
        s.push_str(&format!("HTTPS_PROXY/ALL_PROXY: {}\n", o.env_channel));
    }
    s.push('\n');

    s.push_str("  Siteler: dogrudan vs vigil uzerinden\n\n");
    s.push_str(&format!(
        "  {:<30} {:<10} {:>9} {:>9}  sonuc\n",
        "site", "uygulama", "dogrudan", "vigil"
    ));
    for c in &o.cells {
        s.push_str(&format!(
            "  {:<30} {:<10} {:>4}/{:<4} {:>4}/{:<4}  {}  {}\n",
            c.host,
            c.app,
            c.direct_ok,
            c.trials,
            c.via_ok,
            c.trials,
            c.verdict(),
            c.note
        ));
    }

    if let Some(d) = &o.engaged_proxy {
        s.push_str("\n  Koruma acikken WinINET ne goruyor?\n");
        s.push_str(&format!("     {}\n", d.headline()));
        if let Some(c) = &d.blob {
            s.push_str(&format!(
                "     blob flags 0x{:02X} ({}) proxy {:?}\n",
                c.flags,
                c.describe_flags().join("+"),
                c.proxy_server
            ));
        }
    }

    // **A failure here suppresses these rows and nothing else.** This used to `return`, which is
    // how one failed section deleted three unrelated ones below it — the observation window, the
    // learned strategies and the engine counters — all of which were measured, and the first of
    // which is the number the driver question is read from. Both of the neighbouring failures come
    // from the *same* `hold::engage` refusal, so the one machine that trips this is the one machine
    // where the whole rest of the report silently vanished.
    if !o.apps_failed.is_empty() {
        s.push_str("\n  Uygulamalar: OLCULEMEDI\n");
        s.push_str(&format!(
            "  Bu bolum HIC CALISMADI: {}\n             \x20 Yani \"Discord/Roblox vigil'i kullaniyor mu\" sorusu bu raporda CEVAPSIZ —\n             \x20 bolumun bos olmasina \"kullanmiyorlar\" diye bakilmamali.\n",
            o.apps_failed
        ));
    } else {
        s.push_str("\n  Uygulamalar: vigil'i kullaniyorlar mi?\n");
        s.push_str("  (koruma acikken baslatildi, bize gelen baglantilara bakildi)\n");
        if o.app_wait > 0 {
            s.push_str(&format!(
                "  Sira: once vigil KAPALI kol, sonra vigil ACIK kol. Her kola {} saniye verildi.\n\
                 \x20 Iki kol simetrik degil — kapali kol once kostugu icin acik kol soguk\n\
                 \x20 baslar. Surec sayilarini karsilastirirken bunu hesaba kat.\n",
                o.app_wait
            ));
        }
        s.push('\n');
        s.push_str(&app_rows(o));
    }
    s.push_str("\n  Kalibratorun ogrendigi strateji (host basina)\n");
    if o.learned.is_empty() {
        s.push_str("     (hicbir host icin karar verilmedi — asagidaki sayaclara bak)\n");
    }
    for (host, strat) in &o.learned {
        s.push_str(&format!("     {host:<34} {strat}\n"));
    }
    s.push_str("\n  Motorun sayaclari\n");
    for (k, v) in &o.counters {
        s.push_str(&format!("     {k:<24} {v}\n"));
    }

    if !o.observe_failed.is_empty() {
        s.push_str("\n\n  GOZLEM — YAPILAMADI\n");
        s.push_str(&"-".repeat(72));
        s.push_str(&format!(
            "\n  Makineyi izleme bolumu HIC CALISMADI: {}\n",
            o.observe_failed
        ));
        s.push_str(
            "  Yani \"hangi program vigil'i kullaniyor, hangisi etrafindan doleniyor\"\n             \x20 sorusu bu raporda CEVAPSIZ. Bolumun yokluguna \"hicbir program\n             \x20 baypas etmedi\" diye bakilmamali — olculmedi.\n",
        );
    } else if !o.observed.is_empty() || o.observe_seconds > 0 {
        s.push_str(&crate::observe::render(&o.observed, o.observe_seconds));
    }
    s
}

/// The per-application rows — split out only so that the failure branch above cannot swallow
/// anything but these.
fn app_rows(o: &Outcome) -> String {
    let mut s = String::new();
    for a in &o.apps {
        s.push_str(&format!("  {:<10} {}\n", a.app, a.verdict()));
        if let Some(e) = &a.exe {
            s.push_str(&format!("     program: {e}\n"));
        }
        if a.started {
            s.push_str(&format!(
                "     ayakta olan surec: vigil ACIK {} , vigil KAPALI {}\n",
                a.processes, a.control_processes
            ));
        }
        if !a.seen.is_empty() {
            s.push_str(&format!("     bize gelen adlari: {}\n", a.seen.join(", ")));
        }
        if a.started && !a.missing_critical.is_empty() {
            s.push_str(&format!(
                "     HIC GELMEYEN, ACILIS ICIN GEREKEN adlar: {}\n",
                a.missing_critical.join(", ")
            ));
        }
        for (host, r) in &a.mine {
            s.push_str(&format!(
                "       {:<30} {:>3} baglanti  strateji {}{}{}\n",
                host,
                r.connections,
                r.applied.iter().cloned().collect::<Vec<_>>().join(","),
                if r.untouched > 0 {
                    format!("  dokunulmayan {}", r.untouched)
                } else {
                    String::new()
                },
                if r.clients.is_empty() {
                    String::new()
                } else {
                    format!(
                        "  ({})",
                        r.clients.iter().cloned().collect::<Vec<_>>().join(",")
                    )
                }
            ));
        }
        if a.others > 0 {
            s.push_str(&format!(
                "     (bu sirada bu uygulamanin son ek listesi disindan {} ayri AD geldi;\n     \x20     bunlar baska programlar da olabilir, uygulamanin kendisi de — adlar yazilmadi)\n",
                a.others
            ));
        }
        if !a.other_programs.is_empty() {
            s.push_str(&format!(
                "     o programlar: {}\n",
                a.other_programs
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    s
}

/// Start the proxy, engage everything, measure, and put the machine back.
pub fn run(
    port: u16,
    trials: usize,
    apps_on: bool,
    app_wait: u64,
    observe: u64,
) -> Option<Outcome> {
    use vigil_core::strategy::Strategy;
    use vigil_proxy::{Config, Mode};

    let listen: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().ok()?;
    let cfg = Config {
        listen,
        strategy: Strategy::measured_default(),
        mode: Mode::Auto,
        record_hosts: true,
        ..Default::default()
    };
    let strategy = cfg.strategy.to_string();
    let server = Arc::new(Server::new(cfg));
    let listener = match server.bind() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("  {listen} dinlenemedi ({e}). Uygulama testi atlanıyor.");
            eprintln!(
                "  Başka bir vigil çalışıyor olabilir; --port ile başka bir port denenebilir."
            );
            return None;
        }
    };
    let actual = listener.local_addr().unwrap_or(listen);
    let s2 = Arc::clone(&server);
    std::thread::spawn(move || s2.serve(listener));

    let mut out = Outcome {
        listen: actual.to_string(),
        strategy,
        app_wait: if apps_on { app_wait } else { 0 },
        ..Default::default()
    };

    eprintln!("  siteler doğrudan ve vigil üzerinden ölçülüyor...");
    out.cells = measure_via(&actual.to_string(), trials);
    // Watching and launching are independent: `--no-apps --observe N` is a perfectly sensible
    // run, and wiring the watch inside the launch phase silently swallowed it.
    if apps_on {
        let (runs, engaged, env, failed) = measure_apps(&server, &actual.to_string(), app_wait);
        out.apps = runs;
        out.engaged_proxy = engaged;
        out.env_channel = env;
        // No arm ran, so nothing may be claimed about how long each was given.
        if !failed.is_empty() {
            out.apps_failed = failed;
            out.app_wait = 0;
        }
    }
    out.observed = if observe > 0 {
        let (o, env, ran) = observe_machine(&actual, observe);
        // **Only claim a window that happened**, and say so when it did not. This was
        // unconditional, so an engage that failed rendered "watched for 180 seconds with protection
        // on — no program connected", which is byte-identical to a real and completely idle window.
        // Zeroing it removed the false claim and left a hole, and a hole in *this* number reads as
        // "nothing bypassed vigil" — the wrong turn in the most expensive direction there is.
        out.observe_seconds = if ran { observe } else { 0 };
        if !ran {
            out.observe_failed = if env.is_empty() {
                "ayarlar devreye alınamadı".to_string()
            } else {
                env.clone()
            };
        }
        // The apps phase reports the same channel; keep whichever was actually reached, and prefer
        // the apps phase because that is the arm the verdicts are read from.
        if out.env_channel.is_empty() {
            out.env_channel = env;
        }
        o
    } else {
        Vec::new()
    };
    out.learned = server
        .cache
        .lock()
        .map(|c| {
            c.hosts()
                .map(|h| {
                    (
                        h.to_string(),
                        c.get(h).map(|s| s.to_string()).unwrap_or_default(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let st = &server.stats;
    use std::sync::atomic::Ordering::Relaxed;
    out.counters = vec![
        ("kabul edilen".into(), st.accepted.load(Relaxed)),
        ("tamamlanan".into(), st.completed.load(Relaxed)),
        ("donusturulen".into(), st.transformed.load(Relaxed)),
        ("dokunulmayan".into(), st.excluded.load(Relaxed)),
        ("baglanti hatasi".into(), st.upstream_errors.load(Relaxed)),
        (
            "el sikisma hatasi".into(),
            st.handshake_errors.load(Relaxed),
        ),
        ("dns basarisiz".into(), st.dns_failures.load(Relaxed)),
        (
            "tekrar gonderilen".into(),
            st.first_flight_retries.load(Relaxed),
        ),
        ("kalibre edilen".into(), st.calibrated.load(Relaxed)),
        // The three that say whether the relay actually carried anything. `cevapsiz kapanan` is the
        // one to read on a line whose censorship is silence: a connection the upstream accepted and
        // then said nothing over.
        ("cevapsiz kapanan".into(), st.closed_empty.load(Relaxed)),
        // Non-zero means a host's learned strategy stopped working during this very run.
        ("strateji terk edilen".into(), st.abandoned.load(Relaxed)),
        ("bayt -> sunucu".into(), st.bytes_to_upstream.load(Relaxed)),
        (
            "bayt <- sunucu".into(),
            st.bytes_from_upstream.load(Relaxed),
        ),
        ("http-connect".into(), st.by_http_connect.load(Relaxed)),
        ("socks4".into(), st.by_socks4.load(Relaxed)),
        ("socks5".into(), st.by_socks5.load(Relaxed)),
    ];
    Some(out)
}

fn measure_via(proxy: &str, trials: usize) -> Vec<ViaCell> {
    let mut out = Vec::new();
    let targets: Vec<(&str, &str)> = apps::APPS
        .iter()
        .flat_map(|a| a.probes.iter().map(move |p| (*p, a.name)))
        .chain(apps::CONTROLS.iter().map(|c| (*c, "kontrol")))
        .collect();
    for (host, app) in targets {
        let (mut direct_ok, mut via_ok) = (0usize, 0usize);
        let mut notes: Vec<String> = Vec::new();
        for _ in 0..trials {
            // Both arms label their reason. `via_proxy` already distinguishes a refused CONNECT
            // from a reset and a timeout, and this — its only caller — threw that away with
            // `.is_ok()`: the row that would trigger v2 recorded no reason for vigil's *own*
            // failure. Both are labelled rather than only the new one, because the column has no
            // header and a bare `rst` beside a `vigil:rst` would be ambiguous about which arm it
            // came from.
            match crate::net::direct(host) {
                Ok(()) => direct_ok += 1,
                Err(e) => notes.push(format!("dogrudan:{e}")),
            }
            match crate::net::via_proxy(proxy, host) {
                Ok(()) => via_ok += 1,
                Err(e) => notes.push(format!("vigil:{e}")),
            }
        }
        notes.sort();
        notes.dedup();
        eprintln!("     {host:<30} doğrudan {direct_ok}/{trials}   vigil {via_ok}/{trials}");
        out.push(ViaCell {
            host: host.to_string(),
            app: app.to_string(),
            direct_ok,
            via_ok,
            trials,
            note: notes.join(","),
        });
    }
    out
}

/// What to write back into the **shared** proxy snapshot file when the live setting is no longer
/// ours, or `None` to leave it alone. Pure, so the one decision that can cost a machine its internet
/// is testable on Linux — `mod hold` below is `#[cfg(windows)]` and the fast loop cannot reach it.
///
/// # The race this exists for
///
/// The scanner and the tray application share one snapshot file, and nothing serialises them: the
/// instance lock has two callers and neither is `scan/` or `ui/`. So during the observation window —
/// the one the console explicitly invites the volunteer to use the computer in — a click on
/// "Korumayı aç" produces this:
///
/// 1. scan engaged on `:1085` and saved the user's real setting to the shared file.
/// 2. vigil-app reads the live value, sees `https=127.0.0.1:1085`, and correctly concludes it belongs
///    to somebody else — `engage::start` has no "occupied" answer, it snapshots and takes over. The
///    user's real setting is **overwritten with a port that will be dead in a minute.**
/// 3. scan's restore sees a value that is not its own, says `NotOurs`, and rightly touches nothing.
/// 4. vigil-app exits and faithfully restores `https=127.0.0.1:1085`. Every WinINET client on the
///    machine is offline, and `vigil-repair` can only fall back to disabling the proxy, losing what
///    the user had.
///
/// The scanner is the half that knows: it still holds the value it saved. So when the live setting is
/// no longer ours *and the file on disk now names our own listener*, somebody snapshotted us, and the
/// honest repair is to put our own saved value back into the file. Whoever took over then restores
/// the user's real setting when it exits.
///
/// It is deliberately narrow. Anything else on disk is left alone: a snapshot that names a third
/// party is theirs to restore, and one we cannot account for is not ours to overwrite.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn snapshot_to_repair(
    on_disk: Option<&str>,
    ours: Option<&str>,
    listen: &str,
) -> Option<String> {
    use vigil_platform::sysproxy;
    let live = sysproxy::snapshot_from_text(on_disk?)?;
    // The file claims that "before vigil, the machine pointed at *us*" — which cannot be true, and
    // means our own saved value was overwritten by another instance snapshotting our listener.
    if !sysproxy::points_at_us(&live, listen) {
        return None;
    }
    Some(ours?.to_string())
}

/// Engaging and restoring the host settings **the way the rest of the project does it**.
///
/// This was two pairs of `registry::apply` / `envreg::apply` calls holding the previous values in
/// local variables — one pair in `measure_apps`, one in `observe_machine`. Three things were missing
/// and each is the difference between an instrument and a hazard:
///
/// 1. **Nothing was written to disk**, so closing the black window during the "use your computer
///    normally" phase left the system proxy *and* `HTTPS_PROXY`/`ALL_PROXY` pointing at a dead
///    `127.0.0.1:<port>` across reboots — and the volunteer running this is exactly the person who
///    closes a black window. `vigil-repair` could then only fix the registry half.
/// 2. **No stop handler**, so Ctrl-C and the window's close button skipped the restore entirely.
/// 3. **It wrote over settings that were not ours.** `engage::start` and `envproxy::start` exist to
///    refuse that case; going straight to `apply` bypassed both.
///
/// So this module is the same four steps `ui` and `proxy` use, in one place, with the restore
/// idempotent and reachable from a signal handler.
#[cfg(windows)]
mod hold {
    use std::sync::Mutex;
    use vigil_platform::{engage as e, envproxy, envreg, paths, registry, shutdown, sysproxy};

    /// What we engaged for, so the stop handler — which takes a plain `fn()` and can carry no
    /// state of its own — knows what to compare the live setting against.
    static LISTEN: Mutex<Option<String>> = Mutex::new(None);
    /// The snapshot text this run wrote, kept so it can be put back if another instance
    /// overwrites the shared file with *our* listener. See [`super::snapshot_to_repair`].
    static SAVED: Mutex<Option<String>> = Mutex::new(None);

    /// Engage both channels. Returns a one-line description of what happened to the environment
    /// half, for the report; reports what it refused on the console too. Never panics.
    pub fn engage(listen: &str) -> Result<String, String> {
        // Installed before anything is written, so an interruption in the middle of the first
        // write is still covered.
        if !shutdown::on_stop(restore_hook) {
            eprintln!("  not: bu platformda kapanış işleyicisi kurulamadı");
        }
        if let Ok(mut g) = LISTEN.lock() {
            *g = Some(listen.to_string());
        }

        let current = registry::read_current().map_err(|x| x.to_string())?;
        // **Refuse when the machine is already pointed at a loopback proxy that is not ours.**
        //
        // For the tray application, overwriting a foreign setting is right: a user's own proxy is
        // snapshotted and restored exactly. Here it is not. A loopback proxy on a machine running
        // this scanner is almost always vigil's own tray app on another port, and `engage::start`
        // would faithfully snapshot `https=127.0.0.1:1080` as "what was there before" — into the
        // *shared* snapshot file that `vigil-app` and `vigil-repair` also use. The end of the run
        // then writes a dead port back and deletes the record, which is the documented way to strand
        // a machine permanently.
        //
        // It also ruins the measurement it was called for: the arm labelled "vigil kapalı" would be
        // measured while something on loopback was still protecting the machine.
        if sysproxy::is_stranded(&current, "127.0.0.1:")
            && !sysproxy::points_at_us(&current, listen)
        {
            return Err(format!(
                "sistem proxy'si zaten {} adresini gösteriyor — vigil-app açık olabilir.                  Kapatıp tekrar dene; ölçüm bu hâlde yanlış olur.",
                current.server
            ));
        }
        match e::start(&current, listen) {
            // Already ours from an earlier run: keep whatever snapshot is on disk, because
            // snapshotting our own setting is how a machine gets stranded permanently.
            e::Start::AlreadyEngaged => {}
            e::Start::Engage { apply, snapshot } => {
                let text = sysproxy::snapshot_to_text(&snapshot);
                write(paths::snapshot(), &text)?;
                if let Ok(mut g) = SAVED.lock() {
                    *g = Some(text);
                }
                registry::apply(&apply).map_err(|x| x.to_string())?;
            }
        }

        let env_now = envreg::read_current().map_err(|x| x.to_string())?;
        match envproxy::start(&env_now, listen) {
            envproxy::Start::AlreadyEngaged => {
                return Ok("zaten vigil'i gösteriyordu".into());
            }
            // Somebody else's variables. Overwriting them would break whatever set them, and the
            // measurement is worth less than the machine.
            envproxy::Start::Occupied => {
                let msg = "BASKASINA AIT, dokunulmadi — bu olcumde HTTPS_PROXY vigil'i GOSTERMIYOR";
                eprintln!("  ortam değişkenleri {msg}");
                return Ok(msg.into());
            }
            envproxy::Start::Engage { apply, snapshot } => {
                write(
                    paths::env_snapshot(),
                    &envproxy::snapshot_to_text(&snapshot),
                )?;
                envreg::apply(&apply).map_err(|x| x.to_string())?;
            }
        }
        Ok(format!("vigil'e yonlendirildi -> {listen}"))
    }

    /// Put both back. Idempotent, and safe to call when nothing was ever engaged.
    pub fn restore() {
        let Some(listen) = LISTEN.lock().ok().and_then(|g| g.clone()) else {
            return;
        };
        // Registry first. It is the half with no fallback, and the environment half ends in a
        // `HWND_BROADCAST` whose timeout Windows applies per window.
        if let Ok(current) = registry::read_current() {
            let on_disk = read(paths::snapshot());
            let snap = on_disk.as_deref().and_then(sysproxy::snapshot_from_text);
            match e::stop(&current, snap.as_ref(), &listen) {
                e::Stop::Restore(s) => {
                    if registry::apply(&s).is_ok() {
                        if let Some(p) = paths::snapshot() {
                            let _ = std::fs::remove_file(p);
                        }
                    }
                }
                // Somebody else owns the setting now. Leave it — but if they snapshotted *us* on the
                // way in, the file no longer holds the user's real value and their exit would write
                // a dead port. Put ours back so their restore is correct.
                e::Stop::NotOurs => {
                    let ours = SAVED.lock().ok().and_then(|g| g.clone());
                    if let Some(fix) =
                        super::snapshot_to_repair(on_disk.as_deref(), ours.as_deref(), &listen)
                    {
                        let _ = write(paths::snapshot(), &fix);
                        eprintln!("  not: ayarı başka bir vigil devraldı; anlık görüntü onarıldı");
                    }
                }
            }
        }
        if let Ok(current) = envreg::read_current() {
            let snap = read(paths::env_snapshot()).map(|t| envproxy::snapshot_from_text(&t));
            if let envproxy::Stop::Restore(s) = envproxy::stop(&current, snap.as_ref(), &listen) {
                if envreg::apply(&s).is_ok() {
                    if let Some(p) = paths::env_snapshot() {
                        let _ = std::fs::remove_file(p);
                    }
                }
            }
        }
    }

    fn restore_hook() {
        restore();
        eprintln!("\n  kesildi — ayarlar geri yazıldı");
    }

    fn write(path: Option<std::path::PathBuf>, text: &str) -> Result<(), String> {
        let Some(p) = path else {
            return Err("anlık görüntü yazacak yer yok".into());
        };
        if let Some(d) = p.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        std::fs::write(&p, text).map_err(|x| x.to_string())
    }

    fn read(path: Option<std::path::PathBuf>) -> Option<String> {
        path.and_then(|p| std::fs::read_to_string(p).ok())
    }
}

/// Watch the machine for a while with everything engaged.
#[cfg(windows)]
fn observe_machine(
    listen: &std::net::SocketAddr,
    seconds: u64,
) -> (Vec<crate::observe::Program>, String, bool) {
    let env = match hold::engage(&listen.to_string()) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("  ayarlar devreye alınamadı, izleme atlandı: {e}");
            hold::restore();
            return (
                Vec::new(),
                format!("HİÇBİRİ — devreye alınamadı: {e}"),
                false,
            );
        }
    };
    eprintln!(
        "  {seconds} saniye boyunca izleniyor — bilgisayarı normal kullan (Discord, oyun, tarayıcı)"
    );
    let out = crate::observe::run(listen.port(), seconds);
    hold::restore();
    eprintln!("  gözlem bitti, ayarlar geri yazıldı");
    (out, env, true)
}

#[cfg(not(windows))]
fn observe_machine(
    _listen: &std::net::SocketAddr,
    _seconds: u64,
) -> (Vec<crate::observe::Program>, String, bool) {
    (Vec::new(), String::new(), false)
}

#[cfg(windows)]
fn measure_apps(
    server: &Arc<Server>,
    listen: &str,
    wait: u64,
) -> (
    Vec<AppRun>,
    Option<vigil_platform::proxydiag::Diagnosis>,
    String,
    String,
) {
    let mut out = Vec::new();

    // The control arm first, with nothing engaged: how far does each application get on this
    // line *without* vigil? Without this number the report can only say the tool did
    // something, never whether the something helped.
    let mut control: Vec<(String, Option<String>, usize, bool)> = Vec::new();
    for app in apps::APPS {
        let exe = find_exe(app);
        // Never touch something the person is using. Checked before the control arm, because
        // that arm is the one that would have killed it.
        let already = count_processes(app) > 0;
        if already {
            eprintln!(
                "  {} zaten açık — dokunulmuyor, ölçüm atlanıyor (kapatıp tekrar çalıştır)",
                app.name
            );
            control.push((app.name.to_string(), exe, 0, true));
            continue;
        }
        let mut n = 0;
        if let Some(path) = &exe {
            eprintln!("  {} (vigil kapalı) başlatılıyor...", app.name);
            if launch_via_explorer(path) {
                std::thread::sleep(Duration::from_secs(wait));
                n = count_processes(app);
                kill_by_exe(app);
                std::thread::sleep(Duration::from_secs(SETTLE));
            }
        }
        eprintln!("  {} (vigil kapalı): {n} süreç", app.name);
        control.push((app.name.to_string(), exe, n, false));
    }

    let env_channel = match hold::engage(listen) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("  sistem proxy ayarlanamadı: {e}");
            hold::restore();
            // The reason goes in its own field. It used to come back as the environment channel's
            // state and be rendered under `HTTPS_PROXY/ALL_PROXY:`, so a *registry* refusal — the
            // "another vigil already owns this setting" one, for instance — appeared as a statement
            // about environment variables that had not been touched at all.
            return (out, None, "hiçbiri — bölüm çalışmadı".to_string(), e);
        }
    };
    // Named exactly, because this project has a measured fact that says HTTP_PROXY breaks
    // Discord and `envproxy::ours` deliberately never sets it. A log line claiming otherwise is
    // an invitation to attribute a stall to the wrong cause, which is the mistake this whole
    // round is correcting.
    eprintln!("  koruma açıldı: sistem proxy + HTTPS_PROXY/ALL_PROXY -> {listen}");

    // Read WinINET *now*, with the setting in force. This is the only moment the answer means
    // anything, and until 2026-08-08 nothing in this project asked it at all.
    let engaged = vigil_platform::proxydiag::collect();
    eprintln!("  WinINET: {}", engaged.headline());

    for (app, (_, exe, control_processes, was_running)) in apps::APPS.iter().zip(control) {
        // Emptied rather than diffed against what came before: the cells above sent every probe
        // name through this same proxy, so an application's own name could already be in the
        // set and would then look like "nothing new arrived". That is exactly how an earlier
        // version reported Discord as ignoring the proxy while it was using it.
        if was_running {
            out.push(AppRun {
                app: app.name.to_string(),
                exe,
                started: false,
                was_running: true,
                processes: 0,
                control_processes: 0,
                seen: Vec::new(),
                missing_critical: Vec::new(),
                others: 0,
                ..Default::default()
            });
            continue;
        }
        server.clear_seen();
        let mut started = false;
        if let Some(path) = &exe {
            eprintln!("  {} başlatılıyor...", app.name);
            started = launch_via_explorer(path);
            if !started {
                eprintln!("  {} başlatılamadı", app.name);
            }
        } else {
            eprintln!("  {} kurulu değil, atlanıyor", app.name);
        }
        if started {
            std::thread::sleep(Duration::from_secs(wait));
        }
        let processes = if started { count_processes(app) } else { 0 };
        let detail = server.seen_detail();
        let fresh: Vec<String> = detail.iter().map(|(h, _)| h.clone()).collect();
        let (mine, others) = apps::partition_seen(app, &fresh);
        // Its own names in full; everything else reduced to the set of program names. The
        // asymmetry is the privacy rule: what somebody else's programs asked for is none of
        // this report's business, but *which* programs reached us is the finding.
        let mine_detail: Vec<(String, vigil_proxy::HostRecord)> = detail
            .iter()
            .filter(|(h, _)| apps::belongs_to(app, h))
            .cloned()
            .collect();
        let other_programs: std::collections::BTreeSet<String> = detail
            .iter()
            .filter(|(h, _)| !apps::belongs_to(app, h))
            .flat_map(|(_, r)| r.clients.iter().cloned())
            .collect();
        let missing: Vec<String> = app
            .critical
            .iter()
            .filter(|c| !mine.iter().any(|m| m == *c))
            .map(|c| (*c).to_string())
            .collect();
        eprintln!(
            "  {}: kendi adlarından {} tanesi bize geldi, {} süreç (vigil kapalıyken {})",
            app.name,
            mine.len(),
            processes,
            control_processes
        );
        out.push(AppRun {
            app: app.name.to_string(),
            exe,
            started,
            was_running: false,
            processes,
            control_processes,
            seen: mine.iter().map(|s| (*s).to_string()).collect(),
            missing_critical: missing,
            others,
            mine: mine_detail,
            other_programs,
        });
        if started {
            kill_by_exe(app);
        }
    }

    hold::restore();
    eprintln!("  koruma kapatıldı, ayarlar geri yazıldı");
    (out, Some(engaged), env_channel, String::new())
}

#[cfg(not(windows))]
fn measure_apps(
    _server: &Arc<Server>,
    _listen: &str,
    _wait: u64,
) -> (
    Vec<AppRun>,
    Option<vigil_platform::proxydiag::Diagnosis>,
    String,
    String,
) {
    eprintln!("  (uygulama testi sadece Windows'ta çalışır)");
    (Vec::new(), None, String::new(), String::new())
}

#[cfg(windows)]
fn find_exe(app: &apps::App) -> Option<String> {
    // A Start-menu shortcut first: it carries the arguments the application expects, and
    // Explorer opening a `.lnk` is what a user's double-click does. Discord's `Update.exe`
    // with no arguments exits immediately and reaches nothing — measured, and it made an
    // earlier run report Discord as ignoring the proxy.
    if let Some(rel) = app.shortcut {
        if let Ok(appdata) = std::env::var("APPDATA") {
            let p = format!(r"{appdata}\{rel}");
            if std::path::Path::new(&p).exists() {
                return Some(p);
            }
        }
    }
    // Then both Start-menu trees, by file name. This is what makes the tool survive being
    // handed to somebody whose installer chose a different folder — the case that would
    // otherwise be reported as "not installed" and teach us nothing.
    if let Some(name) = app.shortcut_name {
        for root in [
            std::env::var("APPDATA")
                .ok()
                .map(|a| format!(r"{a}\Microsoft\Windows\Start Menu\Programs")),
            std::env::var("ProgramData")
                .ok()
                .map(|a| format!(r"{a}\Microsoft\Windows\Start Menu\Programs")),
        ]
        .into_iter()
        .flatten()
        {
            if let Some(found) = find_named(std::path::Path::new(&root), name, 0) {
                return Some(found);
            }
        }
    }
    // Then the protocol handler, which is the truth when there is one: these clients update
    // themselves and the folder they live in changes underneath.
    if let Some(key) = app.protocol_key {
        if let Some(p) = protocol_handler_exe(key) {
            if std::path::Path::new(&p).exists() {
                return Some(p);
            }
        }
    }
    if let Some(glob) = app.exe_glob {
        if let Ok(profile) = std::env::var("USERPROFILE") {
            if let Some(found) = expand_glob(&format!(r"{profile}\{glob}")) {
                return Some(found);
            }
        }
    }
    // Machine-wide installs, which no glob under the user profile can reach.
    for (var, glob) in app.extra_globs {
        if let Ok(root) = std::env::var(var) {
            if let Some(found) = expand_glob(&format!(r"{root}\{glob}")) {
                return Some(found);
            }
        }
    }
    // Last: a Microsoft Store package. There is no path to launch — `shell:appsFolder\<family>!
    // <id>` is the only handle Explorer takes — so this returns that form and `launch_via_
    // explorer` opens it exactly as it opens a shortcut.
    let needle = app.packaged_name?;
    let p = crate::hostdiag::packaged(needle)
        .into_iter()
        .find(|p| p.launch_target().is_some())?;
    if p.full_trust == Some(false) {
        eprintln!(
            "  {} paketli (Store) sürüm ve AppContainer: 127.0.0.1'e hiçbir proxy ayarıyla",
            app.name
        );
        eprintln!("  ulaşamaz. Ölçülüyor, ama sonucu bu bilinerek okunmalı.");
    }
    p.launch_target()
}

#[cfg(windows)]
fn protocol_handler_exe(key: &str) -> Option<String> {
    use winreg::enums::HKEY_CLASSES_ROOT;
    use winreg::RegKey;
    let k = RegKey::predef(HKEY_CLASSES_ROOT).open_subkey(key).ok()?;
    let cmd: String = k.get_value("").ok()?;
    cmd.split('"').nth(1).map(|s| s.to_string())
}

/// Depth-limited search for a file by name. Three levels covers every Start-menu layout a
/// vendor has invented, and refuses to walk a whole disk if one is missing.
#[cfg(windows)]
fn find_named(dir: &std::path::Path, name: &str, depth: usize) -> Option<String> {
    if depth > 3 {
        return None;
    }
    let entries = std::fs::read_dir(dir).ok()?;
    let mut subdirs = Vec::new();
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            subdirs.push(p);
        } else if p.file_name().and_then(|n| n.to_str()) == Some(name) {
            return Some(p.display().to_string());
        }
    }
    subdirs
        .into_iter()
        .find_map(|d| find_named(&d, name, depth + 1))
}

/// One `*` is all any of these paths need, and a glob crate is not worth a dependency.
#[cfg(windows)]
fn expand_glob(pattern: &str) -> Option<String> {
    let Some((head, tail)) = pattern.split_once('*') else {
        return std::path::Path::new(pattern)
            .exists()
            .then(|| pattern.to_string());
    };
    let mut best: Option<(std::time::SystemTime, String)> = None;
    for e in std::fs::read_dir(std::path::Path::new(head))
        .ok()?
        .flatten()
    {
        let candidate = format!("{}{}", e.path().display(), tail);
        if !std::path::Path::new(&candidate).exists() {
            continue;
        }
        let when = e
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        if best.as_ref().is_none_or(|(t, _)| when > *t) {
            best = Some((when, candidate));
        }
    }
    best.map(|(_, p)| p)
}

/// Through Explorer, deliberately. A process started as our own child inherits *our*
/// environment block, captured before the variables were written — the test would then measure
/// its own launcher rather than the machine.
#[cfg(windows)]
fn launch_via_explorer(path: &str) -> bool {
    std::process::Command::new("explorer.exe")
        .arg(path)
        .status()
        .is_ok()
}

/// How many of the application's processes are alive right now.
///
/// `tasklist` rather than a process-enumeration API: the application was started by Explorer,
/// so it is not our child and we have no handle to it, and one shelled-out command is cheaper
/// than a dependency for a number we read once per application.
#[cfg(windows)]
fn count_processes(app: &apps::App) -> usize {
    let mut n = 0usize;
    for image in app.processes {
        let out = std::process::Command::new("tasklist")
            .args(["/FI", &format!("IMAGENAME eq {image}"), "/NH"])
            .output();
        if let Ok(o) = out {
            let text = String::from_utf8_lossy(&o.stdout);
            n += text
                .lines()
                .filter(|l| l.to_ascii_lowercase().contains(&image.to_ascii_lowercase()))
                .count();
        }
    }
    n
}

/// Leave the volunteer's desktop as it was found.
#[cfg(windows)]
fn kill_by_exe(app: &apps::App) {
    for n in app.processes {
        let _ = std::process::Command::new("taskkill")
            .args(["/IM", n, "/F"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(direct: usize, via: usize) -> ViaCell {
        ViaCell {
            host: "roblox.com".into(),
            app: "Roblox".into(),
            direct_ok: direct,
            via_ok: via,
            trials: 5,
            note: "rst:5".into(),
        }
    }

    #[test]
    fn the_interesting_outcomes_are_named_distinctly() {
        assert_eq!(cell(0, 5).verdict(), "ENGELLI -> vigil ACIYOR");
        assert_eq!(cell(5, 5).verdict(), "engelli degil");
        assert_eq!(cell(0, 0).verdict(), "ENGELLI -> vigil ACAMIYOR");
        assert_eq!(cell(2, 5).verdict(), "kismen engelli -> vigil aciyor");
        assert_eq!(cell(0, 3).verdict(), "KARARSIZ -> vigil tam acamiyor");
    }

    /// The tool failing to help must not be skimmable.
    #[test]
    fn a_failure_to_help_shouts() {
        assert!(cell(0, 0).verdict().contains("ACAMIYOR"));
        assert!(cell(0, 3).verdict().contains("KARARSIZ"));
    }

    #[test]
    fn an_app_that_never_reached_us_says_so_plainly() {
        let a = AppRun {
            app: "Roblox".into(),
            exe: Some("C:\\x.exe".into()),
            started: true,
            was_running: false,
            processes: 5,
            control_processes: 5,
            seen: vec![],
            missing_critical: vec![],
            others: 12,
            ..Default::default()
        };
        assert!(a.verdict().contains("KULLANMIYOR"));
        assert_eq!(
            AppRun {
                seen: vec!["apis.roblox.com".into()],
                ..a.clone()
            }
            .verdict(),
            "acildi, proxy'yi kullaniyor"
        );

        // The case Resul hit: names arrived, the application never came up. It used to read as
        // success, which is the report answering a question nobody asked. `control_processes`
        // is zero here on purpose — the application does not start either way, so this is not
        // the "we broke it" case, which has its own verdict and its own test.
        assert_eq!(
            AppRun {
                seen: vec!["discord.com".into()],
                processes: 0,
                control_processes: 0,
                ..a.clone()
            }
            .verdict(),
            "BIZE GELDI AMA ACILMADI (surec kalmadi)"
        );
        assert_eq!(
            AppRun {
                seen: vec![],
                processes: 0,
                control_processes: 0,
                ..a.clone()
            }
            .verdict(),
            "ACILMADI (hic baglanmadi, surec de kalmadi)"
        );
        assert_eq!(
            AppRun {
                exe: None,
                started: false,
                ..a
            }
            .verdict(),
            "kurulu degil"
        );
    }

    /// The arm that was missing when it mattered. On 2026-08-06 an environment variable added
    /// that morning stopped Discord reaching its gateway: every number in the report went *up*
    /// — names arriving, connections transformed — while the application got worse. Reproduced
    /// here as the shape the report has to shout about.
    #[test]
    fn an_application_that_got_further_without_us_is_the_loudest_result() {
        let a = AppRun {
            app: "Discord".into(),
            exe: Some("x".into()),
            started: true,
            was_running: false,
            processes: 5,
            control_processes: 6,
            seen: vec!["discord.com".into(), "cdn.discordapp.com".into()],
            missing_critical: vec!["updates.discord.com".into()],
            others: 0,
            ..Default::default()
        };
        assert!(
            a.verdict().contains("BOZUYOR"),
            "reaching us is not the same as working: {}",
            a.verdict()
        );

        // and it outranks every other reading, including a healthy-looking name list
        let text = render(&Outcome {
            listen: "127.0.0.1:1085".into(),
            strategy: "tlsrec:64+split:1".into(),
            env_channel: "vigil'e yonlendirildi".into(),
            observe_failed: String::new(),
            apps_failed: String::new(),
            cells: vec![],
            apps: vec![a],
            learned: vec![],
            counters: vec![],
            observed: vec![],
            observe_seconds: 0,
            app_wait: 45,
            engaged_proxy: None,
        });
        assert!(text.contains("BOZUYOR"));
        assert!(text.contains("vigil ACIK 5"), "{text}");
        assert!(text.contains("vigil KAPALI 6"), "{text}");
    }

    /// The SansürOn run of 2026-08-07, as the report printed it. Discord's updater reached
    /// the proxy, `discord.com` never did, and the process count was five with vigil on and
    /// five with it off — the same number this machine reaches when Discord is blocked. The
    /// report said "opened, uses the proxy", which sent us looking at the network for a fault
    /// that was not there. The verdict has to carry the missing name, not just a footnote.
    #[test]
    fn one_name_arriving_is_not_the_application_working() {
        let a = AppRun {
            app: "Discord".into(),
            exe: Some(r"C:\...\Discord.lnk".into()),
            started: true,
            was_running: false,
            processes: 5,
            control_processes: 5,
            seen: vec!["updates.discord.com".into()],
            missing_critical: vec!["discord.com".into()],
            others: 47,
            ..Default::default()
        };
        assert_ne!(a.verdict(), "acildi, proxy'yi kullaniyor");
        assert!(a.verdict().contains("ACILAMADI"), "{}", a.verdict());

        let text = render(&Outcome {
            listen: "127.0.0.1:1085".into(),
            strategy: "tlsrec:64+split:1".into(),
            env_channel: "vigil'e yonlendirildi".into(),
            observe_failed: String::new(),
            apps_failed: String::new(),
            cells: vec![],
            apps: vec![a],
            learned: vec![],
            counters: vec![],
            observed: vec![],
            observe_seconds: 0,
            app_wait: 45,
            engaged_proxy: None,
        });
        assert!(text.contains("ACILAMADI"), "{text}");
        assert!(text.contains("HIC GELMEYEN"), "{text}");
        assert!(text.contains("discord.com"), "{text}");
    }

    /// The line that would have settled the SansürOn question in one run.
    ///
    /// Two facts the old report could not carry: how many times a name was asked for, and which
    /// program asked. A browser among the *other* programs proves Windows' proxy setting was in
    /// force for WinINET clients, which decides whether an Electron application that sent us
    /// nothing was a configuration failure or its own.
    #[test]
    fn the_record_names_the_programs_and_counts_the_connections() {
        let mut r = vigil_proxy::HostRecord {
            connections: 31,
            untouched: 0,
            ..Default::default()
        };
        r.applied.insert("tlsrec:64+split:1".into());
        r.clients.insert("Update.exe".into());
        let mut others = std::collections::BTreeSet::new();
        others.insert("msedge.exe".into());
        others.insert("chrome.exe".into());

        let text = render(&Outcome {
            listen: "127.0.0.1:1085".into(),
            strategy: "tlsrec:64+split:1".into(),
            env_channel: "vigil'e yonlendirildi".into(),
            observe_failed: String::new(),
            apps_failed: String::new(),
            app_wait: 90,
            apps: vec![AppRun {
                app: "Discord".into(),
                exe: Some("x".into()),
                started: true,
                processes: 5,
                control_processes: 5,
                seen: vec!["updates.discord.com".into()],
                missing_critical: vec!["discord.com".into()],
                others: 47,
                mine: vec![("updates.discord.com".into(), r)],
                other_programs: others,
                ..Default::default()
            }],
            ..Default::default()
        });
        assert!(text.contains("31 baglanti"), "{text}");
        assert!(text.contains("Update.exe"), "{text}");
        assert!(text.contains("msedge.exe, chrome.exe") || text.contains("chrome.exe, msedge.exe"));
        // The arms are not symmetric and the report has to say so, with the number used.
        assert!(text.contains("90 saniye"), "{text}");
        assert!(text.contains("simetrik degil"), "{text}");
    }

    /// Equal counts are not a regression. Most applications settle on the same number either
    /// way, and a tool that cried wolf on that would be ignored by the second run.
    #[test]
    fn the_same_count_either_way_is_not_a_complaint() {
        let a = AppRun {
            app: "Roblox".into(),
            exe: Some("x".into()),
            started: true,
            was_running: false,
            processes: 1,
            control_processes: 1,
            seen: vec!["apis.roblox.com".into()],
            missing_critical: vec![],
            others: 0,
            ..Default::default()
        };
        assert_eq!(a.verdict(), "acildi, proxy'yi kullaniyor");
    }

    /// The rule that came from getting it wrong on a live machine: an application somebody is
    /// using is never touched, and is never scored either — it makes no new connections, so
    /// measuring it would produce a confident "never reached us".
    #[test]
    fn an_application_already_open_is_left_alone_and_not_scored() {
        let a = AppRun {
            app: "Discord".into(),
            exe: Some("x".into()),
            started: false,
            was_running: true,
            processes: 0,
            control_processes: 0,
            seen: vec![],
            missing_critical: vec![],
            others: 0,
            ..Default::default()
        };
        assert!(a.verdict().contains("ZATEN ACIKTI"), "{}", a.verdict());
        assert!(
            !a.verdict().contains("KULLANMIYOR"),
            "an untouched application must not be reported as bypassing"
        );
        assert!(
            !a.verdict().contains("BOZUYOR"),
            "nor as something we broke"
        );
    }

    /// The privacy promise, in the rendered text: a count, never a list.
    #[test]
    fn other_traffic_is_counted_and_never_named() {
        let o = Outcome {
            listen: "127.0.0.1:1085".into(),
            strategy: "tlsrec:64+split:1".into(),
            env_channel: "vigil'e yonlendirildi".into(),
            observe_failed: String::new(),
            apps_failed: String::new(),
            cells: vec![cell(0, 5)],
            learned: Vec::new(),
            counters: Vec::new(),
            observed: Vec::new(),
            observe_seconds: 0,
            app_wait: 45,
            engaged_proxy: None,
            apps: vec![AppRun {
                app: "Roblox".into(),
                exe: Some("x".into()),
                started: true,
                was_running: false,
                processes: 3,
                control_processes: 1,
                seen: vec!["apis.roblox.com".into()],
                missing_critical: vec!["auth.roblox.com".into()],
                others: 37,
                ..Default::default()
            }],
        };
        let text = render(&o);
        // **A count of names, and the text has to say so.** It read "37 baglanti geldi" for a
        // number that counts distinct *hostnames* in a bucket that means "outside this app's own
        // suffix list" — which on one run was entirely the launched application's own process. A
        // number whose label is wrong is worse than no number: it was used to argue a conclusion
        // about other programs that the report could not support.
        assert!(text.contains("37 ayri AD"), "{text}");
        assert!(!text.contains("37 baglanti"), "{text}");
        assert!(text.contains("uygulamanin kendisi de"), "{text}");
        assert!(text.contains("apis.roblox.com"));
        assert!(text.contains("adlar yazilmadi"));
        assert!(text.contains("ENGELLI -> vigil ACIYOR"));
    }

    /// **Both channels have to be in the file, not just on the console.** The volunteer sends the
    /// report; if his environment variables belonged to something else then that channel pointed at
    /// nothing for the whole measurement, and it is the channel Roblox depends on exclusively.
    #[test]
    fn the_environment_channel_says_what_happened_to_it() {
        let mut o = Outcome {
            listen: "127.0.0.1:1085".into(),
            strategy: "tlsrec:64+split:1".into(),
            env_channel: "BASKASINA AIT, dokunulmadi".into(),
            ..Default::default()
        };
        let text = render(&o);
        assert!(text.contains("HTTPS_PROXY/ALL_PROXY"), "{text}");
        assert!(text.contains("BASKASINA AIT"), "{text}");

        // And it is above the verdicts, because a reader who has already believed the table below
        // will not come back for it.
        let at_channel = text.find("HTTPS_PROXY/ALL_PROXY").expect("present");
        let at_table = text.find("Siteler").expect("present");
        assert!(at_channel < at_table, "the channel line must come first");

        // Nothing to say is nothing printed, rather than an empty label.
        o.env_channel = String::new();
        assert!(!render(&o).contains("HTTPS_PROXY/ALL_PROXY"));
    }

    /// **The strand the two programs can produce between them, as a unit test.**
    ///
    /// `mod hold` is `#[cfg(windows)]`, so until this existed the fast Linux loop could not reach the
    /// one decision in the scanner that can cost a machine its internet. The decision is pure, so it
    /// can be tested here even though the thing it repairs is a Windows registry value.
    ///
    /// The scenario: the scanner saved the user's real setting, the tray application then engaged
    /// during the observation window and snapshotted *the scanner's own listener* over it, and the
    /// tray application's exit would restore a port that is about to be dead.
    #[test]
    fn a_snapshot_that_names_our_own_listener_is_put_back() {
        use vigil_platform::sysproxy::{settings_for, snapshot_to_text, ProxySettings};

        let ours_saved = snapshot_to_text(&ProxySettings {
            enabled: true,
            server: "http=corp-proxy:8080".into(),
            bypass: "intranet".into(),
        });
        // What the tray application wrote over it: "before vigil there was 127.0.0.1:1085", which is
        // the scanner's own listener and therefore cannot be true.
        let clobbered = snapshot_to_text(&settings_for("127.0.0.1:1085"));

        let fix = snapshot_to_repair(Some(&clobbered), Some(&ours_saved), "127.0.0.1:1085")
            .expect("our own value must be put back");
        assert_eq!(fix, ours_saved);

        // A snapshot naming a third party is theirs to restore, and is left alone.
        let theirs = snapshot_to_text(&ProxySettings {
            enabled: true,
            server: "http=127.0.0.1:10809".into(),
            bypass: String::new(),
        });
        assert_eq!(
            snapshot_to_repair(Some(&theirs), Some(&ours_saved), "127.0.0.1:1085"),
            None,
            "somebody else's snapshot must not be overwritten"
        );

        // Nothing on disk, or nothing of ours to put back: nothing to do rather than a guess.
        assert_eq!(
            snapshot_to_repair(None, Some(&ours_saved), "127.0.0.1:1085"),
            None
        );
        assert_eq!(
            snapshot_to_repair(Some(&clobbered), None, "127.0.0.1:1085"),
            None
        );
        // And a file we cannot parse is not ours to replace.
        assert_eq!(
            snapshot_to_repair(Some("garbage"), Some(&ours_saved), "127.0.0.1:1085"),
            None
        );
    }

    /// **A watch that did not happen must say so, not vanish.**
    ///
    /// The 180-second window is the measurement that decides whether this project writes a kernel
    /// driver. When the engage failed, the section was simply not rendered — byte-identical to a run
    /// that watched and saw nothing, which reads as "no program bypassed vigil". That is the wrong
    /// turn in the most expensive direction available.
    #[test]
    fn a_watch_that_never_ran_is_reported_as_missing_not_as_empty() {
        let failed = Outcome {
            listen: "127.0.0.1:1085".into(),
            strategy: "tlsrec:64+split:1".into(),
            observe_failed: "ayarlar devreye alınamadı".into(),
            ..Default::default()
        };
        let text = render(&failed);
        assert!(text.contains("GOZLEM — YAPILAMADI"), "{text}");
        assert!(text.contains("CEVAPSIZ"), "{text}");
        assert!(text.contains("olculmedi"), "{text}");
        // And it must not look like a window that ran and saw nothing.
        assert!(!text.contains("hicbir program baglanmadi"), "{text}");

        // A run that never asked for one stays silent, as before.
        let never = Outcome {
            listen: "127.0.0.1:1085".into(),
            strategy: "tlsrec:64+split:1".into(),
            ..Default::default()
        };
        let text = render(&never);
        assert!(!text.contains("GOZLEM"), "{text}");
    }

    /// **An application phase that did not run must not claim ninety seconds per arm.**
    ///
    /// The section printed its heading, "started with protection on", and "each arm was given 90
    /// seconds" with zero rows — ninety seconds attributed to two measurements that never existed, in
    /// the section whose verdicts decide whether this project writes a kernel driver. The trigger is
    /// ordinary: any enabled loopback proxy on another port makes the engage refuse.
    #[test]
    fn an_application_phase_that_never_ran_says_so_and_claims_no_time() {
        let failed = Outcome {
            listen: "127.0.0.1:1085".into(),
            strategy: "tlsrec:64+split:1".into(),
            apps_failed: "sistem proxy'si zaten 127.0.0.1:1080 adresini gösteriyor".into(),
            app_wait: 0,
            ..Default::default()
        };
        let text = render(&failed);
        assert!(text.contains("Uygulamalar: OLCULEMEDI"), "{text}");
        assert!(text.contains("CEVAPSIZ"), "{text}");
        assert!(
            text.contains("127.0.0.1:1080"),
            "the reason must be there: {text}"
        );
        // The three claims that must be gone.
        assert!(!text.contains("saniye verildi"), "{text}");
        assert!(!text.contains("koruma acikken baslatildi"), "{text}");
        assert!(!text.contains("Sira: once vigil KAPALI"), "{text}");
    }

    /// **One section failing must not delete the sections below it.**
    ///
    /// The two failures above are not independent: `measure_apps` and `observe_machine` call the
    /// *same* `hold::engage`, so the machine that trips one trips both — and that was the machine
    /// where the apps failure `return`ed out of `render` and took the observation notice, the
    /// learned strategies and the engine counters with it. Everything below the apps rows is
    /// measured *before* the engage is attempted, so none of it has any business disappearing with
    /// it. The combination is the case no other test constructs, which is why it survived.
    #[test]
    fn a_failed_application_phase_does_not_delete_the_sections_below_it() {
        let both_failed = Outcome {
            listen: "127.0.0.1:1085".into(),
            strategy: "tlsrec:64+split:1".into(),
            apps_failed: "sistem proxy'si zaten 127.0.0.1:1080 adresini gösteriyor".into(),
            observe_failed: "sistem proxy'si zaten 127.0.0.1:1080 adresini gösteriyor".into(),
            learned: vec![
                ("discord.com".into(), "tlsrec:64+split:1".into()),
                ("updates.discord.com".into(), "split:1".into()),
            ],
            counters: vec![
                ("cevapsiz kapanan".into(), 3),
                ("strateji terk edilen".into(), 1),
            ],
            ..Default::default()
        };
        let text = render(&both_failed);

        // The apps failure is still reported...
        assert!(text.contains("Uygulamalar: OLCULEMEDI"), "{text}");
        assert!(!text.contains("Sira: once vigil KAPALI"), "{text}");

        // ...and so is everything that was measured before it.
        assert!(
            text.contains("GOZLEM — YAPILAMADI"),
            "the watch notice must survive an apps failure: {text}"
        );
        assert!(
            text.contains("Kalibratorun ogrendigi strateji"),
            "the learned table must survive an apps failure: {text}"
        );
        assert!(text.contains("discord.com"), "{text}");
        assert!(text.contains("updates.discord.com"), "{text}");
        assert!(
            text.contains("Motorun sayaclari"),
            "the engine counters must survive an apps failure: {text}"
        );
        assert!(text.contains("strateji terk edilen"), "{text}");
    }
}
