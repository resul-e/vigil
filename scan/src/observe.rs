//! Which programs on this machine ignore vigil? Watched, not guessed.
//!
//! The application phase answers the question for the two applications it knows how to start.
//! This answers it for **everything the user actually runs**, without starting anything: with
//! the proxy engaged, every TCP connection to port 443 either goes to our listener or it does
//! not, and the ones that do not are the programs vigil cannot help.
//!
//! That distinction is the one the whole roadmap turns on. A program that ignores the system
//! proxy *and* the environment variables cannot be reached without a packet-level driver, and
//! this project's rule is that the driver gets built when a measurement demands it — not
//! before. So the measurement has to exist.
//!
//! # What it records, and what it refuses to
//!
//! Process names and connection counts. **Not hostnames, not addresses.** Which sites a
//! person visits is none of a testbench's business; which of their programs bypass the tool is
//! exactly its business, and the first can be left out without weakening the second.

use std::collections::{BTreeMap, BTreeSet};

/// One program's behaviour while we watched.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Program {
    pub name: String,
    /// Distinct connections that went to our listener.
    pub via_proxy: usize,
    /// Distinct connections that went straight out to port 443.
    pub direct: usize,
}

impl Program {
    pub fn verdict(&self) -> &'static str {
        match (self.via_proxy, self.direct) {
            (0, 0) => "-",
            (_, 0) => "vigil'i kullaniyor",
            (0, _) => "VIGIL'I BAYPAS EDIYOR",
            _ => "kismen baypas ediyor",
        }
    }
}

/// Fold samples into one row per program.
///
/// Pure, and the reason the sampling above can stay dumb: the folding is where the mistakes
/// would be, so it is the part with tests.
///
/// A connection is counted once however many samples it appears in: the same socket seen five
/// times is one connection, and counting it five times would make a chatty program look worse
/// than a bypassing one.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn tally(samples: &[(String, String, bool)]) -> Vec<Program> {
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut acc: BTreeMap<String, Program> = BTreeMap::new();
    for (proc, conn, via) in samples {
        if !seen.insert((proc.clone(), conn.clone())) {
            continue;
        }
        let e = acc.entry(proc.clone()).or_insert_with(|| Program {
            name: proc.clone(),
            ..Default::default()
        });
        if *via {
            e.via_proxy += 1;
        } else {
            e.direct += 1;
        }
    }
    let mut out: Vec<Program> = acc.into_values().collect();
    // Worst first: the programs that bypass are the finding, and a reader should not have to
    // look for them.
    out.sort_by(|a, b| b.direct.cmp(&a.direct).then(a.name.cmp(&b.name)));
    out
}

pub fn render(programs: &[Program], seconds: u64) -> String {
    let mut s = String::new();
    s.push_str("\n\nGOZLEM — hangi programlar vigil'i kullaniyor?\n");
    s.push_str(&"-".repeat(72));
    s.push_str(&format!(
        "\n{seconds} saniye boyunca, koruma acikken, 443'e giden baglantilar izlendi.\n\
         Sadece program adlari ve sayilar kaydedildi; hangi siteye gidildigi KAYDEDILMEDI.\n\n"
    ));
    s.push_str(&format!(
        "  {:<28} {:>10} {:>10}  sonuc\n",
        "program", "vigil'den", "dogrudan"
    ));
    if programs.is_empty() {
        s.push_str("  (bu sure icinde hicbir program 443'e baglanmadi)\n");
    }
    for p in programs {
        s.push_str(&format!(
            "  {:<28} {:>10} {:>10}  {}\n",
            p.name,
            p.via_proxy,
            p.direct,
            p.verdict()
        ));
    }
    // **This paragraph used to argue for a kernel driver from something the window did not
    // measure.** Two reasons a program shows as bypassing that have nothing to do with it ignoring
    // the settings: the environment half may not have been engaged at all (somebody else owned the
    // variables), and — the common one — Windows hands a process its environment **at start**, so
    // anything that was already running when the proxy was engaged keeps the old one and its next
    // fresh socket is direct however well it would have obeyed. On 2026-08-06 every program in this
    // column was talking to hosts this line does not block, and the sentence would have argued the
    // same thing.
    s.push_str(
        "\n  \"VIGIL'I BAYPAS EDIYOR\" satiri, o programin ayarlari okumadigini KANITLAMAZ.\n\
         \x20 Iki sik sebep: (1) program koruma acilmadan ONCE calisiyordu — Windows ortam\n\
         \x20 degiskenlerini surece baslangicta verir, sonradan degismez; (2) yukaridaki\n\
         \x20 HTTPS_PROXY satiri \"BASKASINA AIT\" diyorsa o kanal hic devrede degildi.\n\
         \x20 Once programi kapatip acmak gerekir. Ondan sonra da baypas ediyorsa, ve\n\
         \x20 gittigi adresler ENGELLI adreslerse, paket seviyesinde bir surucu (v2)\n\
         \x20 tartisilabilir hale gelir.\n",
    );
    s
}

/// Sample the machine's TCP table every second for `seconds`, with the proxy engaged.
///
/// Only connections that appear *after* the window opens are counted — see the baseline below.
#[cfg(windows)]
pub fn run(port: u16, seconds: u64) -> Vec<Program> {
    use std::time::{Duration, Instant};

    let me = std::process::id();
    let mut samples: Vec<(String, String, bool)> = Vec::new();

    // Connections that already existed when we engaged are not evidence of anything: a socket
    // opened before the setting changed could not have used it. Without this, Spotify's and
    // nvidia's long-lived sessions are reported as "bypassing vigil" every single run — an
    // artefact that would have sent us after a driver for programs that never got the chance
    // to obey.
    let baseline: BTreeSet<(u32, String)> = tcp_connections().into_iter().collect();

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut names = pid_names();
    let mut last_refresh = Instant::now();

    while Instant::now() < deadline {
        // Process names change less often than connections do, and `tasklist` is the expensive
        // half of this loop.
        if last_refresh.elapsed() > Duration::from_secs(10) {
            names = pid_names();
            last_refresh = Instant::now();
        }
        for (pid, remote) in tcp_connections() {
            if pid == me || baseline.contains(&(pid, remote.clone())) {
                continue;
            }
            let via = remote.ends_with(&format!(":{port}")) && remote.starts_with("127.0.0.1");
            let is443 = remote.ends_with(":443");
            if !via && !is443 {
                continue;
            }
            // A process we have no name for is the *most* interesting row in the report — the
            // first real run named its biggest bypasser `pid 39636`, which is useless to act
            // on. So an unknown pid refreshes the table immediately rather than waiting for
            // the ten-second tick it may not survive.
            if !names.contains_key(&pid) {
                names = pid_names();
                last_refresh = Instant::now();
            }
            let name = names
                .get(&pid)
                .cloned()
                .unwrap_or_else(|| format!("pid {pid} (kapanmis)"));
            samples.push((name, remote, via));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    tally(&samples)
}

/// `(pid, "addr:port")` for every TCP row `netstat` printed.
///
/// **The state column is never matched on, and matching it was a real bug.** Windows takes those
/// words from a per-language MUI resource: `netstat.exe` itself contains no `ESTABLISHED` at all,
/// only `System32\<lang>\netstat.exe.mui` does, and Windows ships one such package per installed
/// language. So the compare this used to do — `f[3] == "ESTABLISHED"` — dropped **every** row on a
/// non-English Windows, which is the entire audience of this binary. An empty window is
/// byte-identical to "no program bypassed vigil", and that is the wrong turn in the most expensive
/// direction this project can go. It survived because the development machine is English.
///
/// What the compare was actually buying is the exclusion of `TIME_WAIT` rows, and those carry
/// **pid 0** — measured here: of 103 live rows, all 23 `TIME_WAIT` had pid 0, while three
/// `CLOSE_WAIT` rows had real pids and one of them was a genuine socket to `:443`. So pid 0 is
/// both the cheaper test and the more complete one, and `tally` dedups on `(program, remote)`
/// anyway, so admitting the closing states cannot double-count.
///
/// Split out of the command call so it is a pure function over text, which is the only way any of
/// this gets tested at all.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_netstat(text: &str) -> Vec<(u32, String)> {
    let mut v = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        // TCP  local  remote  STATE  pid
        if f.len() < 5 || !f[0].eq_ignore_ascii_case("tcp") {
            continue;
        }
        // The *last* field, not `f[4]`: a language whose state word is two tokens would put its
        // second half there, the parse would fail, and the row would vanish for the same silent
        // reason all over again.
        let Ok(pid) = f[f.len() - 1].parse::<u32>() else {
            continue;
        };
        if pid == 0 {
            continue;
        }
        v.push((pid, f[2].to_string()));
    }
    v
}

/// `(pid, "addr:port")` for every TCP connection on the machine.
///
/// `netstat` rather than `GetExtendedTcpTable`: one shelled-out command against a dependency
/// and a page of `unsafe`, for a table read once a second.
#[cfg(windows)]
fn tcp_connections() -> Vec<(u32, String)> {
    let out = std::process::Command::new("netstat")
        .args(["-ano", "-p", "TCP"])
        .output();
    let Ok(o) = out else { return Vec::new() };
    parse_netstat(&String::from_utf8_lossy(&o.stdout))
}

#[cfg(windows)]
fn pid_names() -> BTreeMap<u32, String> {
    let mut m = BTreeMap::new();
    let Ok(o) = std::process::Command::new("tasklist")
        .args(["/NH", "/FO", "CSV"])
        .output()
    else {
        return m;
    };
    for line in String::from_utf8_lossy(&o.stdout).lines() {
        let cols: Vec<&str> = line.split("\",\"").collect();
        if cols.len() < 2 {
            continue;
        }
        let name = cols[0].trim_matches('"').to_string();
        if let Ok(pid) = cols[1].trim_matches('"').parse::<u32>() {
            m.insert(pid, name);
        }
    }
    m
}

#[cfg(test)]
mod tests {

    /// **The report must not argue for a kernel driver from something it did not measure.**
    ///
    /// A "bypassing" row has two innocent explanations the window cannot see: the program was already
    /// running when the proxy was engaged — Windows gives a process its environment at start and
    /// never updates it — or the environment channel was never engaged because somebody else owned
    /// the variables. The old text said the only way to reach such a program was a driver, which is
    /// the single most expensive decision this project can make.
    #[test]
    fn a_bypassing_row_does_not_conclude_a_driver_is_needed() {
        let text = render(
            &[Program {
                name: "chrome.exe".into(),
                via_proxy: 0,
                direct: 3,
            }],
            180,
        );
        assert!(text.contains("KANITLAMAZ"), "{text}");
        assert!(
            text.contains("kapatip acmak"),
            "the restart explanation has to be there: {text}"
        );
        // And a driver is only mentioned as conditional, never as "the only way".
        assert!(!text.contains("tek yolu"), "{text}");
        assert!(text.contains("tartisilabilir"), "{text}");
    }
    use super::*;

    fn s(p: &str, c: &str, via: bool) -> (String, String, bool) {
        (p.to_string(), c.to_string(), via)
    }

    /// The same socket seen in ten samples is one connection. Otherwise a chatty program that
    /// uses vigil correctly would outrank a quiet one that bypasses it.
    #[test]
    fn a_connection_is_counted_once_however_often_it_is_seen() {
        let samples = vec![
            s("A.exe", "127.0.0.1:1085", true),
            s("A.exe", "127.0.0.1:1085", true),
            s("A.exe", "127.0.0.1:1085", true),
        ];
        let t = tally(&samples);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].via_proxy, 1);
    }

    #[test]
    fn a_bypassing_program_is_named_and_sorted_first() {
        let samples = vec![
            s("Good.exe", "127.0.0.1:1085", true),
            s("Good.exe", "127.0.0.1:1085", true),
            s("Bad.exe", "1.2.3.4:443", false),
            s("Bad.exe", "5.6.7.8:443", false),
        ];
        let t = tally(&samples);
        assert_eq!(t[0].name, "Bad.exe", "the finding must come first");
        assert_eq!(t[0].verdict(), "VIGIL'I BAYPAS EDIYOR");
        assert_eq!(t[1].verdict(), "vigil'i kullaniyor");
    }

    #[test]
    fn a_program_doing_both_is_not_called_clean() {
        let samples = vec![
            s("Half.exe", "127.0.0.1:1085", true),
            s("Half.exe", "1.2.3.4:443", false),
        ];
        assert_eq!(tally(&samples)[0].verdict(), "kismen baypas ediyor");
    }

    /// **The measurement must not depend on what language Windows is installed in.**
    ///
    /// `netstat`'s state column comes from a per-language MUI resource, so it reads `ESTABLISHED`
    /// on the development machine and something else on the machines this binary is actually sent
    /// to. Matching the English word returned zero rows there, and zero rows renders as "no
    /// program bypassed vigil" — the answer that argues *against* the driver this window exists to
    /// decide on. The fixture below is deliberately three different languages plus a two-token
    /// state, because the parser's correctness must not turn on any of them.
    #[test]
    fn a_localised_state_column_still_yields_rows() {
        let turkish = "\r\n\
            Etkin Baglantilar\r\n\r\n\
            \x20 Proto  Yerel Adres            Yabanci Adres          Durum           PID\r\n\
            \x20 TCP    192.168.1.5:51001      104.18.32.7:443        KURULDU         4242\r\n\
            \x20 TCP    127.0.0.1:52002        127.0.0.1:1080         KURULDU         4242\r\n\
            \x20 TCP    0.0.0.0:135            0.0.0.0:0              DINLIYOR        964\r\n";
        let rows = parse_netstat(turkish);
        assert_eq!(
            rows,
            vec![
                (4242, "104.18.32.7:443".to_string()),
                (4242, "127.0.0.1:1080".to_string()),
                (964, "0.0.0.0:0".to_string()),
            ],
            "a Turkish state column must not hide the two rows the window is for"
        );

        // German, and a state word that is two tokens — which is why the pid is taken from the
        // last field rather than from `f[4]`.
        let german = "\x20 TCP    10.0.0.2:60000    93.184.216.34:443    HERGESTELLT    777\r\n\
            \x20 TCP    10.0.0.2:60001    93.184.216.35:443    WARTEN AUF SCHLIESSEN    778\r\n";
        assert_eq!(
            parse_netstat(german),
            vec![
                (777, "93.184.216.34:443".to_string()),
                (778, "93.184.216.35:443".to_string()),
            ]
        );
    }

    /// `TIME_WAIT` rows carry pid 0 and belong to nobody, so they must not be attributed to a
    /// program. That exclusion is the *only* thing the old English-only state compare was buying,
    /// and it is what replaced it.
    #[test]
    fn rows_belonging_to_no_process_are_dropped() {
        let text = "\x20 TCP    10.0.0.2:60000    93.184.216.34:443    TIME_WAIT    0\r\n\
            \x20 TCP    10.0.0.2:60002    93.184.216.36:443    ESTABLISHED    31337\r\n";
        assert_eq!(
            parse_netstat(text),
            vec![(31337, "93.184.216.36:443".to_string())]
        );
    }

    /// Header lines, blank lines and short rows are not connections.
    #[test]
    fn only_tcp_rows_are_read() {
        let text = "\r\nActive Connections\r\n\r\n\
            \x20 Proto  Local Address          Foreign Address        State           PID\r\n\
            \x20 UDP    0.0.0.0:5353           *:*                                    1500\r\n\
            \x20 TCP    10.0.0.2:1            \r\n\
            \x20 TCP    10.0.0.2:60003         93.184.216.37:443      ESTABLISHED     55\r\n";
        assert_eq!(
            parse_netstat(text),
            vec![(55, "93.184.216.37:443".to_string())]
        );
    }

    /// The privacy line, held by a test: the rendered text carries programs and counts, and no
    /// address of anywhere anyone went.
    #[test]
    fn no_address_reaches_the_report() {
        let t = tally(&[s("Bad.exe", "162.159.135.232:443", false)]);
        let text = render(&t, 60);
        assert!(text.contains("Bad.exe"));
        assert!(
            !text.contains("162.159"),
            "an address leaked into the report"
        );
        assert!(text.contains("KAYDEDILMEDI"));
    }
}
