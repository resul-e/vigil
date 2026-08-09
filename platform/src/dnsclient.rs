//! Reading and writing Windows' per-interface DNS servers. The only part of
//! [`crate::sysdns`] that talks to the system.
//!
//! # Reading costs nothing now, and it used to cost seconds
//!
//! This went through PowerShell's `DnsClient` cmdlets, for a good reason that produced a bad
//! result. The reason: `netsh` prints **localised prose** — this machine's Windows is Turkish and
//! its adapters are called things like `Yerel Ağ Bağlantısı* 8` — so a parser of `netsh` output
//! guesses, while the cmdlets return the same fields in any display language.
//!
//! The result, measured 2026-08-09 on this machine:
//!
//! | | |
//! |---|---|
//! | empty `powershell.exe` cold start | 0.23 s |
//! | `Get-DnsClientServerAddress` + `Get-NetAdapter` per interface | **2.93 s first, 1.26 s after** |
//! | the same data from the registry | **0.04 s** |
//!
//! And the owner reported the symptom before anybody measured it: ticking "DNS'i de vigil'e ver"
//! took a long time to react, with a long gap before the consent prompt appeared. Three PowerShell
//! processes were involved and **two of them ran before the prompt** — one to read the interfaces,
//! one to call `Start-Process -Verb RunAs`, which started the third. All of it inside the tray's
//! `WM_COMMAND` handler, so the interface was frozen throughout. `read_interfaces` is also called at
//! startup, before the tray icon exists, so every launch paid it too.
//!
//! So: read from the **registry**, which is locale-independent — better than either PowerShell or
//! `netsh` on the axis that made PowerShell the choice — plus one `GetAdaptersAddresses` call for
//! the interface index, which is the only field the registry does not carry. No process is spawned.
//!
//! The snapshot format keeps the index for a reason that is easy to miss: `vigil-repair` matches a
//! saved snapshot to a live interface by index, so changing that field would leave a machine whose
//! snapshot was written by an older build unrestorable.
//!
//! # Writing still needs administrator rights, and should
//!
//! Pointing a machine's name resolution somewhere is exactly the kind of change a person should be
//! asked about, so the prompt is the feature working. What was wrong was how long it took to appear.
//! [`ShellExecuteExW`] with the `runas` verb is the API `Start-Process -Verb RunAs` wraps — the
//! ShellExecute family calls into the Application Information Service to raise the dialog, which is
//! why `CreateProcess` cannot — so two PowerShell startups were being paid to reach something
//! callable directly.
//!
//! [`ShellExecuteExW`]: https://learn.microsoft.com/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw

use crate::sysdns::Interface;

#[derive(Debug)]
pub enum Error {
    Unsupported,
    Io(String),
    /// The elevated helper ran and reported failure, or the user declined the prompt.
    Refused,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Unsupported => f.write_str("system DNS control is Windows-only"),
            Error::Io(e) => f.write_str(e),
            Error::Refused => f.write_str("the change was refused or the prompt was declined"),
        }
    }
}

/// The registry key that holds every interface's DNS configuration, keyed by adapter GUID.
#[cfg(windows)]
const TCPIP_INTERFACES: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";

/// Whether an interface registers itself in DNS — and the fourth positional argument of
/// `netsh interface ipv4 set dnsservers`.
///
/// **This is the argument that reads like something else.** `netsh`'s own help example is
/// `set dnsservers "Wired Ethernet Connection" static 10.0.0.1 primary`, and `primary` there looks
/// like "make this the primary server". The grammar says otherwise:
///
/// ```text
/// set dnsservers [name=]<string> [source=]dhcp|static [[address=]<IP address>|none]
///                [[register=]none|primary|both] [[validate=]yes|no]
/// ```
///
/// The fourth slot is **`register`**, and `primary` means "register under the primary DNS suffix
/// only" — Dynamic DNS registration, nothing to do with ordering (the address given to `set` is
/// first regardless). Writing it unconditionally, which this code did until 2026-08-09, turned
/// registration *on* for any interface that had it off, as an invisible side effect of changing a
/// resolver, and unticking the menu item did not put it back.
///
/// So the value is read from the interface and handed straight back. Nothing else here should ever
/// construct one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    None,
    Primary,
    Both,
}

impl Register {
    /// What `netsh` calls it.
    pub fn word(self) -> &'static str {
        match self {
            Register::None => "none",
            Register::Primary => "primary",
            Register::Both => "both",
        }
    }

    /// From `RegistrationEnabled` and `RegisterAdapterName`, with **Windows' defaults for absent
    /// values**: registration on, primary suffix only. Measured on this machine — of every
    /// interface under `Tcpip\Parameters\Interfaces`, exactly one carries `RegistrationEnabled`
    /// (0) and none carries `RegisterAdapterName`, so the absent case is the common one and
    /// getting its default wrong would change most of the machine.
    pub fn from_registry(enabled: Option<u32>, adapter_name: Option<u32>) -> Register {
        match (enabled.unwrap_or(1), adapter_name.unwrap_or(0)) {
            (0, _) => Register::None,
            (_, 0) => Register::Primary,
            _ => Register::Both,
        }
    }
}

/// Index, GUID and friendly name for every adapter, from `GetAdaptersAddresses`.
///
/// The index is the one field the registry does not carry, and the snapshot format needs it — see
/// the module documentation for why that field cannot simply be dropped.
#[cfg(windows)]
fn adapters() -> Result<Vec<(u32, String, String)>, Error> {
    use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
        GAA_FLAG_SKIP_UNICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    // Two calls: one to be told the size, one to fill it. Looped a few times because the set of
    // adapters can change between the two — a VPN coming up, a phone tethering — and a fixed
    // single retry would report an empty list at exactly the wrong moment.
    //
    // The buffer is a `Vec<u64>` rather than the obvious `Vec<u8>` for **alignment**:
    // `IP_ADAPTER_ADDRESSES_LH` holds pointers and 64-bit fields, `GetAdaptersAddresses` documents
    // that the buffer must be suitably aligned, and a `Vec<u8>` promises nothing beyond 1. The
    // system allocator happens to over-align a 16 KB request, so this was never going to fault on
    // x86-64 — it was unsound by the rules rather than broken, and one word of element type is a
    // cheaper answer than an argument about which allocator is in use.
    let flags = GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    let mut size: u32 = 16 * 1024;
    let mut buf: Vec<u64> = Vec::new();
    let mut last = ERROR_SUCCESS.0;
    for _ in 0..4 {
        buf.clear();
        buf.resize(size.div_ceil(8) as usize, 0);
        let r = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                flags,
                None,
                Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut size,
            )
        };
        last = r;
        if r == NO_ERROR.0 {
            break;
        }
        if r != ERROR_BUFFER_OVERFLOW.0 {
            return Err(Error::Io(format!("GetAdaptersAddresses failed: {r}")));
        }
    }
    if last != NO_ERROR.0 {
        return Err(Error::Io(format!(
            "GetAdaptersAddresses kept asking for more room: {last}"
        )));
    }

    let mut out = Vec::new();
    let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !p.is_null() {
        let a = unsafe { &*p };
        // `AdapterName` is the GUID in braces, as ASCII; `FriendlyName` is what the user sees and
        // is what `netsh` wants when writing.
        let guid = unsafe { pstr(a.AdapterName.0) };
        let alias = unsafe { pwstr(a.FriendlyName.0) };
        // `IfIndex` is 0 for adapters with no IPv4 — skip those rather than write to index 0. It
        // lives in an anonymous union, which is why the read is unsafe: the buffer came from
        // Windows and the field is only meaningful because `GetAdaptersAddresses` filled it.
        let index = unsafe { a.Anonymous1.Anonymous.IfIndex };
        if index != 0 && !guid.is_empty() {
            out.push((index, guid, alias));
        }
        p = a.Next;
    }
    Ok(out)
}

#[cfg(windows)]
unsafe fn pstr(p: *const u8) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0usize;
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(p, n) }).into_owned()
}

#[cfg(windows)]
unsafe fn pwstr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0usize;
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) })
}

/// Split a registry DNS list. Windows writes them comma-separated for static and
/// space-separated for DHCP, and has been known to use either.
pub fn split_servers(v: &str) -> Vec<String> {
    v.split([',', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(windows)]
pub fn read_interfaces() -> Result<Vec<Interface>, Error> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let root = hklm
        .open_subkey_with_flags(TCPIP_INTERFACES, KEY_READ)
        .map_err(|e| Error::Io(e.to_string()))?;

    let mut out = Vec::new();
    for (index, guid, alias) in adapters()? {
        // The registry key is the GUID in braces, lower-case; `AdapterName` gives it in the same
        // shape, but match case-insensitively rather than trusting that.
        let Ok(k) = root.open_subkey_with_flags(&guid, KEY_READ) else {
            continue;
        };
        let static_servers: Vec<String> = k
            .get_value::<String, _>("NameServer")
            .map(|v| split_servers(&v))
            .unwrap_or_default();
        // What is actually in effect: the static list when there is one, otherwise whatever DHCP
        // handed over.
        let servers = if static_servers.is_empty() {
            k.get_value::<String, _>("DhcpNameServer")
                .map(|v| split_servers(&v))
                .unwrap_or_default()
        } else {
            static_servers.clone()
        };
        out.push(Interface {
            index,
            alias,
            servers,
            static_servers,
        });
    }
    Ok(out)
}

/// Every interface's Dynamic DNS registration setting, by index.
///
/// Read at write time rather than carried on [`Interface`] on purpose: a snapshot file parsed by
/// `sysdns::parse` would have to invent a value for this field, and an invented registration
/// setting written back as administrator is the bug this whole type exists to prevent. The truth is
/// in the registry, it is one read away, and the write is the only place that needs it.
#[cfg(windows)]
fn registrations() -> Result<std::collections::HashMap<u32, Register>, Error> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let root = hklm
        .open_subkey_with_flags(TCPIP_INTERFACES, KEY_READ)
        .map_err(|e| Error::Io(e.to_string()))?;

    let mut out = std::collections::HashMap::new();
    for (index, guid, _) in adapters()? {
        let Ok(k) = root.open_subkey_with_flags(&guid, KEY_READ) else {
            continue;
        };
        out.insert(
            index,
            Register::from_registry(
                k.get_value::<u32, _>("RegistrationEnabled").ok(),
                k.get_value::<u32, _>("RegisterAdapterName").ok(),
            ),
        );
    }
    Ok(out)
}

/// Write `servers` to each interface, or clear the static list when it is `None`.
///
/// One elevated shell for the whole batch: a UAC prompt per interface would be a tool nobody
/// finishes using.
///
/// **This blocks for as long as the consent dialog is on screen** — a minute, or forever. Not the
/// process wait: `ShellExecuteExW` with `runas` is what raises the dialog and it does not return
/// until the user answers, so no timeout on the wait afterwards can bound it. A caller that must
/// come back within a deadline has to bound *this whole call*, on a thread it can walk away from.
#[cfg(windows)]
pub fn apply(changes: &[(u32, Option<Vec<String>>)]) -> Result<(), Error> {
    // The registration setting each interface already has, so that writing a resolver does not
    // change it. Read here rather than taken from the caller: see `registrations`.
    let regs = registrations()?;
    let mut full: Vec<(u32, Option<Vec<String>>, Register)> = Vec::with_capacity(changes.len());
    for (i, s) in changes {
        // No default. An index we have no registration for is an adapter that came or went between
        // the caller's read and ours, and guessing a value is the exact thing `Register` exists to
        // prevent — it would write somebody's Dynamic DNS setting on the strength of a race. Refuse
        // the batch instead: nothing is written, the snapshot is kept, and the caller can try again.
        let Some(r) = regs.get(i).copied() else {
            return Err(Error::Io(format!(
                "adapter {i} changed while the change was being prepared; nothing was written"
            )));
        };
        full.push((*i, s.clone(), r));
    }
    match batch(&full) {
        None => Ok(()),
        Some(cmd) => elevated_cmd(&cmd),
    }
}

/// Build the command line, and nothing else.
///
/// Split out from [`apply`] because it is the part that becomes a **command line run as
/// administrator**, and the only part that can be tested without a consent dialog. `None` means
/// there is nothing to do — which is not the same as an error, and the caller must not prompt.
///
/// Pure, so it is tested on Linux too, where the rest of this file does not exist.
///
/// # Every command's result is read, and that is not free
///
/// The first version joined the commands with `&`, which is unconditional sequencing, and `cmd /c`
/// exits with the exit code of the **last** command — here always `ipconfig /flushdns`, which
/// succeeds whatever happened before it. So `apply` returned `Ok(())` no matter how many `netsh`
/// invocations had failed, and on the *restore* path that is the damaging direction: the caller
/// deletes the snapshot and marks the machine disengaged while an interface is still pinned to
/// `127.0.0.1`, with the only record of its real configuration gone.
///
/// It is also a regression the PowerShell version did not have — that one ran under
/// `$ErrorActionPreference='Stop'` and propagated `$p.ExitCode`.
///
/// So each command sets a flag on failure and the batch ends by reading it. `&&` would have been
/// shorter but stops at the first failure, and when six interfaces are being put back the other
/// five should still be put back. The flag is cleared first, because the environment the shell
/// inherits is the user's and could already contain anything. Verified against the real `cmd.exe`:
/// one failing command in the chain gives exit 1, all-succeeding gives 0, and an inherited
/// `VIGILFAIL=1` does not make a good run look bad.
#[allow(clippy::needless_return)]
pub fn batch(changes: &[(u32, Option<Vec<String>>, Register)]) -> Option<String> {
    // **`netsh` by index, not by name.** The obvious worry with `netsh` is that its output is
    // localised — this machine's adapters are called `Yerel Ağ Bağlantısı* 8` — but that is about
    // *parsing* output, and nothing here parses any. For input, `name=` takes "interface name or
    // index", and index was measured to work: `netsh interface ipv4 show dnsservers name=21` prints
    // the configuration for `Ethernet`. So no localised string is ever constructed or matched, and
    // `apply`'s signature keeps taking the index the snapshot format already stores.
    let mut parts: Vec<String> = Vec::new();
    for (index, servers, register) in changes {
        match servers {
            // Back to DHCP. `sysdns::restore_value` returns `None` for an interface that had no
            // static list, so this is the ordinary restore, not an exceptional one.
            None => parts.push(format!(
                "netsh interface ipv4 set dnsservers name={index} dhcp"
            )),
            Some(list) => {
                // Addresses only, and parsed rather than trusted: this is about to become a command
                // line. Anything that is not an IP address is dropped, silently and deliberately —
                // there is no case where passing it on would be better.
                //
                // **IPv4 only**, and not because IPv6 is unwanted: every command here is
                // `interface ipv4`, whose `address` parameter is documented as an IPv4 address and
                // which rejects anything else. An accepted `::1` would be a command that fails, and
                // a failing command on the restore path is how a snapshot gets deleted for nothing.
                // The IPv6 side of Windows' DNS configuration lives under `Tcpip6` and is not read,
                // written or claimed by any of this.
                let mut addrs: Vec<&String> = Vec::new();
                for s in list.iter() {
                    // Duplicates matter: the second `add dnsservers` of an address already in the
                    // list fails, and every command's result is now read.
                    if s.parse::<std::net::Ipv4Addr>().is_ok() && !addrs.contains(&s) {
                        addrs.push(s);
                    }
                }
                let Some((first, rest)) = addrs.split_first() else {
                    continue;
                };
                // `validate=no` because the validating form sends a query and waits for it, which on
                // a censored line is exactly the wait this whole change exists to remove.
                let reg = register.word();
                parts.push(format!(
                    "netsh interface ipv4 set dnsservers name={index} static {first} {reg} validate=no"
                ));
                for (n, a) in rest.iter().enumerate() {
                    parts.push(format!(
                        "netsh interface ipv4 add dnsservers name={index} {a} index={} validate=no",
                        n + 2
                    ));
                }
            }
        }
    }
    if parts.is_empty() {
        return None;
    }
    // Every command records failure rather than aborting the batch — see the note above.
    let watched: Vec<String> = parts
        .into_iter()
        .map(|c| format!("{c} || set {FAILED}=1"))
        .collect();
    // Flush, or the block-page answers already cached survive the change and the fix looks like it
    // did nothing for the first few minutes. Unwatched: a failed flush is a stale cache, not a
    // wrong setting, and reporting failure for it would delete a snapshot that is still needed.
    Some(format!(
        r#"set "{FAILED}=" & {} & ipconfig /flushdns & if defined {FAILED} exit 1"#,
        watched.join(" & ")
    ))
}

/// The shell variable the batch uses to remember that something failed. Named for this program so
/// that clearing it cannot clear something of the user's.
const FAILED: &str = "VIGILFAIL";

/// Run one command line as administrator and wait for it.
///
/// `ShellExecuteExW` with the `runas` verb, rather than `powershell -Command "Start-Process -Verb
/// RunAs"`. That is the same mechanism — the ShellExecute family calls into the Application
/// Information Service to raise the consent dialog, which is why `CreateProcess` cannot — reached
/// without paying two PowerShell startups first. Measured: an empty `powershell.exe` costs 0.23 s to
/// start, and the old path started two of them before the user saw anything at all.
///
/// `SEE_MASK_NOCLOSEPROCESS` is what makes the wait possible: without it there is no handle to wait
/// on, and the caller would read the settings back before the change had landed and report failure.
///
/// # `cmd.exe` is named absolutely, and that is not pedantry
///
/// `lpFile: w!("cmd.exe")` with no `lpDirectory` searches the **current directory first**. Proved on
/// this machine on 2026-08-09 with a harmless experiment (verb `open`, never `runas`): a copy of
/// `hostname.exe` renamed `cmd.exe` in the working directory is what got launched. Under `runas`
/// that decoy is what the Application Information Service elevates.
///
/// Every condition for it is met by the shipped product: the install directory is user-writable by
/// construction — `.vigil-update/` is created next to the executable without elevation — Explorer
/// sets the working directory to that folder on a double-click, and the double-click is how the
/// program is started. So any code running as the user, with no rights at all, could drop a file
/// there and wait for the one moment the user is *expecting* a consent dialog. The only thing
/// between them and administrator would be noticing the publisher.
///
/// `GetSystemDirectoryW` is the fix, and `lpDirectory` is set to the same place so nothing about
/// the caller's working directory participates.
/// `(the command processor, the directory to run it in)`, both absolute.
///
/// Its own function so that the thing being elevated can be asserted about without elevating
/// anything — see `windows_tests`.
#[cfg(windows)]
fn system_cmd() -> Result<(String, String), Error> {
    use windows::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut buf = [0u16; 260];
    let n = unsafe { GetSystemDirectoryW(Some(&mut buf)) } as usize;
    if n == 0 || n >= buf.len() {
        return Err(Error::Io("could not find the system directory".into()));
    }
    let dir = String::from_utf16_lossy(&buf[..n]);
    Ok((format!(r"{dir}\cmd.exe"), dir))
}

#[cfg(windows)]
fn elevated_cmd(command_line: &str) -> Result<(), Error> {
    use windows::core::{w, HSTRING, PCWSTR};
    use windows::Win32::Foundation::{CloseHandle, ERROR_CANCELLED, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
    use windows::Win32::UI::Shell::{
        ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
    };
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let (exe, dir) = system_cmd()?;
    let exe = HSTRING::from(exe);
    let dir = HSTRING::from(dir);

    // `cmd /c` because the batch is several `netsh` invocations and one `ipconfig`, and one consent
    // dialog for the batch is the whole point — a prompt per interface is a tool nobody finishes
    // using.
    let args = HSTRING::from(format!("/c {command_line}"));
    let mut info = SHELLEXECUTEINFOW {
        cbSize: core::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(exe.as_ptr()),
        lpDirectory: PCWSTR(dir.as_ptr()),
        lpParameters: PCWSTR(args.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };

    unsafe { ShellExecuteExW(&mut info) }.map_err(|e| {
        // The user clicking "No" is not a failure of ours and must not read like one.
        if e.code().0 as u32 & 0xFFFF == ERROR_CANCELLED.0 {
            Error::Refused
        } else {
            Error::Io(format!("could not raise the consent prompt: {e}"))
        }
    })?;

    if info.hProcess.is_invalid() {
        return Err(Error::Io("no handle for the elevated process".into()));
    }
    let waited = unsafe { WaitForSingleObject(info.hProcess, INFINITE) };
    let mut code: u32 = 1;
    let got = unsafe { GetExitCodeProcess(info.hProcess, &mut code) };
    let _ = unsafe { CloseHandle(info.hProcess) };

    if waited != WAIT_OBJECT_0 {
        return Err(Error::Io("the elevated helper never finished".into()));
    }
    if got.is_err() {
        return Err(Error::Io(
            "could not read the elevated helper's result".into(),
        ));
    }
    if code == 0 {
        Ok(())
    } else {
        Err(Error::Refused)
    }
}

#[cfg(not(windows))]
pub fn read_interfaces() -> Result<Vec<Interface>, Error> {
    Err(Error::Unsupported)
}

#[cfg(not(windows))]
pub fn apply(_changes: &[(u32, Option<Vec<String>>)]) -> Result<(), Error> {
    Err(Error::Unsupported)
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    #[test]
    fn the_non_windows_stubs_report_unsupported() {
        assert!(matches!(read_interfaces(), Err(Error::Unsupported)));
        assert!(matches!(apply(&[]), Err(Error::Unsupported)));
    }
}

#[cfg(test)]
mod batch_tests {
    use super::*;

    fn ips(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// The common shape: one interface, whatever registration it already had.
    fn one(index: u32, servers: Option<Vec<String>>) -> Vec<(u32, Option<Vec<String>>, Register)> {
        vec![(index, servers, Register::Primary)]
    }

    #[test]
    fn nothing_to_do_is_not_an_error_and_must_not_prompt() {
        assert_eq!(batch(&[]), None);
        // A change whose every address was rejected is also nothing to do — raising a consent
        // dialog to run no commands would be the worst of both.
        assert_eq!(batch(&one(21, Some(ips(&["not-an-address"])))), None);
    }

    #[test]
    fn setting_two_servers_makes_a_first_and_an_index_2() {
        let cmd = batch(&one(21, Some(ips(&["127.0.0.1", "9.9.9.9"])))).expect("some");
        assert!(
            cmd.contains("set dnsservers name=21 static 127.0.0.1 primary"),
            "{cmd}"
        );
        assert!(
            cmd.contains("add dnsservers name=21 9.9.9.9 index=2"),
            "{cmd}"
        );
        assert!(cmd.contains("ipconfig /flushdns"), "{cmd}");
    }

    #[test]
    fn clearing_goes_back_to_dhcp_rather_than_to_an_empty_static_list() {
        let cmd = batch(&one(9, None)).expect("some");
        assert!(cmd.contains("set dnsservers name=9 dhcp"), "{cmd}");
        assert!(!cmd.contains("static"), "{cmd}");
    }

    /// **`primary` is `register=primary`, not "the primary server".** The interface's own value is
    /// handed back, so changing a resolver never changes whether the machine registers itself in
    /// DNS. The `none` case is the one that used to be silently turned on.
    #[test]
    fn the_registration_setting_is_the_interfaces_own() {
        for (r, word) in [
            (Register::None, "none"),
            (Register::Primary, "primary"),
            (Register::Both, "both"),
        ] {
            let cmd = batch(&[(21, Some(ips(&["127.0.0.1"])), r)]).expect("some");
            assert!(
                cmd.contains(&format!("static 127.0.0.1 {word} validate=no")),
                "{r:?}: {cmd}"
            );
        }
    }

    /// Windows' defaults for the absent values, which is what most interfaces have.
    #[test]
    fn an_interface_that_says_nothing_registers_under_the_primary_suffix() {
        assert_eq!(Register::from_registry(None, None), Register::Primary);
        assert_eq!(Register::from_registry(Some(0), None), Register::None);
        // Registration off wins over the suffix question — there is no suffix to register under.
        assert_eq!(Register::from_registry(Some(0), Some(1)), Register::None);
        assert_eq!(Register::from_registry(Some(1), Some(1)), Register::Both);
        assert_eq!(Register::from_registry(None, Some(1)), Register::Both);
    }

    /// **The one that returned `Ok(())` for a batch where everything failed.** `cmd /c` exits with
    /// the last command's code, and the last command was always the flush.
    ///
    /// Verified against the real `cmd.exe` on 2026-08-09: this shape gives exit 1 when one command
    /// in the chain fails, 0 when none does, and 0 when the *environment* already had `VIGILFAIL=1`
    /// — which is why the batch clears it first.
    #[test]
    fn a_failing_command_cannot_be_hidden_by_the_flush_that_follows_it() {
        let cmd = batch(&[
            (21, Some(ips(&["127.0.0.1"])), Register::Primary),
            (9, None, Register::Primary),
        ])
        .expect("some");
        assert!(cmd.starts_with(r#"set "VIGILFAIL=" & "#), "{cmd}");
        assert!(cmd.ends_with("& if defined VIGILFAIL exit 1"), "{cmd}");
        // Every netsh command reports, and the flush does not: a stale cache is not a wrong
        // setting, and failing for it would throw away a snapshot that is still needed.
        assert_eq!(cmd.matches("|| set VIGILFAIL=1").count(), 2, "{cmd}");
        assert!(
            !cmd.contains("ipconfig /flushdns || set"),
            "the flush must not be able to fail the batch: {cmd}"
        );
    }

    /// A duplicate in the saved list would make the second `add` fail — and now a failing command
    /// is a failing batch, so the restore would report failure for a list it restored correctly.
    #[test]
    fn a_repeated_address_is_written_once() {
        let cmd = batch(&one(21, Some(ips(&["9.9.9.9", "1.1.1.1", "9.9.9.9"])))).expect("some");
        assert_eq!(cmd.matches("9.9.9.9").count(), 1, "{cmd}");
        assert!(
            cmd.contains("add dnsservers name=21 1.1.1.1 index=2"),
            "{cmd}"
        );
    }

    /// **The safety one.** This string becomes a command line run as administrator, so anything
    /// that is not an IP address must not reach it — and the check has to be a parse, not a
    /// character filter, because a character filter is a list of things somebody forgot.
    #[test]
    fn only_things_that_parse_as_addresses_reach_the_command_line() {
        let nasty = ips(&[
            "127.0.0.1",
            "8.8.8.8 & shutdown /s",
            "$(whoami)",
            "1.1.1.1|calc",
            "",
            "; del C:\\Windows",
            "::1",
        ]);
        let cmd = batch(&one(21, Some(nasty))).expect("some");
        for bad in ["shutdown", "whoami", "calc", "del ", "$("] {
            assert!(!cmd.contains(bad), "{bad:?} survived into: {cmd}");
        }
        // `|` appears in the batch's own `||`, so check the injected form rather than the
        // character: nothing of the caller's may bring its own pipe.
        assert!(!cmd.contains("|calc"), "{cmd}");
        assert!(cmd.contains("static 127.0.0.1 primary"), "{cmd}");
        // **`::1` is dropped.** Every command here is `interface ipv4`, whose address parameter is
        // documented as IPv4; an accepted IPv6 address would be a command that fails, and a failing
        // command on the restore path now deletes a snapshot for nothing.
        assert!(!cmd.contains("::1"), "{cmd}");
    }

    /// One consent dialog for the whole batch. A prompt per interface is a tool nobody finishes
    /// using, and this is what keeps it to one.
    #[test]
    fn every_interface_goes_into_one_command_line() {
        let cmd = batch(&[
            (21, Some(ips(&["127.0.0.1"])), Register::Primary),
            (9, Some(ips(&["127.0.0.1"])), Register::Primary),
            (4, None, Register::None),
        ])
        .expect("some");
        assert_eq!(cmd.matches("netsh").count(), 3, "{cmd}");
        assert_eq!(cmd.matches("ipconfig /flushdns").count(), 1, "{cmd}");
    }

    /// The companion to `the_thing_elevated_is_the_real_command_processor_by_absolute_path`, which
    /// can only check what [`system_cmd`] returns — not that the call site uses it. A regression
    /// that put `lpFile: w!("cmd.exe")` back would leave that test green, so this one reads the
    /// source: the only way to name the command processor here is through the helper.
    ///
    /// Runs on Linux too, where the code it is reading does not compile, which is the point.
    #[test]
    fn nothing_in_this_file_names_the_command_processor_relatively() {
        let src = include_str!("dnsclient.rs");
        // Assembled rather than written out, or this line is itself the thing it is looking for —
        // which is exactly what happened the first time.
        let bare = format!("w!({:?})", "cmd.exe");
        for line in src.lines() {
            // Skip the documentation that quotes the mistake in order to explain it.
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            assert!(
                !code.contains(&bare),
                "a bare command processor name is back, and it is elevated: {line}"
            );
        }
        assert!(
            src.contains(r#"format!(r"{dir}\cmd.exe")"#),
            "the absolute-path helper is gone"
        );
    }

    #[test]
    fn a_registry_list_splits_on_either_separator() {
        assert_eq!(
            split_servers("1.1.1.1,9.9.9.9"),
            ips(&["1.1.1.1", "9.9.9.9"])
        );
        assert_eq!(
            split_servers("1.1.1.1 9.9.9.9"),
            ips(&["1.1.1.1", "9.9.9.9"])
        );
        assert_eq!(
            split_servers(" 1.1.1.1 , 9.9.9.9 "),
            ips(&["1.1.1.1", "9.9.9.9"])
        );
        assert!(split_servers("").is_empty());
        assert!(split_servers("  ,  ").is_empty());
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    /// **`registrations()` now gates every write**, so if it can fail on a real machine, no DNS
    /// change can ever be made on that machine — `apply` refuses before it prompts. It is the one
    /// piece of the rewritten elevated path that can be exercised without elevating anything, so it
    /// is exercised: it must succeed, and it must have an answer for every interface
    /// `read_interfaces` reports, because a missing one is a refused batch.
    #[test]
    fn every_interface_has_a_registration_setting_to_hand_back() {
        let regs = registrations().expect("the registration settings are readable");
        for i in read_interfaces().expect("reads") {
            assert!(
                regs.contains_key(&i.index),
                "no registration value for {} ({}) — a change to it would be refused",
                i.alias,
                i.index
            );
        }
        // And the values are the machine's own, not a default someone invented: this machine has
        // exactly one interface with registration disabled (measured 2026-08-09), so the set of
        // values must not be uniformly `Primary` by construction.
        assert!(!regs.is_empty());
    }

    /// **The privilege-escalation gate.** `ShellExecuteExW` with a bare `cmd.exe` and no
    /// `lpDirectory` searches the **current directory first** — proved on this machine on
    /// 2026-08-09 with the `open` verb and a decoy: a copy of `hostname.exe` renamed `cmd.exe` in
    /// the working directory is what got launched.
    ///
    /// Everything the attack needs is how the product ships: the install folder is user-writable
    /// (`.vigil-update/` is created there without elevation), Explorer sets the working directory to
    /// it on a double-click, and the one moment the user is *expecting* a consent dialog is the
    /// moment they tick this menu item. Any code running as the user, with no rights at all, would
    /// have got administrator.
    ///
    /// So the test is about the string, not about elevating anything: it must be an absolute path
    /// under the system directory, and that file must exist.
    #[test]
    fn the_thing_elevated_is_the_real_command_processor_by_absolute_path() {
        let (exe, dir) = system_cmd().expect("the system directory");
        assert!(
            exe.to_ascii_lowercase().ends_with(r"\system32\cmd.exe"),
            "{exe}"
        );
        // Absolute, drive-qualified, and with nothing relative left in it.
        assert!(
            exe.chars().nth(1) == Some(':'),
            "not drive-qualified: {exe}"
        );
        assert!(!exe.contains(r"\.\") && !exe.contains(r"\..\"), "{exe}");
        assert!(
            std::path::Path::new(&exe).is_file(),
            "{exe} is not a file on this machine"
        );
        // `lpDirectory` is set to the same place, so nothing about the caller's working directory
        // takes part in resolving anything.
        assert!(exe.starts_with(&dir), "{exe} is not inside {dir}");
    }

    /// **Reading must not spawn a process.** This is the regression guard for the change that
    /// replaced PowerShell with the registry.
    ///
    /// Measured on this machine: `Get-DnsClientServerAddress` + `Get-NetAdapter` cost 2.93 s the
    /// first time and 1.26 s after; the registry read costs 0.04 s. The threshold is 300 ms — far
    /// above what the registry needs even on a loaded build machine, and far below what any path
    /// through `powershell.exe` can achieve, since an *empty* PowerShell takes 0.23 s to start and
    /// the old script ran cmdlets that load CIM.
    ///
    /// It matters beyond tidiness: this runs inside the tray's `WM_COMMAND` handler and at startup
    /// before the tray icon exists, so seconds here are seconds of frozen interface.
    #[test]
    fn reading_the_interfaces_is_fast_enough_to_have_spawned_nothing() {
        let started = std::time::Instant::now();
        let ifaces = read_interfaces().expect("reads");
        let took = started.elapsed();

        assert!(
            !ifaces.is_empty(),
            "no interfaces at all — the registry read found nothing, which is not a plausible \
             machine state and means the enumeration is broken rather than merely slow"
        );
        assert!(
            took < std::time::Duration::from_millis(300),
            "reading took {took:?}. The registry path costs about 40 ms; anything in this range \
             means a process was spawned, and this call is on the UI thread."
        );
    }

    /// Every interface must carry the index the snapshot format is keyed on. A zero index would
    /// make `vigil-repair` unable to match a saved snapshot to a live interface.
    #[test]
    fn every_interface_has_a_usable_index_and_name() {
        for i in read_interfaces().expect("reads") {
            assert_ne!(i.index, 0, "{i:?} has no index");
            assert!(!i.alias.is_empty(), "{i:?} has no name");
        }
    }
}
