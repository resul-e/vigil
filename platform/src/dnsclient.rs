//! Reading and writing Windows' per-interface DNS servers. The only part of
//! [`crate::sysdns`] that talks to the system.
//!
//! Through PowerShell's `DnsClient` cmdlets rather than `netsh`: `netsh` prints localised
//! prose that a parser has to guess at, and this machine's Windows is Turkish. The cmdlets
//! return the same fields whatever the display language, and the registry read that tells
//! DHCP from static is one line next to them.
//!
//! Writing needs administrator rights — reading does not — so the write path re-launches
//! itself elevated and Windows shows the consent dialog. That prompt is the feature working,
//! not a wart: pointing a machine's name resolution somewhere is exactly the kind of change a
//! person should be asked about.

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

/// One line per interface: `index<TAB>alias<TAB>servers<TAB>static`, which is exactly the
/// format [`crate::sysdns::parse`] reads, so there is one parser and not two.
#[cfg(windows)]
const READ_SCRIPT: &str = r#"
$ErrorActionPreference='SilentlyContinue'
Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object {
  $ix = $_.InterfaceIndex
  $guid = (Get-NetAdapter -InterfaceIndex $ix).InterfaceGuid
  $ns = ''
  if ($guid) {
    $ns = (Get-ItemProperty ("HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\" + $guid)).NameServer
  }
  "{0}`t{1}`t{2}`t{3}" -f $ix, $_.InterfaceAlias, ($_.ServerAddresses -join ','), $ns
}
"#;

#[cfg(windows)]
pub fn read_interfaces() -> Result<Vec<Interface>, Error> {
    let out = powershell(READ_SCRIPT)?;
    Ok(crate::sysdns::parse(&out))
}

/// Write `servers` to each interface, or clear the static list when it is `None`.
///
/// One elevated shell for the whole batch: a UAC prompt per interface would be a tool nobody
/// finishes using.
#[cfg(windows)]
pub fn apply(changes: &[(u32, Option<Vec<String>>)]) -> Result<(), Error> {
    if changes.is_empty() {
        return Ok(());
    }
    let mut script = String::from("$ErrorActionPreference='Stop';");
    for (index, servers) in changes {
        match servers {
            None => script.push_str(&format!(
                "Set-DnsClientServerAddress -InterfaceIndex {index} -ResetServerAddresses;"
            )),
            Some(list) => {
                let quoted: Vec<String> = list
                    .iter()
                    // Addresses only, and checked here rather than trusted: this string is
                    // about to become a command line.
                    .filter(|s| s.parse::<std::net::IpAddr>().is_ok())
                    .map(|s| format!("'{s}'"))
                    .collect();
                if quoted.is_empty() {
                    continue;
                }
                script.push_str(&format!(
                    "Set-DnsClientServerAddress -InterfaceIndex {index} -ServerAddresses {};",
                    quoted.join(",")
                ));
            }
        }
    }
    // Flush the resolver cache, or the block-page answers already in it survive the change and
    // the fix looks like it did nothing for the first few minutes.
    script.push_str("Clear-DnsClientCache;");
    elevated(&script)
}

#[cfg(windows)]
fn powershell(script: &str) -> Result<String, Error> {
    let out = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| Error::Io(e.to_string()))?;
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Run a script as administrator, and wait for it.
///
/// `Start-Process -Verb RunAs` is what raises the consent dialog. `-Wait` matters: without it
/// the caller would read the settings back before the change landed and report failure.
#[cfg(windows)]
fn elevated(script: &str) -> Result<(), Error> {
    let encoded = {
        let wide: Vec<u16> = script.encode_utf16().collect();
        let mut bytes = Vec::with_capacity(wide.len() * 2);
        for w in wide {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        base64(&bytes)
    };
    let launcher = format!(
        "$p = Start-Process powershell -Verb RunAs -Wait -PassThru -WindowStyle Hidden \
         -ArgumentList '-NoProfile','-EncodedCommand','{encoded}'; exit $p.ExitCode"
    );
    let status = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &launcher])
        .status()
        .map_err(|e| Error::Io(e.to_string()))?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::Refused)
    }
}

/// `-EncodedCommand` takes base64, and a script full of quotes has no business being pasted
/// into a command line twice.
#[cfg(windows)]
fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        s.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    s
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

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// Against the reference vectors in RFC 4648, because a wrong encoder here produces a
    /// script that runs *something else* with administrator rights.
    #[test]
    fn base64_matches_the_rfc() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    /// UTF-16LE, which is what `-EncodedCommand` expects; ASCII passed through as bytes would
    /// decode to garbage on the other side.
    #[test]
    fn a_script_encodes_as_utf16le() {
        let wide: Vec<u8> = "Hi".encode_utf16().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(wide, vec![b'H', 0, b'i', 0]);
        assert_eq!(base64(&wide), "SABpAA==");
    }
}
