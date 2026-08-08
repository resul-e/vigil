//! Which program opened this connection?
//!
//! The proxy has always been able to say *what* was asked for and never *who* asked. On
//! 2026-08-07 that was the difference between two explanations of the same Superonline report:
//! forty-seven connections arrived from "other programs" while Discord's Chromium half sent us
//! nothing, and whether any of those forty-seven came from a browser decides whether the
//! Windows proxy setting was in force at all. The report could not say, so the run could not
//! settle it, and a volunteer's evening bought less than it should have.
//!
//! Every client is on loopback and owned by the same user, so this needs no administrator
//! rights: `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)` lists the owning process id for
//! every TCP endpoint, and the client's own source port identifies its row.
//!
//! The row arithmetic is pure and tested on Linux. Getting it wrong would not fail loudly — it
//! would attribute connections to the wrong program, which is worse than not knowing.

/// Address family and table class, as `GetExtendedTcpTable` wants them.
#[cfg_attr(not(windows), allow(dead_code))]
const AF_INET: u32 = 2;
#[cfg_attr(not(windows), allow(dead_code))]
const TCP_TABLE_OWNER_PID_ALL: u32 = 5;

/// Bytes per `MIB_TCPROW_OWNER_PID`: six DWORDs, all naturally aligned, so no padding.
const ROW: usize = 24;

/// Find the process id owning the IPv4 TCP endpoint bound to `local_port`.
///
/// `table` is a `MIB_TCPTABLE_OWNER_PID` exactly as the API filled it: a count, then that many
/// rows. Pure so the offsets can be tested somewhere other than the machine they matter on.
///
/// The port inside a row is stored in **network byte order in the low two bytes** of a DWORD,
/// which is the detail that makes this worth a test rather than a one-liner.
pub fn owning_pid(table: &[u8], local_port: u16) -> Option<u32> {
    if table.len() < 4 {
        return None;
    }
    let count = u32::from_le_bytes([table[0], table[1], table[2], table[3]]) as usize;
    let rows = &table[4..];
    // Trust the buffer, not the count: a count larger than the bytes we were handed means we
    // have misunderstood the layout, and reading past the end would be the wrong way to find out.
    let available = rows.len() / ROW;
    for i in 0..count.min(available) {
        let r = &rows[i * ROW..][..ROW];
        let raw = u32::from_le_bytes([r[8], r[9], r[10], r[11]]);
        let port = u16::from_be_bytes([(raw & 0xFF) as u8, ((raw >> 8) & 0xFF) as u8]);
        if port == local_port {
            return Some(u32::from_le_bytes([r[20], r[21], r[22], r[23]]));
        }
    }
    None
}

/// The image name — `Discord.exe`, `msedge.exe` — of whatever opened the loopback connection
/// whose client-side port is `local_port`. `None` when it cannot be determined.
///
/// Never an error: a measurement that fails to name a program must degrade to "unknown", not
/// refuse the connection it was watching.
pub fn program_for_local_port(local_port: u16) -> Option<String> {
    imp::program_for_local_port(local_port)
}

#[cfg(windows)]
mod imp {
    use super::{owning_pid, AF_INET, TCP_TABLE_OWNER_PID_ALL};

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn GetExtendedTcpTable(
            table: *mut core::ffi::c_void,
            size: *mut u32,
            order: i32,
            af: u32,
            class: u32,
            reserved: u32,
        ) -> u32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> isize;
        fn CloseHandle(h: isize) -> i32;
        fn QueryFullProcessImageNameW(
            process: isize,
            flags: u32,
            name: *mut u16,
            size: *mut u32,
        ) -> i32;
    }

    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    const NO_ERROR: u32 = 0;

    pub fn program_for_local_port(local_port: u16) -> Option<String> {
        let pid = pid_for(local_port)?;
        image_name(pid)
    }

    fn pid_for(local_port: u16) -> Option<u32> {
        // Two calls: ask for the size, then ask again with a buffer. Retried a few times
        // because the table can grow between the two on a busy machine, and a fixed guess
        // would silently return nothing on exactly the machines worth measuring.
        let mut size: u32 = 0;
        for _ in 0..4 {
            let rc = unsafe {
                GetExtendedTcpTable(
                    core::ptr::null_mut(),
                    &mut size,
                    0,
                    AF_INET,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            };
            if rc != ERROR_INSUFFICIENT_BUFFER && rc != NO_ERROR {
                return None;
            }
            let mut buf = vec![0u8; size as usize];
            let rc = unsafe {
                GetExtendedTcpTable(
                    buf.as_mut_ptr().cast(),
                    &mut size,
                    0,
                    AF_INET,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            };
            if rc == NO_ERROR {
                return owning_pid(&buf, local_port);
            }
            if rc != ERROR_INSUFFICIENT_BUFFER {
                return None;
            }
        }
        None
    }

    fn image_name(pid: u32) -> Option<String> {
        if pid == 0 {
            return None;
        }
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h == 0 {
            return None;
        }
        let mut buf = [0u16; 260];
        let mut len = buf.len() as u32;
        let ok = unsafe { QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) };
        unsafe { CloseHandle(h) };
        if ok == 0 {
            return None;
        }
        let full = String::from_utf16_lossy(&buf[..len as usize]);
        // The file name only. The full path would name the user's profile directory, and this
        // number ends up in a report that gets forwarded.
        full.rsplit(['\\', '/']).next().map(str::to_string)
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn program_for_local_port(_local_port: u16) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a table the way Windows does, so the offsets are tested against the documented
    /// layout rather than against the reader.
    fn table(rows: &[(u16, u32)]) -> Vec<u8> {
        let mut b = (rows.len() as u32).to_le_bytes().to_vec();
        for (port, pid) in rows {
            b.extend_from_slice(&5u32.to_le_bytes()); // dwState = ESTABLISHED
            b.extend_from_slice(&0x0100_007Fu32.to_le_bytes()); // dwLocalAddr = 127.0.0.1
                                                                // dwLocalPort: network byte order in the low two bytes.
            let be = port.to_be_bytes();
            b.extend_from_slice(&u32::from_le_bytes([be[0], be[1], 0, 0]).to_le_bytes());
            b.extend_from_slice(&0u32.to_le_bytes()); // dwRemoteAddr
            b.extend_from_slice(&0u32.to_le_bytes()); // dwRemotePort
            b.extend_from_slice(&pid.to_le_bytes());
        }
        b
    }

    #[test]
    fn the_row_holding_our_port_names_its_process() {
        let t = table(&[(1080, 4), (52344, 9876), (443, 1234)]);
        assert_eq!(owning_pid(&t, 52344), Some(9876));
        assert_eq!(owning_pid(&t, 1080), Some(4));
        assert_eq!(owning_pid(&t, 443), Some(1234));
    }

    #[test]
    fn a_port_that_is_not_there_is_none_not_a_wrong_answer() {
        assert_eq!(owning_pid(&table(&[(1080, 4)]), 52344), None);
    }

    /// The byte order is the whole reason this is a tested function: read little-endian, a
    /// client on port 52344 (0xCC78) would be looked up as 0x78CC and quietly attributed to
    /// whatever else happened to match.
    #[test]
    fn the_port_is_read_in_network_byte_order() {
        let t = table(&[(52344, 7)]);
        assert_eq!(owning_pid(&t, 52344), Some(7));
        assert_eq!(owning_pid(&t, 0x78CC), None, "byte order is being ignored");
    }

    #[test]
    fn an_empty_or_truncated_table_is_none() {
        assert_eq!(owning_pid(&[], 1), None);
        assert_eq!(owning_pid(&[0, 0, 0], 1), None);
        assert_eq!(owning_pid(&1u32.to_le_bytes(), 1), None);
    }

    /// A count larger than the buffer must be clamped, not trusted. This runs against a
    /// kernel-filled buffer on somebody else's machine.
    #[test]
    fn a_count_that_overruns_the_buffer_does_not_panic() {
        let mut t = table(&[(1080, 4)]);
        t[0] = 200;
        assert_eq!(owning_pid(&t, 1080), Some(4));
        assert_eq!(owning_pid(&t, 9999), None);
    }

    #[cfg(not(windows))]
    #[test]
    fn off_windows_it_declines_rather_than_guessing() {
        assert_eq!(program_for_local_port(1080), None);
    }
}
