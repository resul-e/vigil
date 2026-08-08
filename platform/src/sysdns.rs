//! Pointing Windows' own resolver at vigil, and putting it back. Pure.
//!
//! The proxy fixes names for the connections it carries and the environment variables reach
//! the programs that read them. What is left is everything else on the machine, and on this
//! line "everything else" is being handed the censor's block page: measured 2026-08-05, the
//! system resolver answered `roblox.com`, `discord.com`, `apis.roblox.com` and the rest with
//! `195.175.254.2` while an off-port upstream answered honestly.
//!
//! [`crate::dnsserver`](../../vigil_proxy/dnsserver/index.html) can serve that honest answer to
//! the whole machine. This module decides whether it is safe to point the machine at it, and
//! how to undo that — which matters more here than it does for the proxy setting, because a
//! machine left pointing at a resolver that is not running has **no name resolution at all**.
//!
//! # The two decisions that keep that from happening
//!
//! 1. **A fallback server is always written after us.** Windows queries the first server and
//!    moves to the next when it does not answer, so a vigil that stops leaves the machine
//!    working rather than dark. The fallback is deliberately *not* the ISP's resolver: on this
//!    line, plain UDP/53 to a public resolver is **dropped** for blocked names rather than
//!    answered falsely, so it can degrade us but it cannot poison us.
//! 2. **The previous setting is snapshotted before anything is written**, including whether it
//!    was DHCP, and `vigil-repair` can put it back without vigil running.

/// What Windows reports for one network interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub index: u32,
    pub alias: String,
    /// The servers currently in effect, in order.
    pub servers: Vec<String>,
    /// The statically configured servers. Empty means the interface is on DHCP, and restoring
    /// it means clearing the static list rather than writing yesterday's addresses back.
    pub static_servers: Vec<String>,
}

impl Interface {
    pub fn is_dhcp(&self) -> bool {
        self.static_servers.is_empty()
    }
}

/// Where a query goes when vigil is not answering.
///
/// Quad9 rather than the subscriber's own resolver, and the reason is measured: on this line
/// public resolvers are *dropped* for the blocked names and answered normally for everything
/// else, while the ISP's resolver answers the blocked ones with a block page. A fallback that
/// can only fail is strictly better than one that can lie.
pub const FALLBACK: &str = "9.9.9.9";

/// The loopback address the machine is pointed at.
pub const OURS: &str = "127.0.0.1";

/// What we would write for an interface.
pub fn ours() -> Vec<String> {
    vec![OURS.to_string(), FALLBACK.to_string()]
}

/// Is this interface already pointed at us?
pub fn points_at_us(i: &Interface) -> bool {
    i.servers.first().is_some_and(|s| s == OURS)
}

/// Interfaces worth touching: the ones that actually have a resolver configured.
///
/// An interface with no servers is not carrying the machine's DNS, and writing ours onto every
/// virtual adapter — WSL, Hyper-V, VPN stubs — would be a large blast radius for no gain.
pub fn targets(all: &[Interface]) -> Vec<&Interface> {
    all.iter()
        .filter(|i| !i.servers.is_empty() && !points_at_us(i))
        .collect()
}

/// Interfaces still pointing at a vigil that may not be running.
pub fn stranded(all: &[Interface]) -> Vec<&Interface> {
    all.iter().filter(|i| points_at_us(i)).collect()
}

/// What to write to put an interface back the way it was: `None` means "clear the static list
/// and let DHCP supply it again".
pub fn restore_value(snapshot: &Interface) -> Option<Vec<String>> {
    if snapshot.is_dhcp() {
        None
    } else {
        Some(snapshot.static_servers.clone())
    }
}

/// Serialise a snapshot: one interface per line, `index<TAB>alias<TAB>servers<TAB>static`.
pub fn snapshot_to_text(ifaces: &[Interface]) -> String {
    let mut s = String::new();
    for i in ifaces {
        s.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            i.index,
            i.alias,
            i.servers.join(","),
            i.static_servers.join(",")
        ));
    }
    s
}

/// Parse either a snapshot file or the tab-separated lines the Windows helper prints.
///
/// One format for both, so what is read back is exactly what was written and there is no
/// second parser to disagree with the first.
pub fn parse(text: &str) -> Vec<Interface> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 3 {
            continue;
        }
        let Ok(index) = f[0].trim().parse::<u32>() else {
            continue;
        };
        let split = |s: &str| -> Vec<String> {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        };
        out.push(Interface {
            index,
            alias: f[1].trim().to_string(),
            servers: split(f[2]),
            static_servers: split(f.get(3).copied().unwrap_or("")),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(index: u32, alias: &str, servers: &[&str], stat: &[&str]) -> Interface {
        Interface {
            index,
            alias: alias.into(),
            servers: servers.iter().map(|s| (*s).to_string()).collect(),
            static_servers: stat.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn what_we_write_puts_a_fallback_after_us() {
        let v = ours();
        assert_eq!(v[0], OURS, "we must be asked first");
        assert_eq!(
            v.len(),
            2,
            "a machine with only us on the list goes dark if we stop"
        );
        assert_ne!(v[1], OURS);
    }

    /// The fallback must not be able to lie. The ISP's resolver answers blocked names with a
    /// block page; a public one on plain 53 is dropped for exactly those names on this line.
    #[test]
    fn the_fallback_is_a_public_resolver_not_the_isps() {
        assert_eq!(FALLBACK, "9.9.9.9");
        assert!(
            !FALLBACK.starts_with("192.168."),
            "a router forwards to the ISP"
        );
        assert!(!FALLBACK.starts_with("10."));
    }

    #[test]
    fn only_interfaces_that_carry_dns_are_touched() {
        let all = vec![
            iface(21, "Ethernet", &["192.168.0.1"], &[]),
            iface(9, "vEthernet (WSL)", &[], &[]),
            iface(4, "Loopback", &[], &[]),
        ];
        let t = targets(&all);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].alias, "Ethernet");
    }

    /// Engaging twice must not write our own value into the snapshot, which is the mistake
    /// that makes a restore point at a resolver that is not running.
    #[test]
    fn an_interface_already_pointing_at_us_is_not_a_target() {
        let all = vec![iface(
            21,
            "Ethernet",
            &["127.0.0.1", "9.9.9.9"],
            &["127.0.0.1", "9.9.9.9"],
        )];
        assert!(points_at_us(&all[0]));
        assert!(targets(&all).is_empty());
        assert_eq!(stranded(&all).len(), 1, "but repair must still find it");
    }

    /// A machine on DHCP must go back to DHCP, not to a frozen copy of today's addresses.
    #[test]
    fn restoring_dhcp_clears_rather_than_writing_yesterdays_addresses() {
        let dhcp = iface(21, "Ethernet", &["192.168.0.1"], &[]);
        assert!(dhcp.is_dhcp());
        assert_eq!(restore_value(&dhcp), None);

        let stat = iface(21, "Ethernet", &["1.1.1.1"], &["1.1.1.1"]);
        assert!(!stat.is_dhcp());
        assert_eq!(restore_value(&stat), Some(vec!["1.1.1.1".to_string()]));
    }

    #[test]
    fn a_snapshot_round_trips() {
        let ifaces = vec![
            iface(21, "Ethernet", &["192.168.0.1"], &[]),
            iface(7, "Wi-Fi", &["1.1.1.1", "1.0.0.1"], &["1.1.1.1", "1.0.0.1"]),
        ];
        assert_eq!(parse(&snapshot_to_text(&ifaces)), ifaces);
    }

    /// The helper's output and a snapshot file are the same format on purpose; whatever the
    /// shell hands back, a line that is not one of ours must be skipped rather than guessed at.
    #[test]
    fn junk_lines_are_skipped_not_guessed_at() {
        let text = "21\tEthernet\t192.168.0.1\t\n\
                    not a line\n\
                    \n\
                    x\tEthernet\t1.2.3.4\t\n\
                    7\tWi-Fi\t1.1.1.1,1.0.0.1\t1.1.1.1\r\n";
        let v = parse(text);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].index, 21);
        assert_eq!(v[1].alias, "Wi-Fi");
        assert_eq!(v[1].servers.len(), 2);
        assert_eq!(v[1].static_servers, vec!["1.1.1.1".to_string()]);
    }

    #[test]
    fn an_alias_with_spaces_and_parentheses_survives() {
        let v = parse("9\tvEthernet (Default Switch)\t172.20.16.1\t\n");
        assert_eq!(v[0].alias, "vEthernet (Default Switch)");
    }
}
