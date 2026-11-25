// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use crate::argv;
use crate::shell::{command_check, command_run, CommandError, Output, DEFAULT_TIMEOUT};

pub const IP: &str = "/usr/sbin/ip";
pub const ETHTOOL: &str = "/usr/sbin/ethtool";
const NETNS_RUN_DIR: &str = "/var/run/netns";

/// The kernel's interface name limit. A QinQ stack named from its parent gives
/// `enp1s0f0np0.100.200`, which is 19 characters and fails.
pub const IFNAMSIZ: usize = 15;

/// ETHTOOL_LINK_MODE_*_BIT indices. Note 2500baseT_Full is bit 47; probing the
/// wrong bit proves nothing, because the driver refuses an unknown mask either way.
pub const LINK_MODE_BITS: &[(u32, u32)] = &[(100, 3), (1000, 5), (2500, 47), (5000, 48), (10000, 12)];

/// Short name for `ethtool -K`, long name as `ethtool -k` prints it.
pub const OFFLOAD_FLAGS: &[(&str, &str, &str)] = &[
    ("rx_checksum", "rx", "rx-checksumming"),
    ("tx_checksum", "tx", "tx-checksumming"),
    ("tso", "tso", "tcp-segmentation-offload"),
    ("gso", "gso", "generic-segmentation-offload"),
    ("gro", "gro", "generic-receive-offload"),
    ("lro", "lro", "large-receive-offload"),
    ("sg", "sg", "scatter-gather"),
    ("rx_vlan", "rxvlan", "rx-vlan-offload"),
    ("tx_vlan", "txvlan", "tx-vlan-offload"),
];

const COUNTER_PATTERNS: &[&str] = &[
    "error", "drop", "discard", "xon", "xoff", "undersize", "oversize", "fragment", "jabber",
    "crc", "missed", "collision", "carrier", "align", "no_buffer", "fifo", "over",
];
const COUNTER_BASE_KEYS: &[&str] = &["rx_packets", "tx_packets", "rx_bytes", "tx_bytes"];

#[derive(Debug, thiserror::Error)]
pub enum NetnsError {
    #[error("{0}")]
    Rejected(String),
    #[error(transparent)]
    Command(#[from] CommandError),
}

pub fn ns_exec_argv(ns: Option<&str>, parts: &[String]) -> Vec<String> {
    match ns {
        None => parts.to_vec(),
        Some(name) => {
            let mut out = argv![IP, "netns", "exec", name];
            out.extend_from_slice(parts);
            out
        }
    }
}

pub async fn ns_exec(ns: Option<&str>, parts: &[String]) -> Output {
    command_run(&ns_exec_argv(ns, parts), DEFAULT_TIMEOUT, None).await
}

/// Run an ip(8) subcommand, using -n rather than a full exec where possible.
async fn ip_run(ns: Option<&str>, args: &[String]) -> Output {
    let mut parts = match ns {
        None => argv![IP],
        Some(name) => argv![IP, "-n", name],
    };
    parts.extend_from_slice(args);
    command_run(&parts, DEFAULT_TIMEOUT, None).await
}

async fn ip_check(ns: Option<&str>, args: &[String]) -> Result<Output, NetnsError> {
    let out = ip_run(ns, args).await;
    if out.ok() {
        Ok(out)
    } else {
        Err(NetnsError::Command(CommandError(out)))
    }
}

pub fn ns_list() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(NETNS_RUN_DIR) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

pub fn ns_exists(ns: &str) -> bool {
    Path::new(NETNS_RUN_DIR).join(ns).exists()
}

pub async fn ns_create(ns: &str) -> Result<(), NetnsError> {
    if ns_exists(ns) {
        return Ok(());
    }
    command_check(&argv![IP, "netns", "add", ns], DEFAULT_TIMEOUT).await?;
    // Without a running loopback, a socket bound inside the namespace cannot
    // reach itself, which breaks iperf3's control connection retry path.
    ip_check(Some(ns), &argv!["link", "set", "lo", "up"]).await?;
    Ok(())
}

pub async fn ns_delete(ns: &str) -> Result<(), NetnsError> {
    if !ns_exists(ns) {
        return Ok(());
    }
    command_check(&argv![IP, "netns", "del", ns], DEFAULT_TIMEOUT).await?;
    Ok(())
}

pub async fn link_names(ns: Option<&str>) -> Vec<String> {
    let out = ip_run(ns, &argv!["-j", "link", "show"]).await;
    if !out.ok() {
        return Vec::new();
    }
    serde_json::from_str::<Vec<serde_json::Value>>(&out.stdout)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|e| e["ifname"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Move a physical interface from the default namespace into ns.
pub async fn port_adopt(iface: &str, ns: &str) -> Result<(), NetnsError> {
    if !ns_exists(ns) {
        return Err(NetnsError::Rejected(format!("namespace {ns} does not exist")));
    }
    if link_names(Some(ns)).await.iter().any(|n| n == iface) {
        return Ok(());
    }
    if !link_names(None).await.iter().any(|n| n == iface) {
        return Err(NetnsError::Rejected(format!(
            "interface {iface} is not in the default namespace (already claimed elsewhere?)"
        )));
    }
    command_check(&argv![IP, "link", "set", iface, "netns", ns], DEFAULT_TIMEOUT).await?;
    Ok(())
}

/// Move an interface back to the default namespace, which is pid 1's.
pub async fn port_release(iface: &str, ns: &str) -> Result<(), NetnsError> {
    if !ns_exists(ns) || !link_names(Some(ns)).await.iter().any(|n| n == iface) {
        return Ok(());
    }
    let _ = ip_run(Some(ns), &argv!["link", "set", iface, "down"]).await;
    let _ = ip_run(Some(ns), &argv!["addr", "flush", "dev", iface]).await;
    command_check(&argv![IP, "-n", ns, "link", "set", iface, "netns", "1"], DEFAULT_TIMEOUT).await?;
    Ok(())
}

pub async fn link_up_set(ns: Option<&str>, iface: &str, up: bool) -> Result<(), NetnsError> {
    ip_check(ns, &argv!["link", "set", iface, if up { "up" } else { "down" }]).await?;
    Ok(())
}

pub async fn link_mtu_set(ns: Option<&str>, iface: &str, mtu: u32) -> Result<(), NetnsError> {
    ip_check(ns, &argv!["link", "set", iface, "mtu", mtu]).await?;
    Ok(())
}

pub async fn mac_set(ns: Option<&str>, iface: &str, mac: &str) -> Result<(), NetnsError> {
    ip_check(ns, &argv!["link", "set", iface, "address", mac]).await?;
    Ok(())
}

pub async fn addr_add(ns: Option<&str>, iface: &str, cidr: &str) -> Result<(), NetnsError> {
    let family = if cidr.contains(':') { "-6" } else { "-4" };
    ip_check(ns, &argv![family, "addr", "add", cidr, "dev", iface]).await?;
    Ok(())
}

pub async fn addr_flush(ns: Option<&str>, iface: &str) {
    let _ = ip_run(ns, &argv!["addr", "flush", "dev", iface]).await;
}

pub async fn route_default_add(ns: Option<&str>, gateway: &str, iface: &str) -> Result<(), NetnsError> {
    let family = if gateway.contains(':') { "-6" } else { "-4" };
    ip_check(ns, &argv![family, "route", "replace", "default", "via", gateway, "dev", iface]).await?;
    Ok(())
}

/// Add a VLAN sub-interface. `802.1ad` gives the outer tag of a QinQ stack.
///
/// `name` matters for QinQ: deriving it from the parent exceeds IFNAMSIZ.
pub async fn vlan_add(
    ns: Option<&str>,
    parent: &str,
    vid: u16,
    protocol: &str,
    name: Option<&str>,
) -> Result<String, NetnsError> {
    if !matches!(protocol, "802.1Q" | "802.1ad") {
        return Err(NetnsError::Rejected(format!(
            "vlan protocol must be 802.1Q or 802.1ad, got {protocol:?}"
        )));
    }
    let name = name.map(str::to_string).unwrap_or(format!("{parent}.{vid}"));
    if name.len() > IFNAMSIZ {
        return Err(NetnsError::Rejected(format!(
            "interface name {name:?} is {} characters, over the {IFNAMSIZ} limit",
            name.len()
        )));
    }
    if !link_names(ns).await.iter().any(|n| *n == name) {
        ip_check(
            ns,
            &argv!["link", "add", "link", parent, "name", &name, "type", "vlan", "protocol", protocol, "id", vid],
        )
        .await?;
    }
    Ok(name)
}

/// The peer's link-layer address from the namespace's neighbour table.
///
/// A crafted frame needs a real next hop: broadcast reaches a directly cabled
/// peer but a device will not forward it, so the frame would arrive nowhere in
/// the test that matters. One ping populates the table when it is cold.
pub async fn neigh_mac_get(ns: Option<&str>, ip: &str) -> Option<String> {
    for attempt in 0..2 {
        let out = ip_run(ns, &argv!["-j", "neigh", "show", "to", ip]).await;
        if let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(&out.stdout) {
            if let Some(mac) = entries.iter().find_map(|e| e["lladdr"].as_str()) {
                return Some(mac.to_string());
            }
        }
        if attempt == 0 {
            let _ = ns_exec(ns, &argv!["/usr/bin/ping", "-c", "1", "-W", "1", "-q", ip]).await;
        }
    }
    None
}

pub async fn addrs_get(ns: Option<&str>, iface: &str) -> Vec<String> {
    let out = ip_run(ns, &argv!["-j", "addr", "show", "dev", iface]).await;
    if !out.ok() {
        return Vec::new();
    }
    let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(&out.stdout) else {
        return Vec::new();
    };
    let mut addresses = Vec::new();
    for entry in entries {
        for info in entry["addr_info"].as_array().unwrap_or(&Vec::new()) {
            if info["scope"].as_str() == Some("link") {
                continue;
            }
            if let (Some(local), Some(prefix)) = (info["local"].as_str(), info["prefixlen"].as_u64())
            {
                addresses.push(format!("{local}/{prefix}"));
            }
        }
    }
    addresses
}

/// Restrict autoneg to a single speed, or restore every supported mode.
///
/// This is how a port presents itself as a slower link partner, for downshift
/// tests, without separate hardware.
pub async fn advertise_set(
    ns: Option<&str>,
    iface: &str,
    mbps: Option<u32>,
) -> Result<(), NetnsError> {
    let Some(mbps) = mbps else {
        let out = ns_exec(ns, &argv![ETHTOOL, "-s", iface, "autoneg", "on"]).await;
        if !out.ok() {
            return Err(NetnsError::Rejected(format!(
                "restoring autoneg on {iface} failed: {}",
                out.text()
            )));
        }
        return Ok(());
    };

    let bit = LINK_MODE_BITS
        .iter()
        .find(|(speed, _)| *speed == mbps)
        .map(|(_, bit)| *bit)
        .ok_or_else(|| {
            let known: Vec<String> = LINK_MODE_BITS.iter().map(|(s, _)| s.to_string()).collect();
            NetnsError::Rejected(format!(
                "no link-mode bit known for {mbps} Mbps; known: {}",
                known.join(", ")
            ))
        })?;

    let mask = format!("{:#x}", 1u64 << bit);
    let out = ns_exec(ns, &argv![ETHTOOL, "-s", iface, "advertise", mask]).await;
    if !out.ok() {
        let supported = link_state_get(ns, iface).await;
        return Err(NetnsError::Rejected(format!(
            "{iface} refused to advertise {mbps} Mbps ({}); it supports {}",
            out.text().trim(),
            supported["supported_modes"]
        )));
    }
    Ok(())
}

pub async fn offloads_get(ns: Option<&str>, dev: &str) -> BTreeMap<String, String> {
    let out = ns_exec(ns, &argv![ETHTOOL, "-k", dev]).await;
    let mut result = BTreeMap::new();
    if !out.ok() {
        return result;
    }
    let mut raw: BTreeMap<&str, &str> = BTreeMap::new();
    for line in out.stdout.lines() {
        if let Some((key, value)) = line.trim().split_once(':') {
            raw.insert(key.trim(), value.trim());
        }
    }
    for (name, _short, long) in OFFLOAD_FLAGS {
        if let Some(value) = raw.get(long) {
            let state = if value.starts_with("on") { "on" } else { "off" };
            let entry = if value.contains("[fixed]") {
                format!("fixed-{state}")
            } else {
                state.to_string()
            };
            result.insert(name.to_string(), entry);
        }
    }
    result
}

pub async fn offloads_set(
    ns: Option<&str>,
    dev: &str,
    settings: &BTreeMap<String, bool>,
) -> Result<BTreeMap<String, String>, NetnsError> {
    let known: Vec<&str> = OFFLOAD_FLAGS.iter().map(|(n, _, _)| *n).collect();
    let unknown: Vec<&String> = settings.keys().filter(|k| !known.contains(&k.as_str())).collect();
    if !unknown.is_empty() {
        return Err(NetnsError::Rejected(format!(
            "unknown offloads {unknown:?}; accepted: {known:?}"
        )));
    }

    let mut parts = argv![ETHTOOL, "-K", dev];
    for (name, wanted) in settings {
        let short = OFFLOAD_FLAGS
            .iter()
            .find(|(n, _, _)| n == name)
            .map(|(_, s, _)| *s)
            .unwrap_or(name.as_str());
        parts.push(short.to_string());
        parts.push(if *wanted { "on".into() } else { "off".into() });
    }
    let out = ns_exec(ns, &parts).await;
    if !out.ok() {
        return Err(NetnsError::Rejected(format!(
            "ethtool -K failed on {dev}: {}",
            out.text()
        )));
    }
    Ok(offloads_get(ns, dev).await)
}

pub async fn pause_get(ns: Option<&str>, dev: &str) -> BTreeMap<String, bool> {
    let out = ns_exec(ns, &argv![ETHTOOL, "-a", dev]).await;
    let mut result = BTreeMap::new();
    if !out.ok() {
        return result;
    }
    for line in out.stdout.lines() {
        let Some((key, value)) = line.trim().split_once(':') else {
            continue;
        };
        let field = match key.trim() {
            "Autonegotiate" => "autoneg",
            "RX" => "rx",
            "TX" => "tx",
            _ => continue,
        };
        result.insert(field.to_string(), value.trim() == "on");
    }
    result
}

/// Issue a pause change. The caller must verify it took.
///
/// i40e accepts `ethtool -A <dev> rx on tx on` with rc 0 and applies nothing,
/// while `autoneg off rx on tx on` fails outright with Operation not supported.
/// A success here means only that ethtool did not complain.
pub async fn pause_set(
    ns: Option<&str>,
    dev: &str,
    autoneg: Option<bool>,
    rx: Option<bool>,
    tx: Option<bool>,
) -> Result<(), NetnsError> {
    let mut parts = argv![ETHTOOL, "-A", dev];
    for (flag, value) in [("autoneg", autoneg), ("rx", rx), ("tx", tx)] {
        if let Some(wanted) = value {
            parts.push(flag.to_string());
            parts.push(if wanted { "on".into() } else { "off".into() });
        }
    }
    if parts.len() == 3 {
        return Err(NetnsError::Rejected(
            "pause_set needs at least one of autoneg, rx or tx".into(),
        ));
    }
    let out = ns_exec(ns, &parts).await;
    if !out.ok() {
        return Err(NetnsError::Rejected(format!(
            "ethtool -A failed on {dev}: {}",
            out.text()
        )));
    }
    Ok(())
}

/// Driver and link counters, merged. Filtered unless `full`: i40e alone reports
/// 298 statistics, which is no use to a caller reading them.
pub async fn counters_get(ns: Option<&str>, dev: &str, full: bool) -> BTreeMap<String, i64> {
    let mut stats = ethtool_stats(ns, dev).await;
    stats.extend(link_stats(ns, dev).await);
    if full {
        return stats;
    }
    stats
        .into_iter()
        .filter(|(key, _)| {
            let lower = key.to_lowercase();
            COUNTER_BASE_KEYS.contains(&key.as_str())
                || COUNTER_PATTERNS.iter().any(|p| lower.contains(p))
        })
        .collect()
}

/// Keep only the keys worth showing a caller, from an already-diffed map.
pub fn counters_interesting(moved: &BTreeMap<String, i64>) -> BTreeMap<String, i64> {
    moved
        .iter()
        .filter(|(key, _)| {
            let lower = key.to_lowercase();
            COUNTER_PATTERNS.iter().any(|p| lower.contains(p))
        })
        .map(|(key, value)| (key.clone(), *value))
        .collect()
}

/// Only the counters that moved, so a caller sees the run and not the history.
pub fn counters_diff(
    before: &BTreeMap<String, i64>,
    after: &BTreeMap<String, i64>,
) -> BTreeMap<String, i64> {
    after
        .iter()
        .filter_map(|(key, value)| {
            before
                .get(key)
                .filter(|previous| *previous != value)
                .map(|previous| (key.clone(), value - previous))
        })
        .collect()
}

async fn ethtool_stats(ns: Option<&str>, dev: &str) -> BTreeMap<String, i64> {
    let out = ns_exec(ns, &argv![ETHTOOL, "-S", dev]).await;
    let mut stats = BTreeMap::new();
    if !out.ok() {
        return stats;
    }
    for line in out.stdout.lines() {
        if let Some((key, value)) = line.trim().split_once(':') {
            if let Ok(number) = value.trim().parse::<i64>() {
                stats.insert(key.trim().to_string(), number);
            }
        }
    }
    stats
}

async fn link_stats(ns: Option<&str>, dev: &str) -> BTreeMap<String, i64> {
    let out = ip_run(ns, &argv!["-s", "-j", "link", "show", "dev", dev]).await;
    let mut stats = BTreeMap::new();
    if !out.ok() {
        return stats;
    }
    let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(&out.stdout) else {
        return stats;
    };
    let Some(blocks) = entries.first().and_then(|e| e["stats64"].as_object()) else {
        return stats;
    };
    for (direction, block) in blocks {
        for (key, value) in block.as_object().unwrap_or(&serde_json::Map::new()) {
            if let Some(number) = value.as_i64() {
                stats.insert(format!("link.{direction}_{key}"), number);
            }
        }
    }
    stats
}

/// Carrier, negotiated speed and duplex, read from the owning namespace.
pub async fn link_state_get(ns: Option<&str>, iface: &str) -> serde_json::Value {
    let mut state = serde_json::json!({"iface": iface, "netns": ns, "present": false});

    let out = ip_run(ns, &argv!["-j", "-d", "link", "show", "dev", iface]).await;
    if !out.ok() {
        return state;
    }
    let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(&out.stdout) else {
        return state;
    };
    let Some(entry) = entries.first() else {
        return state;
    };

    let flags: Vec<&str> = entry["flags"]
        .as_array()
        .map(|f| f.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let map = state.as_object_mut().expect("state is an object");
    map.insert("present".into(), true.into());
    map.insert("mac".into(), entry["address"].clone());
    map.insert("mtu".into(), entry["mtu"].clone());
    map.insert("operstate".into(), entry["operstate"].clone());
    map.insert("admin_up".into(), flags.contains(&"UP").into());
    map.insert("carrier".into(), (!flags.contains(&"NO-CARRIER")).into());

    let ethtool = ethtool_state(ns, iface).await;
    if let Some(extra) = ethtool.as_object() {
        for (key, value) in extra {
            map.insert(key.clone(), value.clone());
        }
    }
    state
}

async fn ethtool_state(ns: Option<&str>, iface: &str) -> serde_json::Value {
    let out = ns_exec(ns, &argv![ETHTOOL, iface]).await;
    if !out.ok() {
        return serde_json::json!({});
    }
    let text = &out.stdout;
    let mut map = serde_json::Map::new();

    for (key, field) in [
        ("Speed", "speed"),
        ("Duplex", "duplex"),
        ("Auto-negotiation", "autoneg"),
        ("Port", "port"),
        ("Link detected", "link_detected"),
    ] {
        if let Some(value) = scalar_find(text, key) {
            map.insert(field.into(), value.into());
        }
    }

    let supported = modes_parse(text, "Supported link modes:");
    for (header, field) in [
        ("Advertised link modes:", "advertised_modes"),
        ("Link partner advertised link modes:", "link_partner_modes"),
    ] {
        let parsed = modes_parse(text, header);
        if !parsed.is_empty() {
            map.insert(field.into(), serde_json::to_value(&parsed).unwrap());
        }
    }
    let max = supported.iter().filter_map(|m| mode_mbps(m)).max();
    if !supported.is_empty() {
        map.insert("supported_modes".into(), serde_json::to_value(&supported).unwrap());
    }
    map.insert(
        "speed_mbps".into(),
        serde_json::to_value(map.get("speed").and_then(|v| v.as_str()).and_then(speed_mbps)).unwrap(),
    );
    map.insert("max_speed_mbps".into(), serde_json::to_value(max).unwrap());
    map.insert(
        "pause".into(),
        serde_json::to_value(pause_get(ns, iface).await).unwrap(),
    );
    serde_json::Value::Object(map)
}

fn scalar_find(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some((found, value)) = trimmed.split_once(':') {
            if found.trim() == key && !value.trim().is_empty() {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// Collect a multi-line ethtool mode list.
///
/// Continuation lines are indented with no key of their own and may carry
/// several modes, as in "10baseT/Half 10baseT/Full".
pub fn modes_parse(text: &str, header: &str) -> Vec<String> {
    let mut modes = Vec::new();
    let mut in_block = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(header) {
            in_block = true;
            if let Some((_, rest)) = trimmed.split_once(':') {
                modes.extend(rest.split_whitespace().map(str::to_string));
            }
            continue;
        }
        if !in_block {
            continue;
        }
        if trimmed.contains(':') || trimmed.is_empty() {
            break;
        }
        modes.extend(trimmed.split_whitespace().map(str::to_string));
    }
    modes.retain(|m| m != "Not" && m != "reported");
    modes
}

pub fn speed_mbps(speed: &str) -> Option<u32> {
    let text = speed.trim();
    if text.contains("Unknown") {
        return None;
    }
    if let Some(number) = text.strip_suffix("Mb/s") {
        return number.trim().parse().ok();
    }
    if let Some(number) = text.strip_suffix("Gb/s") {
        return number.trim().parse::<f64>().ok().map(|g| (g * 1000.0) as u32);
    }
    None
}

fn mode_mbps(mode: &str) -> Option<u32> {
    let digits: String = mode.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Join two namespaces with a veth pair. Used for self-tests with no DUT attached.
pub async fn veth_add(ns_a: &str, ns_b: &str, name_a: &str, name_b: &str) -> Result<(), NetnsError> {
    command_check(
        &argv![IP, "link", "add", name_a, "type", "veth", "peer", "name", name_b],
        DEFAULT_TIMEOUT,
    )
    .await?;
    command_check(&argv![IP, "link", "set", name_a, "netns", ns_a], DEFAULT_TIMEOUT).await?;
    command_check(&argv![IP, "link", "set", name_b, "netns", ns_b], DEFAULT_TIMEOUT).await?;
    Ok(())
}

pub const PAUSE_SETTLE: Duration = Duration::from_millis(1500);

#[cfg(test)]
mod tests {
    use super::*;

    const X710: &str = "Settings for enp1s0f0np0:
	Supported ports: [ TP ]
	Supported link modes:   100baseT/Full
	                        1000baseT/Full
	                        10000baseT/Full
	Supported pause frame use: Symmetric Receive-only
	Supports auto-negotiation: Yes
	Advertised link modes:  100baseT/Full
	                        1000baseT/Full
	                        10000baseT/Full
	Advertised pause frame use: No
	Speed: 1000Mb/s
	Duplex: Full
	Auto-negotiation: on
	Link detected: yes";

    const IGB: &str = "	Supported link modes:   10baseT/Half 10baseT/Full
	                        100baseT/Half 100baseT/Full
	                        1000baseT/Full
	Supported pause frame use: Symmetric
	Speed: Unknown!";

    #[test]
    fn modes_parse_handles_continuation_lines() {
        assert_eq!(
            modes_parse(X710, "Supported link modes:"),
            vec!["100baseT/Full", "1000baseT/Full", "10000baseT/Full"]
        );
    }

    #[test]
    fn modes_parse_handles_several_modes_on_one_line() {
        assert_eq!(
            modes_parse(IGB, "Supported link modes:"),
            vec![
                "10baseT/Half", "10baseT/Full",
                "100baseT/Half", "100baseT/Full",
                "1000baseT/Full"
            ]
        );
    }

    #[test]
    fn link_partner_header_does_not_match_advertised() {
        let text = "	Advertised link modes:  1000baseT/Full\n	Link partner advertised link modes: 100baseT/Full\n	Speed: 1000Mb/s";
        assert_eq!(modes_parse(text, "Advertised link modes:"), vec!["1000baseT/Full"]);
        assert_eq!(
            modes_parse(text, "Link partner advertised link modes:"),
            vec!["100baseT/Full"]
        );
    }

    #[test]
    fn no_partner_modes_is_absent_not_empty_zero() {
        assert!(modes_parse(X710, "Link partner advertised link modes:").is_empty());
    }

    #[test]
    fn scalars_parse() {
        assert_eq!(scalar_find(X710, "Speed").unwrap(), "1000Mb/s");
        assert_eq!(scalar_find(X710, "Duplex").unwrap(), "Full");
        assert_eq!(scalar_find(X710, "Link detected").unwrap(), "yes");
        assert!(scalar_find(X710, "Nonexistent").is_none());
    }

    #[test]
    fn speed_parsing_covers_both_units_and_unknown() {
        assert_eq!(speed_mbps("1000Mb/s"), Some(1000));
        assert_eq!(speed_mbps("10000Mb/s"), Some(10000));
        assert_eq!(speed_mbps("10Gb/s"), Some(10000));
        assert_eq!(speed_mbps("Unknown!"), None);
    }

    #[test]
    fn max_speed_comes_from_the_widest_supported_mode() {
        let modes = modes_parse(X710, "Supported link modes:");
        assert_eq!(modes.iter().filter_map(|m| mode_mbps(m)).max(), Some(10000));
        let modes = modes_parse(IGB, "Supported link modes:");
        assert_eq!(modes.iter().filter_map(|m| mode_mbps(m)).max(), Some(1000));
    }

    #[test]
    fn link_mode_bit_for_2500_is_47() {
        let lookup = |mbps: u32| LINK_MODE_BITS.iter().find(|(s, _)| *s == mbps).map(|(_, b)| *b);
        assert_eq!(lookup(2500), Some(47));
        assert_eq!(lookup(10000), Some(12));
        assert_eq!(lookup(1000), Some(5));
        assert_eq!(lookup(100), Some(3));
        assert_eq!(lookup(777), None);
        assert_eq!(format!("{:#x}", 1u64 << 47), "0x800000000000");
    }

    #[test]
    fn ns_exec_argv_wraps_only_when_a_namespace_is_given() {
        assert_eq!(ns_exec_argv(None, &argv!["ethtool", "eth0"]), vec!["ethtool", "eth0"]);
        assert_eq!(
            ns_exec_argv(Some("tgen-p0"), &argv!["ethtool", "eth0"]),
            vec![IP, "netns", "exec", "tgen-p0", "ethtool", "eth0"]
        );
    }

    #[test]
    fn offload_names_map_short_to_long() {
        let short = |name: &str| {
            OFFLOAD_FLAGS.iter().find(|(n, _, _)| *n == name).map(|(_, s, _)| *s)
        };
        assert_eq!(short("tx_checksum"), Some("tx"));
        assert_eq!(short("rx_vlan"), Some("rxvlan"));
        assert_eq!(short("tso"), Some("tso"));
    }

    #[test]
    fn counters_diff_reports_only_what_moved() {
        let before = BTreeMap::from([
            ("tx_packets".to_string(), 10i64),
            ("rx_errors".to_string(), 0),
            ("unchanged".to_string(), 7),
        ]);
        let after = BTreeMap::from([
            ("tx_packets".to_string(), 110i64),
            ("rx_errors".to_string(), 2),
            ("unchanged".to_string(), 7),
            ("appeared".to_string(), 5),
        ]);
        let moved = counters_diff(&before, &after);
        assert_eq!(moved.get("tx_packets"), Some(&100));
        assert_eq!(moved.get("rx_errors"), Some(&2));
        assert!(!moved.contains_key("unchanged"));
        // A key absent from the baseline has no delta to report.
        assert!(!moved.contains_key("appeared"));
    }

    #[tokio::test]
    async fn vlan_name_over_the_limit_is_refused_with_the_count() {
        let err = vlan_add(Some("tgen-p0"), "enp1s0f0np0.100", 200, "802.1Q", None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("19 characters"), "{err}");
        assert!(err.contains("over the 15 limit"), "{err}");
    }

    #[tokio::test]
    async fn bad_vlan_protocol_refused() {
        let err = vlan_add(None, "eth0", 10, "802.1X", None).await.unwrap_err().to_string();
        assert!(err.contains("802.1Q or 802.1ad"), "{err}");
    }

    #[tokio::test]
    async fn advertise_set_rejects_an_unknown_speed() {
        let err = advertise_set(None, "eth0", Some(777)).await.unwrap_err().to_string();
        assert!(err.contains("no link-mode bit known for 777"), "{err}");
    }
}
