// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::process::{Child, Command};

use crate::argv;
use crate::netns::ns_exec_argv;

pub const TRAFGEN: &str = "/usr/sbin/trafgen";

pub const MIN_FRAME: u32 = 60;
pub const MAX_FRAME: u32 = 9216;
const ETH_HEADER: u32 = 14;
const IP_HEADER: u32 = 20;
const UDP_HEADER: u32 = 8;

/// trafgen's default 0.5 MiB TX ring fails on i40e with EAGAIN from the flush,
/// so the ring is enlarged rather than left at the default.
pub const DEFAULT_RING_SIZE: &str = "4MiB";

const STOP_GRACE: Duration = Duration::from_secs(5);
const START_TIMEOUT: Duration = Duration::from_secs(10);
const START_POLL: Duration = Duration::from_millis(200);

/// Transient and not fatal. On i40e trafgen's TX_RING flush returns EAGAIN
/// repeatedly while traffic still flows: one run logged it on all eight workers
/// and still transmitted. Occurrences are counted and reported, and a run is
/// judged solely by whether packets actually left the port.
const FLUSH_ERROR_MARKER: &str = "Flushing TX_RING failed";
const FATAL_MARKERS: &[&str] = &["Unknown option", "invalid option", "No such device", "Cannot open"];

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct TrafgenError(pub String);

fn rejected<T>(message: impl Into<String>) -> Result<T, TrafgenError> {
    Err(TrafgenError(message.into()))
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TrafgenSpec {
    #[serde(default = "sixty_four")]
    pub frame_bytes: u32,
    #[serde(default = "ten")]
    pub duration_s: u32,
    #[serde(default = "four")]
    pub cpus: u32,
    /// Paces the load, for example '1Mpps' or '5Gbit'. Omit to send as fast as
    /// the host can.
    #[serde(default)]
    pub rate: Option<String>,
    #[serde(default = "src_ip_default")]
    pub src_ip: String,
    #[serde(default = "dst_ip_default")]
    pub dst_ip: String,
    #[serde(default = "sport_default")]
    pub sport: u16,
    #[serde(default = "dport_default")]
    pub dport: u16,
    #[serde(default)]
    pub vlan: Option<u16>,
    /// Above 1, one packet block per source address is emitted.
    #[serde(default = "one")]
    pub src_mac_count: u32,
    #[serde(default = "ring_default")]
    pub ring_size: String,
}

fn sixty_four() -> u32 {
    64
}
fn ten() -> u32 {
    10
}
fn four() -> u32 {
    4
}
fn one() -> u32 {
    1
}
fn src_ip_default() -> String {
    "10.0.0.1".into()
}
fn dst_ip_default() -> String {
    "10.0.0.2".into()
}
fn sport_default() -> u16 {
    12345
}
fn dport_default() -> u16 {
    9999
}
fn ring_default() -> String {
    DEFAULT_RING_SIZE.into()
}

impl Default for TrafgenSpec {
    fn default() -> Self {
        Self {
            frame_bytes: sixty_four(),
            duration_s: ten(),
            cpus: four(),
            rate: None,
            src_ip: src_ip_default(),
            dst_ip: dst_ip_default(),
            sport: sport_default(),
            dport: dport_default(),
            vlan: None,
            src_mac_count: one(),
            ring_size: ring_default(),
        }
    }
}

impl TrafgenSpec {
    pub fn validate(&self) -> Result<(), TrafgenError> {
        // 60 is the Ethernet minimum before the 4-byte FCS the MAC appends, and
        // it exceeds the 46 bytes an Ethernet, VLAN, IPv4 and UDP header stack
        // needs, so no separate header-fit check is reachable.
        if !(MIN_FRAME..=MAX_FRAME).contains(&self.frame_bytes) {
            return rejected(format!(
                "frame_bytes {} out of range {MIN_FRAME}..{MAX_FRAME}",
                self.frame_bytes
            ));
        }
        if !(1..=86400).contains(&self.duration_s) {
            return rejected(format!("duration_s {} out of range 1..86400", self.duration_s));
        }
        if !(1..=64).contains(&self.cpus) {
            return rejected(format!("cpus {} out of range 1..64", self.cpus));
        }
        if let Some(vlan) = self.vlan {
            if !(1..=4094).contains(&vlan) {
                return rejected(format!("vlan {vlan} out of range 1..4094"));
            }
        }
        if !(1..=256).contains(&self.src_mac_count) {
            return rejected(format!(
                "src_mac_count {} out of range 1..256",
                self.src_mac_count
            ));
        }
        Ok(())
    }
}

/// Derive a distinct source MAC from the port's own, index in the last octet.
///
/// The locally administered bit is forced on, so the generated addresses cannot
/// be mistaken for the card's real globally assigned address.
pub fn mac_vary(base: &str, index: u32) -> String {
    let mut parts: Vec<u8> = base
        .split(':')
        .filter_map(|p| u8::from_str_radix(p, 16).ok())
        .collect();
    if parts.len() != 6 {
        return base.to_string();
    }
    parts[0] |= 0x02;
    parts[5] = (index & 0xFF) as u8;
    parts.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

fn mac_bytes(mac: &str) -> String {
    mac.split(':').map(|p| format!("0x{p}")).collect::<Vec<_>>().join(", ")
}

fn ip_bytes(addr: &str) -> String {
    addr.split('.')
        .filter_map(|p| p.parse::<u8>().ok())
        .map(|b| format!("0x{b:02x}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn packet_build(spec: &TrafgenSpec, src_mac: &str, dst_mac: &str) -> String {
    let tagged = spec.vlan.is_some();
    let ip_offset = ETH_HEADER + if tagged { 4 } else { 0 };
    let udp_offset = ip_offset + IP_HEADER;
    let payload = spec.frame_bytes - (udp_offset + UDP_HEADER);

    let mut lines = vec![format!("{},", mac_bytes(dst_mac)), format!("{},", mac_bytes(src_mac))];
    if let Some(vlan) = spec.vlan {
        lines.push("0x81, 0x00,".into());
        lines.push(format!("const16({vlan}),"));
    }
    lines.push("0x08, 0x00,".into());
    lines.push(format!("0x45, 0x00, const16({}),", spec.frame_bytes - ip_offset));
    lines.push("const16(0), 0x40, 0x00, 0x40, 0x11,".into());
    lines.push(format!("csumip({ip_offset}, {}),", ip_offset + IP_HEADER - 1));
    lines.push(format!("{},", ip_bytes(&spec.src_ip)));
    lines.push(format!("{},", ip_bytes(&spec.dst_ip)));
    lines.push(format!("const16({}), const16({}),", spec.sport, spec.dport));
    lines.push(format!("const16({}),", UDP_HEADER + payload));
    lines.push(format!("csumudp({ip_offset}, {udp_offset}),"));
    if payload > 0 {
        lines.push(format!("fill(0x00, {payload}),"));
    }
    format!("{{\n  {}\n}}", lines.join("\n  "))
}

/// Valid Ethernet/IPv4/UDP frames, so a device under test will forward them.
///
/// trafgen computes both checksums itself via csumip and csumudp, with offsets
/// that shift when a VLAN tag is present.
///
/// For src_mac_count above one, one packet block per address is emitted and
/// trafgen cycles through them. A runtime drnd() would be both inexact, since it
/// randomises the whole octet regardless of the count asked for, and slower:
/// trafgen's own example warns that dynamic elements cost performance.
pub fn config_build(spec: &TrafgenSpec, src_mac: &str, dst_mac: &str) -> Result<String, TrafgenError> {
    spec.validate()?;
    if spec.src_mac_count == 1 {
        return Ok(format!("{}\n", packet_build(spec, src_mac, dst_mac)));
    }
    let blocks: Vec<String> = (0..spec.src_mac_count)
        .map(|index| packet_build(spec, &mac_vary(src_mac, index), dst_mac))
        .collect();
    Ok(format!("{}\n", blocks.join("\n")))
}

pub fn trafgen_argv(dev: &str, conf: &Path, spec: &TrafgenSpec) -> Vec<String> {
    let mut parts = argv![
        TRAFGEN,
        "--dev", dev,
        "--conf", conf.display(),
        "--ring-size", &spec.ring_size,
        "--cpus", spec.cpus,
        "--num", "0",
        "--no-cpu-stats",
        // /proc/sys/net/core is read-only under `ip netns exec`, and trafgen
        // treats failing to tune socket memory as fatal for some cpu counts.
        "--no-sock-mem",
    ];
    if let Some(rate) = &spec.rate {
        parts.extend(argv!["--rate", rate]);
    }
    parts
}

/// A small-frame load from one port, measured by counters on both ends.
pub struct TrafgenFlow {
    pub ns: String,
    pub dev: String,
    pub spec: TrafgenSpec,
    pub conf: PathBuf,
    pub log_path: PathBuf,
    child: Option<Child>,
    pgid: Option<i32>,
}

impl TrafgenFlow {
    pub fn new(
        ns: &str,
        dev: &str,
        spec: TrafgenSpec,
        conf: PathBuf,
        src_mac: &str,
        dst_mac: &str,
    ) -> Result<Self, TrafgenError> {
        let text = config_build(&spec, src_mac, dst_mac)?;
        if let Some(parent) = conf.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&conf, text).map_err(|e| TrafgenError(format!("cannot write config: {e}")))?;
        Ok(Self {
            ns: ns.to_string(),
            dev: dev.to_string(),
            spec,
            log_path: conf.with_file_name("trafgen.log"),
            conf,
            child: None,
            pgid: None,
        })
    }

    /// Liveness of the worker group, not of the parent.
    ///
    /// With more than one cpu trafgen forks workers and the parent exits at once,
    /// so the parent's exit says nothing about whether traffic is flowing.
    pub fn running(&self) -> bool {
        let Some(pgid) = self.pgid else { return false };
        unsafe { libc::killpg(pgid, 0) == 0 }
    }

    /// `probe_iface` is the physical port whose transmit counter proves the
    /// workers are sending, which is the only reliable readiness signal here.
    pub async fn start(&mut self, probe_iface: &str) -> Result<(), TrafgenError> {
        let parts = ns_exec_argv(Some(&self.ns), &trafgen_argv(&self.dev, &self.conf, &self.spec));
        tracing::info!(command = %parts.join(" "), "trafgen");

        // Output goes to a file, never a pipe: trafgen prints while it runs and
        // an undrained pipe fills, blocking it on write. Its own session, so the
        // forked workers share one process group and can all be signalled;
        // signalling the parent alone leaves them transmitting at line rate.
        let log = std::fs::File::create(&self.log_path)
            .map_err(|e| TrafgenError(format!("cannot open trafgen log: {e}")))?;
        let errors = log
            .try_clone()
            .map_err(|e| TrafgenError(format!("cannot duplicate log handle: {e}")))?;

        let (program, rest) = parts.split_first().expect("argv is never empty");
        let mut command = Command::new(program);
        command
            .args(rest)
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(errors))
            .stdin(Stdio::null())
            .process_group(0);
        let child = command
            .spawn()
            .map_err(|e| TrafgenError(format!("cannot start trafgen: {e}")))?;
        self.pgid = child.id().map(|pid| pid as i32);
        self.child = Some(child);

        self.ready_wait(probe_iface).await
    }

    /// Wait until packets are actually leaving the port, or a real error appears.
    ///
    /// Two things rule out the obvious checks. The parent exiting is not a
    /// failure, as above. And trafgen's stdout is a file, so libc full-buffers it
    /// and the startup banner never reaches disk while the process lives, which
    /// makes a log marker useless. A rising transmit counter is unambiguous.
    ///
    /// A fatal message does arrive, because the buffer is flushed when trafgen
    /// exits on the error.
    async fn ready_wait(&mut self, probe_iface: &str) -> Result<(), TrafgenError> {
        let baseline = self.tx_packets(probe_iface).await;
        let deadline = tokio::time::Instant::now() + START_TIMEOUT;
        while tokio::time::Instant::now() < deadline {
            let text = self.output();
            if let Some(marker) = FATAL_MARKERS.iter().find(|m| text.contains(*m)) {
                let tail = tail_of(&text, 300);
                self.stop().await;
                return rejected(format!("trafgen failed to start ({marker}): {tail}"));
            }
            if self.tx_packets(probe_iface).await > baseline {
                return Ok(());
            }
            tokio::time::sleep(START_POLL).await;
        }

        let alive = self.running();
        let flush_errors = self.flush_errors();
        let tail = tail_of(&self.output(), 200);
        self.stop().await;
        rejected(format!(
            "trafgen sent no packets within {START_TIMEOUT:?} (workers {}). \
             {flush_errors} TX_RING flush errors across {} workers. Log: {}",
            if alive { "alive" } else { "gone" },
            self.spec.cpus,
            if tail.is_empty() { "empty" } else { &tail }
        ))
    }

    async fn tx_packets(&self, iface: &str) -> i64 {
        crate::netns::counters_get(Some(&self.ns), iface, true)
            .await
            .get("tx_packets")
            .copied()
            .unwrap_or(0)
    }

    pub async fn stop(&mut self) {
        self.group_signal(libc::SIGTERM);
        // Reap the leader before polling the group. killpg(pgid, 0) succeeds on
        // a zombie, so an unreaped leader makes running() true for ever: stop()
        // then burns both grace periods and reports the group alive after
        // SIGKILL while the real workers are long gone.
        self.leader_reap().await;
        if !self.group_gone_wait(STOP_GRACE).await {
            tracing::warn!("trafgen workers survived SIGTERM, killing the group");
            self.group_signal(libc::SIGKILL);
            if !self.group_gone_wait(STOP_GRACE).await {
                tracing::error!(pgid = ?self.pgid, "trafgen group still alive after SIGKILL");
            }
        }
        self.leader_reap().await;
    }

    async fn leader_reap(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
        }
    }

    fn group_signal(&self, signal: i32) {
        if let Some(pgid) = self.pgid {
            unsafe {
                libc::killpg(pgid, signal);
            }
        }
    }

    async fn group_gone_wait(&self, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            if !self.running() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        !self.running()
    }

    pub fn output(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }

    pub fn flush_errors(&self) -> usize {
        self.output().matches(FLUSH_ERROR_MARKER).count()
    }
}

/// Derive pps and loss from the counters, since trafgen only reports its own TX.
pub fn summary_build(
    spec: &TrafgenSpec,
    elapsed_s: f64,
    tx_delta: &std::collections::BTreeMap<String, i64>,
    rx_delta: &std::collections::BTreeMap<String, i64>,
) -> Value {
    let sent = tx_delta.get("tx_packets").copied().unwrap_or(0);
    let received = rx_delta.get("rx_packets").copied().unwrap_or(0);
    // Measured bytes, not frame_bytes times packets: inferring the rate from the
    // requested frame size reports nonsense if anything else is on the link.
    let sent_bytes = tx_delta.get("tx_bytes").copied().unwrap_or(0);
    let received_bytes = rx_delta.get("rx_bytes").copied().unwrap_or(0);
    let per_s = |value: i64| {
        if elapsed_s > 0.0 {
            Some((value as f64 / elapsed_s / 1e6 * 10000.0).round() / 10000.0)
        } else {
            None
        }
    };
    let gbps = |bytes: i64| {
        if elapsed_s > 0.0 {
            Some((bytes as f64 * 8.0 / elapsed_s / 1e9 * 1000.0).round() / 1000.0)
        } else {
            None
        }
    };

    let mut out = json!({
        "frame_bytes": spec.frame_bytes,
        "duration_s": (elapsed_s * 100.0).round() / 100.0,
        "cpus": spec.cpus,
        "packets_sent": sent,
        "packets_received": received,
        "tx_mpps": per_s(sent),
        "rx_mpps": per_s(received),
        "tx_gbps": gbps(sent_bytes),
        "rx_gbps": gbps(received_bytes),
        "mean_tx_frame_bytes": (sent > 0).then(|| (sent_bytes as f64 / sent as f64 * 10.0).round() / 10.0),
        "rx_missed_errors": rx_delta.get("rx_missed_errors").copied().unwrap_or(0),
    });
    if sent > 0 {
        let lost = sent - received;
        out["loss_packets"] = lost.into();
        out["loss_percent"] = (((100.0 * lost as f64 / sent as f64) * 10000.0).round() / 10000.0).into();
    }
    out
}

fn tail_of(text: &str, limit: usize) -> String {
    let trimmed = text.trim();
    if trimmed.len() <= limit {
        return trimmed.to_string();
    }
    trimmed
        .char_indices()
        .rev()
        .nth(limit)
        .map(|(index, _)| trimmed[index..].to_string())
        .unwrap_or_else(|| trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_vary_forces_the_locally_administered_bit() {
        assert_eq!(mac_vary("3c:fd:fe:97:8e:98", 0), "3e:fd:fe:97:8e:00");
        assert_eq!(mac_vary("3c:fd:fe:97:8e:98", 255), "3e:fd:fe:97:8e:ff");
        let first = u8::from_str_radix(&mac_vary("3c:fd:fe:97:8e:98", 7)[..2], 16).unwrap();
        assert_eq!(first & 0x02, 0x02);
    }

    #[test]
    fn one_packet_block_per_requested_mac() {
        // Regression: drnd(1) randomised the whole octet, so asking for 16
        // source MACs put 255 distinct addresses on the wire.
        for count in [1u32, 2, 16, 64] {
            let spec = TrafgenSpec { src_mac_count: count, ..Default::default() };
            let cfg = config_build(&spec, "3c:fd:fe:97:8e:98", "3c:fd:fe:97:8e:99").unwrap();
            assert_eq!(cfg.matches('{').count(), count as usize);
            assert!(!cfg.contains("drnd"));
        }
    }

    #[test]
    fn generated_macs_are_distinct() {
        let spec = TrafgenSpec { src_mac_count: 8, ..Default::default() };
        let cfg = config_build(&spec, "3c:fd:fe:97:8e:98", "3c:fd:fe:97:8e:99").unwrap();
        let sources: Vec<&str> = cfg.lines().filter(|l| l.trim_start().starts_with("0x3e")).collect();
        assert_eq!(sources.len(), 8);
        assert_eq!(sources.iter().collect::<std::collections::HashSet<_>>().len(), 8);
    }

    #[test]
    fn vlan_shifts_the_checksum_offsets() {
        let plain = config_build(&TrafgenSpec::default(), "02:00:00:00:00:01", "02:00:00:00:00:02").unwrap();
        let tagged = config_build(
            &TrafgenSpec { vlan: Some(100), ..Default::default() },
            "02:00:00:00:00:01", "02:00:00:00:00:02",
        ).unwrap();
        assert!(plain.contains("csumip(14, 33)"));
        assert!(tagged.contains("csumip(18, 37)"));
        assert!(tagged.contains("0x81, 0x00"));
    }

    #[test]
    fn minimum_frame_still_fits_a_vlan_header_stack() {
        // 60 bytes holds eth + vlan + ipv4 + udp (46), leaving 14 of payload.
        let spec = TrafgenSpec { frame_bytes: 60, vlan: Some(100), ..Default::default() };
        let cfg = config_build(&spec, "02:00:00:00:00:01", "02:00:00:00:00:02").unwrap();
        assert!(cfg.contains("fill(0x00, 14)"), "{cfg}");
    }

    #[test]
    fn frame_below_the_ethernet_minimum_refused() {
        let spec = TrafgenSpec { frame_bytes: 40, ..Default::default() };
        assert!(spec.validate().unwrap_err().to_string().contains("out of range 60"));
    }

    #[test]
    fn out_of_range_refused() {
        assert!(TrafgenSpec { cpus: 0, ..Default::default() }.validate().is_err());
        assert!(TrafgenSpec { cpus: 65, ..Default::default() }.validate().is_err());
        assert!(TrafgenSpec { src_mac_count: 0, ..Default::default() }.validate().is_err());
        assert!(TrafgenSpec { src_mac_count: 257, ..Default::default() }.validate().is_err());
        assert!(TrafgenSpec { vlan: Some(4095), ..Default::default() }.validate().is_err());
    }

    #[test]
    fn argv_raises_the_ring_and_skips_sysctl_tuning() {
        // A 0.5 MiB ring fails outright on i40e, and an undrained pipe deadlocks
        // the process once trafgen fills it.
        let parts = trafgen_argv("eth0", Path::new("/tmp/x.cfg"), &TrafgenSpec::default());
        let after = |flag: &str| parts.iter().position(|p| p == flag).map(|i| parts[i + 1].clone());
        assert_eq!(after("--ring-size").unwrap(), "4MiB");
        assert_eq!(after("--num").unwrap(), "0");
        assert!(parts.contains(&"--no-sock-mem".to_string()));
    }

    #[test]
    fn rate_is_passed_through_when_set() {
        let spec = TrafgenSpec { rate: Some("1Mpps".into()), ..Default::default() };
        let parts = trafgen_argv("eth0", Path::new("/tmp/x.cfg"), &spec);
        let index = parts.iter().position(|p| p == "--rate").unwrap();
        assert_eq!(parts[index + 1], "1Mpps");
    }

    #[test]
    fn summary_uses_measured_bytes_not_the_requested_frame_size() {
        // A run contaminated by other traffic must not have its rate inferred
        // from frame_bytes; that reported 34 Gbps on a 10G link once.
        let tx = std::collections::BTreeMap::from([
            ("tx_packets".to_string(), 14_000_000i64),
            ("tx_bytes".to_string(), 896_000_000),
        ]);
        let rx = std::collections::BTreeMap::from([
            ("rx_packets".to_string(), 13_800_000i64),
            ("rx_bytes".to_string(), 883_200_000),
            ("rx_missed_errors".to_string(), 42),
        ]);
        let out = summary_build(&TrafgenSpec::default(), 5.0, &tx, &rx);
        assert_eq!(out["tx_mpps"], 2.8);
        assert_eq!(out["rx_mpps"], 2.76);
        assert_eq!(out["mean_tx_frame_bytes"], 64.0);
        assert_eq!(out["tx_gbps"], 1.434);
        assert_eq!(out["loss_packets"], 200_000);
        assert_eq!(out["rx_missed_errors"], 42);
    }

    #[test]
    fn summary_is_quiet_when_nothing_was_sent() {
        let empty = std::collections::BTreeMap::new();
        let out = summary_build(&TrafgenSpec::default(), 5.0, &empty, &empty);
        assert_eq!(out["packets_sent"], 0);
        assert!(out.get("loss_percent").is_none());
        assert_eq!(out["mean_tx_frame_bytes"], Value::Null);
    }
}
