// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use rand::RngExt;
use serde_json::{json, Value};
use tokio::process::{Child, Command};

use crate::argv;
use crate::leases::now_s;
use crate::netns::ns_exec_argv;
use crate::shell::{command_run, DEFAULT_TIMEOUT};

pub const TCPDUMP: &str = "/usr/bin/tcpdump";
pub const DEFAULT_SNAPLEN: u32 = 262_144;
const MAX_SECONDS: u32 = 3600;
const MAX_PACKETS: u64 = 10_000_000;
const START_TIMEOUT: Duration = Duration::from_secs(5);
const STOP_GRACE: Duration = Duration::from_secs(3);

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct CaptureError(pub String);

#[derive(Debug, Clone)]
pub struct CaptureSpec {
    pub bpf: String,
    pub seconds: Option<u32>,
    pub max_packets: Option<u64>,
    pub snaplen: u32,
}

impl Default for CaptureSpec {
    fn default() -> Self {
        Self { bpf: String::new(), seconds: None, max_packets: None, snaplen: DEFAULT_SNAPLEN }
    }
}

impl CaptureSpec {
    pub fn validate(&self) -> Result<(), CaptureError> {
        if let Some(seconds) = self.seconds {
            if !(1..=MAX_SECONDS).contains(&seconds) {
                return Err(CaptureError(format!("seconds {seconds} out of range 1..{MAX_SECONDS}")));
            }
        }
        if let Some(max) = self.max_packets {
            if !(1..=MAX_PACKETS).contains(&max) {
                return Err(CaptureError(format!("max_packets {max} out of range 1..{MAX_PACKETS}")));
            }
        }
        if !(64..=DEFAULT_SNAPLEN).contains(&self.snaplen) {
            return Err(CaptureError(format!("snaplen {} out of range 64..{DEFAULT_SNAPLEN}", self.snaplen)));
        }
        // tcpdump takes its filter as trailing argv, so one starting with a dash
        // would be read as an option.
        if self.bpf.starts_with('-') {
            return Err(CaptureError(format!("bpf filter may not start with '-': {:?}", self.bpf)));
        }
        if let Some(bad) = self.bpf.chars().find(|c| !bpf_char_allowed(*c)) {
            return Err(CaptureError(format!(
                "bpf filter has a character tcpdump will not accept: {bad:?}"
            )));
        }
        Ok(())
    }
}

fn bpf_char_allowed(c: char) -> bool {
    c.is_ascii_alphanumeric() || " ()[]:.,/*&|!<>=_+-".contains(c)
}

pub fn capture_argv(dev: &str, pcap: &Path, spec: &CaptureSpec) -> Vec<String> {
    let mut parts = argv![
        TCPDUMP,
        "-i", dev,
        "-w", pcap.display(),
        "-s", spec.snaplen,
        // -U flushes each packet, so the file is readable while running.
        "-U",
        // tcpdump drops to the 'tcpdump' user on Debian and then cannot write
        // into our state directory.
        "-Z", "root",
        "-n",
    ];
    if let Some(seconds) = spec.seconds {
        parts.extend(argv!["-G", seconds, "-W", "1"]);
    }
    if let Some(max) = spec.max_packets {
        parts.extend(argv!["-c", max]);
    }
    if !spec.bpf.is_empty() {
        parts.push(spec.bpf.clone());
    }
    parts
}

pub struct Capture {
    pub capture_id: String,
    pub port: String,
    pub ns: String,
    pub dev: String,
    pub spec: CaptureSpec,
    pub pcap: PathBuf,
    pub started_at: f64,
    pub stopped_at: Option<f64>,
    child: Option<Child>,
}

impl Capture {
    pub fn new(port: &str, ns: &str, dev: &str, spec: CaptureSpec, directory: &Path) -> Result<Self, CaptureError> {
        spec.validate()?;
        std::fs::create_dir_all(directory)
            .map_err(|e| CaptureError(format!("cannot create {}: {e}", directory.display())))?;
        let capture_id = id_new();
        Ok(Self {
            pcap: directory.join(format!("{capture_id}.pcap")),
            capture_id,
            port: port.to_string(),
            ns: ns.to_string(),
            dev: dev.to_string(),
            spec,
            started_at: now_s(),
            stopped_at: None,
            child: None,
        })
    }

    pub fn running(&mut self) -> bool {
        match self.child.as_mut() {
            None => false,
            Some(child) => matches!(child.try_wait(), Ok(None)),
        }
    }

    pub async fn start(&mut self) -> Result<(), CaptureError> {
        let parts = ns_exec_argv(Some(&self.ns), &capture_argv(&self.dev, &self.pcap, &self.spec));
        tracing::info!(capture = %self.capture_id, command = %parts.join(" "), "capture");
        let (program, rest) = parts.split_first().expect("argv is never empty");
        let child = Command::new(program)
            .args(rest)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .spawn()
            .map_err(|e| CaptureError(format!("cannot start tcpdump: {e}")))?;
        self.child = Some(child);
        self.listening_wait().await
    }

    /// Wait until tcpdump has created the file, so no traffic is missed.
    async fn listening_wait(&mut self) -> Result<(), CaptureError> {
        let deadline = tokio::time::Instant::now() + START_TIMEOUT;
        while tokio::time::Instant::now() < deadline {
            if self.pcap.metadata().map(|m| m.len() > 0).unwrap_or(false) {
                return Ok(());
            }
            if let Some(child) = self.child.as_mut() {
                if let Ok(Some(_)) = child.try_wait() {
                    let stderr = self.stderr_read().await;
                    return Err(CaptureError(format!(
                        "tcpdump exited before capturing: {}",
                        stderr.trim()
                    )));
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(CaptureError(format!(
            "tcpdump did not start capturing on {} within {START_TIMEOUT:?}",
            self.dev
        )))
    }

    pub async fn stop(&mut self) -> Value {
        if let Some(child) = self.child.as_mut() {
            if matches!(child.try_wait(), Ok(None)) {
                let _ = child.start_kill();
                let _ = tokio::time::timeout(STOP_GRACE, child.wait()).await;
            }
        }
        self.stopped_at = Some(now_s());
        self.state().await
    }

    /// Stop without awaiting, for teardown paths that cannot be async.
    ///
    /// A tcpdump still running inside a namespace about to be deleted would
    /// otherwise be killed by the kernel with its pcap half written.
    pub fn kill(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
        self.stopped_at = Some(now_s());
    }

    async fn stderr_read(&mut self) -> String {
        let Some(child) = self.child.as_mut() else {
            return String::new();
        };
        let Some(stderr) = child.stderr.take() else {
            return String::new();
        };
        let mut text = String::new();
        let mut reader = tokio::io::BufReader::new(stderr);
        let _ = tokio::io::AsyncReadExt::read_to_string(&mut reader, &mut text).await;
        text
    }

    pub async fn packets_count(&self) -> u64 {
        if !self.pcap.exists() {
            return 0;
        }
        let out = command_run(
            &argv![TCPDUMP, "-r", self.pcap.display(), "-nn", "--count"],
            DEFAULT_TIMEOUT,
            None,
        )
        .await;
        out.text()
            .split_whitespace()
            .find_map(|word| word.parse::<u64>().ok())
            .unwrap_or(0)
    }

    /// Human-readable packet lines, read back from the pcap.
    pub async fn decode(&self, limit: usize, verbose: bool) -> Vec<String> {
        if !self.pcap.exists() {
            return Vec::new();
        }
        let mut parts = argv![TCPDUMP, "-r", self.pcap.display(), "-nn", "-e", "-c", limit];
        if verbose {
            parts.push("-v".into());
        }
        let out = command_run(&parts, Duration::from_secs(120), None).await;
        out.stdout
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.starts_with("reading from file"))
            .map(str::to_string)
            .collect()
    }

    pub async fn state(&mut self) -> Value {
        let running = self.running();
        json!({
            "capture_id": self.capture_id,
            "port": self.port,
            "netns": self.ns,
            "dev": self.dev,
            "bpf": if self.spec.bpf.is_empty() { "(none)".to_string() } else { self.spec.bpf.clone() },
            "running": running,
            "pcap": self.pcap.display().to_string(),
            "pcap_bytes": self.pcap.metadata().map(|m| m.len()).unwrap_or(0),
            "packets": self.packets_count().await,
            "duration_s": ((self.stopped_at.unwrap_or_else(now_s) - self.started_at) * 100.0).round() / 100.0,
        })
    }
}

fn id_new() -> String {
    // Eight random bytes, not two: a narrow suffix collides inside one second
    // by the birthday paradox, and a collision would evict a live entry from
    // the registry keyed on this id.
    let suffix: [u8; 8] = rand::rng().random();
    let hex: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    format!("cap-{}-{hex}", now_s() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_filter_starting_with_a_dash_is_refused() {
        let spec = CaptureSpec { bpf: "-w /etc/shadow".into(), ..Default::default() };
        assert!(spec.validate().unwrap_err().to_string().contains("may not start with"));
    }

    #[test]
    fn shell_metacharacters_are_refused() {
        for bad in ["udp; rm -rf /", "udp `id`", "udp $(id)", "udp'x"] {
            let spec = CaptureSpec { bpf: bad.into(), ..Default::default() };
            assert!(spec.validate().is_err(), "{bad} was accepted");
        }
    }

    #[test]
    fn real_filters_are_accepted() {
        for good in [
            "udp port 9999",
            "ether proto 0x8808",
            "ip and ip[1]>>2 == 46",
            "vlan",
            "icmp6",
            "tcp port 9997 and not host 10.0.0.1",
            "",
        ] {
            let spec = CaptureSpec { bpf: good.into(), ..Default::default() };
            assert!(spec.validate().is_ok(), "{good} was refused");
        }
    }

    #[test]
    fn out_of_range_refused() {
        assert!(CaptureSpec { seconds: Some(0), ..Default::default() }.validate().is_err());
        assert!(CaptureSpec { max_packets: Some(0), ..Default::default() }.validate().is_err());
        assert!(CaptureSpec { snaplen: 10, ..Default::default() }.validate().is_err());
        assert!(CaptureSpec::default().validate().is_ok());
    }

    #[test]
    fn argv_keeps_tcpdump_as_root_and_flushes_each_packet() {
        // -Z root because it otherwise drops privileges and cannot write the
        // pcap; -U so the file is readable while the capture runs.
        let spec = CaptureSpec { bpf: "udp port 9999".into(), max_packets: Some(50), ..Default::default() };
        let parts = capture_argv("enp1s0f1np1", Path::new("/tmp/x.pcap"), &spec);
        assert!(parts.contains(&"-U".to_string()));
        let z = parts.iter().position(|p| p == "-Z").unwrap();
        assert_eq!(parts[z + 1], "root");
        let c = parts.iter().position(|p| p == "-c").unwrap();
        assert_eq!(parts[c + 1], "50");
        assert_eq!(parts.last().unwrap(), "udp port 9999", "filter is trailing argv");
    }

    #[test]
    fn an_empty_filter_is_not_passed_as_an_argument() {
        let parts = capture_argv("eth0", Path::new("/tmp/x.pcap"), &CaptureSpec::default());
        assert_eq!(parts.last().unwrap(), "-n");
    }

    #[test]
    fn ids_are_distinct() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            assert!(seen.insert(id_new()));
        }
    }
}
