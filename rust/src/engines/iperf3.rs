// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::argv;
use crate::netns::ns_exec_argv;

pub const IPERF3: &str = "/usr/bin/iperf3";
pub const SS: &str = "/usr/bin/ss";

pub const DEFAULT_PORT: u16 = 25201;
const LISTEN_TIMEOUT: Duration = Duration::from_secs(5);
const LISTEN_POLL: Duration = Duration::from_millis(100);
const STOP_GRACE: Duration = Duration::from_secs(3);

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Iperf3Error(pub String);

fn rejected<T>(message: impl Into<String>) -> Result<T, Iperf3Error> {
    Err(Iperf3Error(message.into()))
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Iperf3Spec {
    #[serde(default = "proto_tcp")]
    pub proto: String,
    #[serde(default = "ten")]
    pub duration_s: u32,
    /// Required for udp: iperf3 otherwise defaults to 1 Mbit/s and the
    /// measurement is meaningless. Also paces tcp.
    #[serde(default)]
    pub bitrate: Option<String>,
    #[serde(default = "one")]
    pub streams: u32,
    #[serde(default)]
    pub packet_size: Option<u32>,
    #[serde(default)]
    pub reverse: bool,
    #[serde(default)]
    pub bidir: bool,
    #[serde(default)]
    pub omit_s: u32,
    #[serde(default = "one_f64")]
    pub interval_s: f64,
    #[serde(default)]
    pub congestion: Option<String>,
    #[serde(default)]
    pub mss: Option<u32>,
    #[serde(default)]
    pub dscp: Option<u8>,
    #[serde(default)]
    pub bind: Option<String>,
    #[serde(default = "default_port")]
    pub port: u16,
}

fn proto_tcp() -> String {
    "tcp".into()
}
fn ten() -> u32 {
    10
}
fn one() -> u32 {
    1
}
fn one_f64() -> f64 {
    1.0
}
fn default_port() -> u16 {
    DEFAULT_PORT
}

impl Default for Iperf3Spec {
    fn default() -> Self {
        Self {
            proto: proto_tcp(),
            duration_s: ten(),
            bitrate: None,
            streams: one(),
            packet_size: None,
            reverse: false,
            bidir: false,
            omit_s: 0,
            interval_s: one_f64(),
            congestion: None,
            mss: None,
            dscp: None,
            bind: None,
            port: DEFAULT_PORT,
        }
    }
}

impl Iperf3Spec {
    pub fn validate(&self) -> Result<(), Iperf3Error> {
        if !matches!(self.proto.as_str(), "tcp" | "udp") {
            return rejected(format!("proto must be 'tcp' or 'udp', got {:?}", self.proto));
        }
        if !(1..=86400).contains(&self.duration_s) {
            return rejected(format!("duration_s {} out of range 1..86400", self.duration_s));
        }
        if !(1..=128).contains(&self.streams) {
            return rejected(format!("streams {} out of range 1..128", self.streams));
        }
        if self.proto == "udp" && self.bitrate.as_deref().unwrap_or("").is_empty() {
            return rejected(
                "udp requires an explicit bitrate, for example '900M' or '0' for unlimited",
            );
        }
        if self.reverse && self.bidir {
            return rejected("reverse and bidir are mutually exclusive");
        }
        if self.congestion.is_some() && self.proto != "tcp" {
            return rejected("congestion applies to tcp only");
        }
        if let Some(mss) = self.mss {
            if self.proto != "tcp" {
                return rejected("mss applies to tcp only");
            }
            if !(88..=9000).contains(&mss) {
                return rejected(format!("mss {mss} out of range 88..9000"));
            }
        }
        if let Some(dscp) = self.dscp {
            if dscp > 63 {
                return rejected(format!("dscp {dscp} out of range 0..63"));
            }
        }
        Ok(())
    }
}

/// -1 makes the server exit after a single test, so a crashed client cannot
/// leave a listener holding the port.
pub fn server_argv(bind_ip: &str, port: u16) -> Vec<String> {
    argv![IPERF3, "-s", "-1", "-B", bind_ip, "-p", port, "--json-stream"]
}

pub fn client_argv(server_ip: &str, spec: &Iperf3Spec) -> Vec<String> {
    let mut parts = argv![
        IPERF3,
        "-c", server_ip,
        "-p", spec.port,
        "-t", spec.duration_s,
        "-i", spec.interval_s,
        "-P", spec.streams,
        "--json-stream",
    ];
    if spec.proto == "udp" {
        parts.push("-u".into());
    }
    if let Some(bitrate) = &spec.bitrate {
        parts.extend(argv!["-b", bitrate]);
    }
    if let Some(size) = spec.packet_size {
        parts.extend(argv!["-l", size]);
    }
    if spec.reverse {
        parts.push("-R".into());
    }
    if spec.bidir {
        parts.push("--bidir".into());
    }
    if spec.omit_s > 0 {
        parts.extend(argv!["-O", spec.omit_s]);
    }
    if let Some(algo) = &spec.congestion {
        parts.extend(argv!["-C", algo]);
    }
    if let Some(mss) = spec.mss {
        parts.extend(argv!["-M", mss]);
    }
    if let Some(dscp) = spec.dscp {
        parts.extend(argv!["--dscp", dscp]);
    }
    if let Some(bind) = &spec.bind {
        parts.extend(argv!["-B", bind]);
    }
    parts
}

/// What a poller sees while a flow is in flight.
#[derive(Default)]
pub struct Live {
    pub intervals: AtomicU64,
    pub last: Mutex<Option<Value>>,
}

impl Live {
    pub async fn snapshot(&self) -> Value {
        let last = self.last.lock().await.clone().unwrap_or(Value::Null);
        json!({
            "intervals": self.intervals.load(Ordering::Relaxed),
            "mbps": last["bits_per_second"].as_f64().map(|b| (b / 1e6 * 1000.0).round() / 1000.0),
            "bytes": last["bytes"],
            "retransmits": last["retransmits"],
            "jitter_ms": last["jitter_ms"],
            "lost_percent": last["lost_percent"],
        })
    }
}

/// One iperf3 measurement: a server in the sink namespace, a client in the source.
pub struct Iperf3Flow {
    pub src_ns: String,
    pub dst_ns: String,
    pub dst_ip: String,
    pub spec: Iperf3Spec,
}

impl Iperf3Flow {
    pub async fn run(
        self,
        samples_path: &Path,
        stderr_path: &Path,
        live: Arc<Live>,
        cancel: CancellationToken,
    ) -> Result<Value, Iperf3Error> {
        self.spec.validate()?;

        let mut server = spawn(&ns_exec_argv(
            Some(&self.dst_ns),
            &server_argv(&self.dst_ip, self.spec.port),
        ))?;
        let listen = self.listen_wait(&mut server).await;
        if let Err(err) = listen {
            let _ = kill(&mut server).await;
            return Err(err);
        }

        let client_argv = ns_exec_argv(Some(&self.src_ns), &client_argv(&self.dst_ip, &self.spec));
        tracing::info!(command = %client_argv.join(" "), "iperf3 client");
        let mut client = spawn(&client_argv)?;

        let outcome = self.pump(&mut client, samples_path, &live, &cancel).await;
        let stopped_early = cancel.is_cancelled();
        if stopped_early {
            let _ = kill(&mut client).await;
        }

        let status = client.wait().await.ok();
        let rc = status.and_then(|s| s.code()).unwrap_or(-1);
        let stderr = read_remaining(&mut client).await;
        if !stderr.is_empty() {
            let _ = tokio::fs::write(stderr_path, &stderr).await;
        }
        let _ = kill(&mut server).await;

        let end = outcome?;
        let Some(end) = end else {
            let detail = if stderr.trim().is_empty() {
                format!("iperf3 exited rc={rc} without an end record")
            } else {
                stderr.trim().to_string()
            };
            return Err(Iperf3Error(detail));
        };

        let mut summary = summary_parse(&end, &self.spec);
        summary["rc"] = rc.into();
        summary["intervals"] = live.intervals.load(Ordering::Relaxed).into();
        if stopped_early {
            summary["stopped_early"] = true.into();
        }
        Ok(summary)
    }

    /// Block until the server is listening, so the client does not race it.
    async fn listen_wait(&self, server: &mut Child) -> Result<(), Iperf3Error> {
        let pattern = format!("sport = :{}", self.spec.port);
        let deadline = tokio::time::Instant::now() + LISTEN_TIMEOUT;
        while tokio::time::Instant::now() < deadline {
            if let Ok(Some(_)) = server.try_wait() {
                let stderr = read_remaining(server).await;
                return Err(Iperf3Error(format!(
                    "iperf3 server exited before listening: {}",
                    stderr.trim()
                )));
            }
            let out = crate::shell::command_run(
                &ns_exec_argv(Some(&self.dst_ns), &argv![SS, "-H", "-ltn", &pattern]),
                Duration::from_secs(5),
                None,
            )
            .await;
            if !out.stdout.trim().is_empty() {
                return Ok(());
            }
            tokio::time::sleep(LISTEN_POLL).await;
        }
        Err(Iperf3Error(format!(
            "iperf3 server did not listen on {}:{} within {LISTEN_TIMEOUT:?}",
            self.dst_ip, self.spec.port
        )))
    }

    /// Stream the client's NDJSON to disk, tracking the latest interval.
    async fn pump(
        &self,
        client: &mut Child,
        samples_path: &Path,
        live: &Arc<Live>,
        cancel: &CancellationToken,
    ) -> Result<Option<Value>, Iperf3Error> {
        let stdout = client
            .stdout
            .take()
            .ok_or_else(|| Iperf3Error("iperf3 client has no stdout".into()))?;
        let mut sink = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(samples_path)
            .await
            .map_err(|e| Iperf3Error(format!("cannot write samples: {e}")))?;

        let mut lines = BufReader::new(stdout).lines();
        let mut end = None;
        loop {
            let next = tokio::select! {
                line = lines.next_line() => line,
                _ = cancel.cancelled() => break,
            };
            let Ok(Some(line)) = next else { break };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let _ = sink.write_all(format!("{trimmed}\n").as_bytes()).await;
            let _ = sink.flush().await;

            let Ok(record) = serde_json::from_str::<Value>(trimmed) else {
                continue;
            };
            match record["event"].as_str() {
                Some("interval") => {
                    live.intervals.fetch_add(1, Ordering::Relaxed);
                    *live.last.lock().await = Some(record["data"]["sum"].clone());
                }
                Some("end") => end = Some(record["data"].clone()),
                Some("error") => {
                    return Err(Iperf3Error(record["data"].to_string()));
                }
                _ => {}
            }
        }
        Ok(end)
    }
}

fn spawn(parts: &[String]) -> Result<Child, Iperf3Error> {
    let (program, rest) = parts
        .split_first()
        .ok_or_else(|| Iperf3Error("empty command".into()))?;
    Command::new(program)
        .args(rest)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| Iperf3Error(format!("cannot start {program}: {e}")))
}

async fn kill(child: &mut Child) -> std::io::Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    let _ = child.start_kill();
    let _ = tokio::time::timeout(STOP_GRACE, child.wait()).await;
    Ok(())
}

async fn read_remaining(child: &mut Child) -> String {
    let Some(stderr) = child.stderr.take() else {
        return String::new();
    };
    let mut text = String::new();
    let mut reader = BufReader::new(stderr);
    let _ = tokio::io::AsyncReadExt::read_to_string(&mut reader, &mut text).await;
    text
}

/// Reduce an iperf3 end record to a flat, engine-neutral summary.
pub fn summary_parse(end: &Value, spec: &Iperf3Spec) -> Value {
    let mut out = if spec.proto == "udp" {
        udp_summary(end)
    } else {
        tcp_summary(end)
    };
    let map = out.as_object_mut().expect("summary is an object");
    map.insert("proto".into(), spec.proto.clone().into());
    map.insert("streams".into(), spec.streams.into());
    map.insert(
        "duration_s".into(),
        ((seconds_of(end) * 100.0).round() / 100.0).into(),
    );
    out
}

fn tcp_summary(end: &Value) -> Value {
    let sent = &end["sum_sent"];
    let received = &end["sum_received"];
    let mut out = json!({
        "tx_mbps": mbps(&sent["bits_per_second"]),
        "rx_mbps": mbps(&received["bits_per_second"]),
        "tx_bytes": sent["bytes"],
        "rx_bytes": received["bytes"],
        "retransmits": sent["retransmits"],
    });

    let streams = end["streams"].as_array().cloned().unwrap_or_default();
    let map = out.as_object_mut().unwrap();
    for (field, value) in rtt_summary(&streams) {
        map.insert(field, value);
    }
    let per_stream: Vec<Value> = streams
        .iter()
        .filter_map(|s| s["sender"]["retransmits"].as_i64())
        .map(Value::from)
        .collect();
    if per_stream.len() > 1 {
        map.insert("retransmits_per_stream".into(), per_stream.into());
    }
    out
}

/// Per-stream RTT, in milliseconds.
///
/// A zero is treated as absent, not as a measurement: in reverse mode the local
/// end is the receiver and iperf3 reports its sender RTT fields as 0, which
/// would otherwise surface as a real 0.000 ms round trip.
fn rtt_summary(streams: &[Value]) -> Vec<(String, Value)> {
    let gather = |key: &str| -> Vec<f64> {
        streams
            .iter()
            .filter_map(|s| s["sender"][key].as_f64())
            .filter(|v| *v > 0.0)
            .collect()
    };
    let round3 = |v: f64| (v / 1000.0 * 1000.0).round() / 1000.0;

    let mut out = Vec::new();
    let mins = gather("min_rtt");
    if let Some(value) = mins.iter().cloned().fold(None, |acc: Option<f64>, v| {
        Some(acc.map_or(v, |a| a.min(v)))
    }) {
        out.push(("rtt_min_ms".to_string(), round3(value).into()));
    }
    let means = gather("mean_rtt");
    if !means.is_empty() {
        let mean = means.iter().sum::<f64>() / means.len() as f64;
        out.push(("rtt_mean_ms".to_string(), round3(mean).into()));
    }
    let maxs = gather("max_rtt");
    if let Some(value) = maxs.iter().cloned().fold(None, |acc: Option<f64>, v| {
        Some(acc.map_or(v, |a| a.max(v)))
    }) {
        out.push(("rtt_max_ms".to_string(), round3(value).into()));
    }
    out
}

fn udp_summary(end: &Value) -> Value {
    let total = &end["sum"];
    json!({
        "tx_mbps": mbps(&total["bits_per_second"]),
        "tx_bytes": total["bytes"],
        "packets": total["packets"],
        "lost_packets": total["lost_packets"],
        "loss_percent": round(&total["lost_percent"], 4),
        "jitter_ms": round(&total["jitter_ms"], 4),
    })
}

fn seconds_of(end: &Value) -> f64 {
    for key in ["sum_sent", "sum_received", "sum"] {
        if let Some(seconds) = end[key]["seconds"].as_f64() {
            return seconds;
        }
    }
    0.0
}

fn mbps(value: &Value) -> Value {
    match value.as_f64() {
        Some(bits) => (((bits / 1e6) * 1000.0).round() / 1000.0).into(),
        None => Value::Null,
    }
}

fn round(value: &Value, digits: u32) -> Value {
    let factor = 10f64.powi(digits as i32);
    match value.as_f64() {
        Some(number) => ((number * factor).round() / factor).into(),
        None => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_end() -> Value {
        json!({
            "streams": [{"sender": {"min_rtt": 948, "mean_rtt": 977, "max_rtt": 1026}}],
            "sum_sent": {"bits_per_second": 9410689056.9, "bytes": 9412673536u64, "retransmits": 418, "seconds": 8.001687},
            "sum_received": {"bits_per_second": 9408158595.7, "bytes": 9410314240u64, "seconds": 8.001833}
        })
    }

    #[test]
    fn udp_without_bitrate_refused() {
        let spec = Iperf3Spec { proto: "udp".into(), ..Default::default() };
        assert!(spec.validate().unwrap_err().to_string().contains("udp requires an explicit bitrate"));
    }

    #[test]
    fn udp_with_bitrate_accepted() {
        let spec = Iperf3Spec { proto: "udp".into(), bitrate: Some("900M".into()), ..Default::default() };
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn reverse_and_bidir_are_exclusive() {
        let spec = Iperf3Spec { reverse: true, bidir: true, ..Default::default() };
        assert!(spec.validate().unwrap_err().to_string().contains("mutually exclusive"));
    }

    #[test]
    fn out_of_range_refused() {
        assert!(Iperf3Spec { duration_s: 0, ..Default::default() }.validate().is_err());
        assert!(Iperf3Spec { streams: 0, ..Default::default() }.validate().is_err());
        assert!(Iperf3Spec { streams: 129, ..Default::default() }.validate().is_err());
        assert!(Iperf3Spec { dscp: Some(64), ..Default::default() }.validate().is_err());
        assert!(Iperf3Spec { mss: Some(10), ..Default::default() }.validate().is_err());
    }

    #[test]
    fn mss_and_congestion_are_tcp_only() {
        let udp = |extra: fn(&mut Iperf3Spec)| {
            let mut spec = Iperf3Spec { proto: "udp".into(), bitrate: Some("1M".into()), ..Default::default() };
            extra(&mut spec);
            spec.validate().unwrap_err().to_string()
        };
        assert!(udp(|s| s.mss = Some(1200)).contains("mss applies to tcp only"));
        assert!(udp(|s| s.congestion = Some("bbr".into())).contains("congestion applies to tcp only"));
    }

    #[test]
    fn server_argv_binds_and_exits_after_one_test() {
        let parts = server_argv("10.80.0.2", 25201);
        assert!(parts.contains(&"-1".to_string()));
        let bind = parts.iter().position(|p| p == "-B").unwrap();
        assert_eq!(parts[bind + 1], "10.80.0.2");
    }

    #[test]
    fn client_argv_carries_every_option() {
        let spec = Iperf3Spec {
            proto: "udp".into(), duration_s: 30, bitrate: Some("9G".into()), streams: 4,
            packet_size: Some(1400), reverse: true, omit_s: 2, port: 25300,
            dscp: Some(46), bind: Some("10.80.0.1".into()), ..Default::default()
        };
        let parts = client_argv("10.80.0.2", &spec);
        let after = |flag: &str| {
            parts.iter().position(|p| p == flag).map(|i| parts[i + 1].clone())
        };
        assert_eq!(after("-c").unwrap(), "10.80.0.2");
        assert_eq!(after("-t").unwrap(), "30");
        assert_eq!(after("-b").unwrap(), "9G");
        assert_eq!(after("-P").unwrap(), "4");
        assert_eq!(after("-l").unwrap(), "1400");
        assert_eq!(after("-O").unwrap(), "2");
        assert_eq!(after("-p").unwrap(), "25300");
        assert_eq!(after("--dscp").unwrap(), "46");
        assert_eq!(after("-B").unwrap(), "10.80.0.1");
        assert!(parts.contains(&"-u".to_string()));
        assert!(parts.contains(&"-R".to_string()));
        assert!(parts.contains(&"--json-stream".to_string()));
    }

    #[test]
    fn bidir_emits_its_own_flag_not_reverse() {
        let parts = client_argv("10.0.0.1", &Iperf3Spec { bidir: true, ..Default::default() });
        assert!(parts.contains(&"--bidir".to_string()));
        assert!(!parts.contains(&"-R".to_string()));
    }

    #[test]
    fn tcp_summary_values() {
        let out = summary_parse(&tcp_end(), &Iperf3Spec::default());
        assert_eq!(out["tx_mbps"], 9410.689);
        assert_eq!(out["rx_mbps"], 9408.159);
        assert_eq!(out["retransmits"], 418);
        assert_eq!(out["rtt_min_ms"], 0.948);
        assert_eq!(out["rtt_mean_ms"], 0.977);
        assert_eq!(out["rtt_max_ms"], 1.026);
        assert_eq!(out["duration_s"], 8.0);
    }

    #[test]
    fn udp_summary_values() {
        let end = json!({"sum": {
            "bits_per_second": 499949000.0, "bytes": 187594800u64, "packets": 156329,
            "lost_packets": 12, "lost_percent": 0.00768, "jitter_ms": 0.0011, "seconds": 3.0
        }});
        let spec = Iperf3Spec { proto: "udp".into(), bitrate: Some("500M".into()), ..Default::default() };
        let out = summary_parse(&end, &spec);
        assert_eq!(out["tx_mbps"], 499.949);
        assert_eq!(out["packets"], 156329);
        assert_eq!(out["lost_packets"], 12);
        assert_eq!(out["loss_percent"], 0.0077);
        assert_eq!(out["jitter_ms"], 0.0011);
    }

    #[test]
    fn zero_rtt_is_omitted_not_reported_as_zero() {
        let end = json!({
            "streams": [{"sender": {"min_rtt": 0, "mean_rtt": 0, "max_rtt": 0}}],
            "sum_sent": {"bits_per_second": 9391319000.0, "seconds": 6.0},
            "sum_received": {"bits_per_second": 9386136000.0, "seconds": 6.0}
        });
        let spec = Iperf3Spec { reverse: true, ..Default::default() };
        let out = summary_parse(&end, &spec);
        assert!(out.get("rtt_mean_ms").is_none());
        assert_eq!(out["tx_mbps"], 9391.319);
    }

    #[test]
    fn rtt_averaged_across_streams() {
        let end = json!({
            "streams": [
                {"sender": {"min_rtt": 900, "mean_rtt": 1000, "max_rtt": 1100, "retransmits": 56}},
                {"sender": {"min_rtt": 800, "mean_rtt": 1200, "max_rtt": 1500, "retransmits": 319}}
            ],
            "sum_sent": {"bits_per_second": 1e9, "seconds": 1.0},
            "sum_received": {"bits_per_second": 1e9, "seconds": 1.0}
        });
        let out = summary_parse(&end, &Iperf3Spec { streams: 2, ..Default::default() });
        assert_eq!(out["rtt_min_ms"], 0.8);
        assert_eq!(out["rtt_mean_ms"], 1.1);
        assert_eq!(out["rtt_max_ms"], 1.5);
        assert_eq!(out["retransmits_per_stream"], json!([56, 319]));
    }

    #[test]
    fn summary_survives_a_truncated_end_record() {
        let out = summary_parse(&json!({}), &Iperf3Spec::default());
        assert_eq!(out["tx_mbps"], Value::Null);
        assert_eq!(out["duration_s"], 0.0);
    }
}
