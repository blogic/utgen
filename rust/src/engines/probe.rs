// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

use crate::argv;
use crate::netns::ns_exec_argv;

pub const DEFAULT_PORT: u16 = 25301;
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const REAP_GRACE: Duration = Duration::from_secs(15);
const MIN_PACKET: u32 = 16;
const MAX_PACKET: u32 = 9000;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ProbeError(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProbeSpec {
    #[serde(default = "ten")]
    pub duration_s: u32,
    #[serde(default = "thousand")]
    pub rate_pps: f64,
    #[serde(default = "two_hundred")]
    pub packet_size: u32,
    #[serde(default)]
    pub dscp: Option<u8>,
    #[serde(default = "default_port")]
    pub port: u16,
}

fn ten() -> u32 {
    10
}
fn thousand() -> f64 {
    1000.0
}
fn two_hundred() -> u32 {
    200
}
fn default_port() -> u16 {
    DEFAULT_PORT
}

impl Default for ProbeSpec {
    fn default() -> Self {
        Self {
            duration_s: ten(),
            rate_pps: thousand(),
            packet_size: two_hundred(),
            dscp: None,
            port: DEFAULT_PORT,
        }
    }
}

impl ProbeSpec {
    pub fn validate(&self) -> Result<(), ProbeError> {
        if !(1..=86400).contains(&self.duration_s) {
            return Err(ProbeError(format!(
                "duration_s {} out of range 1..86400",
                self.duration_s
            )));
        }
        if !(1.0..=500_000.0).contains(&self.rate_pps) {
            return Err(ProbeError(format!(
                "rate_pps {} out of range 1..500000",
                self.rate_pps
            )));
        }
        if !(MIN_PACKET..=MAX_PACKET).contains(&self.packet_size) {
            return Err(ProbeError(format!(
                "packet_size {} out of range {MIN_PACKET}..{MAX_PACKET}",
                self.packet_size
            )));
        }
        if let Some(dscp) = self.dscp {
            if dscp > 63 {
                return Err(ProbeError(format!("dscp {dscp} out of range 0..63")));
            }
        }
        Ok(())
    }
}

/// Run one probe and return loss, reordering and one-way delay.
///
/// The receiver is started first and announces itself before the sender begins,
/// so the opening packets are not counted as loss.
pub async fn probe_run(
    src_ns: &str,
    dst_ns: &str,
    dst_ip: &str,
    bind_ip: &str,
    spec: &ProbeSpec,
) -> Result<Value, ProbeError> {
    spec.validate()?;

    let mut receiver = helper_spawn(dst_ns, "probe-rx")?;
    let rx_spec = json!({
        "bind": bind_ip,
        "port": spec.port,
        // Outlives the sender, so a late packet is still counted.
        "duration_s": spec.duration_s + 2,
    });
    stdin_write(&mut receiver, &rx_spec).await?;
    if let Err(err) = ready_wait(&mut receiver).await {
        let _ = receiver.kill().await;
        return Err(err);
    }

    let mut sender = helper_spawn(src_ns, "probe-tx")?;
    let tx_spec = json!({
        "dst_ip": dst_ip,
        "port": spec.port,
        "duration_s": spec.duration_s,
        "rate_pps": spec.rate_pps,
        "packet_size": spec.packet_size,
        "dscp": spec.dscp,
    });
    stdin_write(&mut sender, &tx_spec).await?;

    let tx_output = tokio::time::timeout(
        Duration::from_secs(spec.duration_s as u64) + REAP_GRACE,
        sender.wait_with_output(),
    )
    .await
    .map_err(|_| ProbeError("sender did not finish in time".into()))?
    .map_err(|e| ProbeError(format!("sender failed: {e}")))?;

    let rx_output = tokio::time::timeout(REAP_GRACE + Duration::from_secs(5), receiver.wait_with_output())
        .await
        .map_err(|_| ProbeError("receiver did not finish in time".into()))?
        .map_err(|e| ProbeError(format!("receiver failed: {e}")))?;

    let tx_stats = json_tail(&String::from_utf8_lossy(&tx_output.stdout)).ok_or_else(|| {
        ProbeError(format!(
            "sender produced no result: {}",
            String::from_utf8_lossy(&tx_output.stderr).trim()
        ))
    })?;
    let rx_stats = json_tail(&String::from_utf8_lossy(&rx_output.stdout)).ok_or_else(|| {
        ProbeError(format!(
            "receiver produced no result: {}",
            String::from_utf8_lossy(&rx_output.stderr).trim()
        ))
    })?;

    Ok(merge(&rx_stats, &tx_stats, spec))
}

pub fn merge(rx_stats: &Value, tx_stats: &Value, spec: &ProbeSpec) -> Value {
    let mut out = rx_stats.clone();
    let map = out.as_object_mut().expect("rx stats are an object");
    for (key, value) in tx_stats.as_object().into_iter().flatten() {
        map.insert(format!("tx_{key}"), value.clone());
    }
    map.insert("packet_size".into(), spec.packet_size.into());
    map.insert("rate_pps_requested".into(), spec.rate_pps.into());

    let sent = tx_stats["packets_sent"].as_u64().unwrap_or(0);
    let received = rx_stats["packets_received"].as_u64().unwrap_or(0);
    if sent > 0 {
        let lost = sent.saturating_sub(received);
        map.insert("loss_vs_sent".into(), lost.into());
        map.insert(
            "loss_vs_sent_percent".into(),
            (((100.0 * lost as f64 / sent as f64) * 10000.0).round() / 10000.0).into(),
        );
    }
    out
}

/// Our own binary, resolved once.
///
/// Resolved at first use and cached, because /proc/self/exe reports
/// `<path> (deleted)` once the file has been replaced, which an in-place
/// package upgrade does. Spawning that literal path fails immediately and the
/// only symptom is "helper exited before binding".
pub fn own_binary() -> Result<PathBuf, ProbeError> {
    static CACHED: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    CACHED
        .get_or_init(|| {
            let path = std::env::current_exe().ok()?;
            let text = path.to_string_lossy();
            match text.strip_suffix(" (deleted)") {
                None => Some(path),
                Some(real) => {
                    tracing::warn!(
                        path = real,
                        "our binary was replaced while running; helpers will use the new one"
                    );
                    Some(PathBuf::from(real))
                }
            }
        })
        .clone()
        .ok_or_else(|| ProbeError("cannot locate our own binary".into()))
}

pub fn helper_spawn(ns: &str, subcommand: &str) -> Result<Child, ProbeError> {
    let exe = own_binary()?;
    let parts = ns_exec_argv(Some(ns), &argv![exe.display(), subcommand]);
    let (program, rest) = parts.split_first().expect("argv is never empty");
    Command::new(program)
        .args(rest)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ProbeError(format!("cannot start {subcommand}: {e}")))
}

pub async fn stdin_write(child: &mut Child, spec: &Value) -> Result<(), ProbeError> {
    let mut pipe = child
        .stdin
        .take()
        .ok_or_else(|| ProbeError("helper has no stdin".into()))?;
    pipe.write_all(spec.to_string().as_bytes())
        .await
        .map_err(|e| ProbeError(format!("cannot write spec: {e}")))?;
    pipe.shutdown()
        .await
        .map_err(|e| ProbeError(format!("cannot close spec: {e}")))
}

pub async fn ready_wait(child: &mut Child) -> Result<Value, ProbeError> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ProbeError("helper has no stdout".into()))?;
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let read = tokio::time::timeout(READY_TIMEOUT, reader.read_line(&mut line))
        .await
        .map_err(|_| ProbeError(format!("helper did not become ready within {READY_TIMEOUT:?}")))?
        .map_err(|e| ProbeError(format!("cannot read readiness: {e}")))?;
    // The reader buffered part of the output, so it is handed back rather than
    // dropped; otherwise the final result line is lost.
    child.stdout = Some(reader.into_inner());
    if read == 0 {
        return Err(ProbeError("helper exited before binding".into()));
    }
    Ok(serde_json::from_str(line.trim()).unwrap_or(Value::Null))
}

/// The helpers print a readiness line before their result, so take the last object.
pub fn json_tail(text: &str) -> Option<Value> {
    text.trim()
        .lines()
        .rev()
        .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
        .find(|value| value.is_object() && value.get("ready").is_none())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_range_refused() {
        assert!(ProbeSpec { duration_s: 0, ..Default::default() }.validate().is_err());
        assert!(ProbeSpec { rate_pps: 0.0, ..Default::default() }.validate().is_err());
        assert!(ProbeSpec { rate_pps: 1e9, ..Default::default() }.validate().is_err());
        assert!(ProbeSpec { packet_size: 4, ..Default::default() }.validate().is_err());
        assert!(ProbeSpec { dscp: Some(64), ..Default::default() }.validate().is_err());
        assert!(ProbeSpec::default().validate().is_ok());
    }

    #[test]
    fn json_tail_skips_the_readiness_line() {
        let text = "{\"ready\": true}\n{\"packets_received\": 12000}\n";
        assert_eq!(json_tail(text).unwrap()["packets_received"], 12000);
    }

    #[test]
    fn json_tail_ignores_noise_and_returns_none_when_empty() {
        assert!(json_tail("not json at all").is_none());
        assert!(json_tail("").is_none());
        assert!(json_tail("{\"ready\": true}").is_none());
    }

    #[test]
    fn merge_prefixes_sender_fields_and_derives_loss() {
        let rx = json!({"packets_received": 11800, "lost": 0, "reordered": 2});
        let tx = json!({"packets_sent": 12000, "rate_pps_actual": 2000.0});
        let out = merge(&rx, &tx, &ProbeSpec::default());
        assert_eq!(out["packets_received"], 11800);
        assert_eq!(out["tx_packets_sent"], 12000);
        assert_eq!(out["tx_rate_pps_actual"], 2000.0);
        assert_eq!(out["loss_vs_sent"], 200);
        assert_eq!(out["loss_vs_sent_percent"], 1.6667);
        assert_eq!(out["reordered"], 2);
        assert_eq!(out["packet_size"], 200);
    }

    #[test]
    fn merge_omits_loss_when_nothing_was_sent() {
        let out = merge(&json!({"packets_received": 0}), &json!({}), &ProbeSpec::default());
        assert!(out.get("loss_vs_sent").is_none());
    }
}
