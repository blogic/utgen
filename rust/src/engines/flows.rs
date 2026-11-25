// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::probe::{helper_spawn, json_tail, ready_wait, stdin_write, ProbeError};

pub const DEFAULT_TCP_PORT: u16 = 25501;
pub const DEFAULT_UDP_PORT: u16 = 25502;
const REAP_GRACE: Duration = Duration::from_secs(30);
const MAX_FLOWS: u64 = 200_000;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct FlowsError(pub String);

impl From<ProbeError> for FlowsError {
    fn from(err: ProbeError) -> Self {
        Self(err.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FlowsSpec {
    #[serde(default = "thousand")]
    pub count: u64,
    #[serde(default = "proto_tcp")]
    pub proto: String,
    #[serde(default = "thirty")]
    pub duration_s: u32,
    /// Paces how fast flows are opened; 0 means as fast as possible.
    #[serde(default)]
    pub open_rate_per_s: f64,
    #[serde(default)]
    pub churn: bool,
    #[serde(default = "one_second")]
    pub flow_lifetime_s: f64,
    #[serde(default = "ten_seconds")]
    pub connect_timeout_s: f64,
    /// Spreads flows over several source addresses, which must already be on
    /// the endpoint.
    #[serde(default)]
    pub source_ips: Vec<String>,
    #[serde(default = "default_tcp_port")]
    pub tcp_port: u16,
    #[serde(default = "default_udp_port")]
    pub udp_port: u16,
}

fn thousand() -> u64 {
    1000
}
fn proto_tcp() -> String {
    "tcp".into()
}
fn thirty() -> u32 {
    30
}
fn one_second() -> f64 {
    1.0
}
fn ten_seconds() -> f64 {
    10.0
}
fn default_tcp_port() -> u16 {
    DEFAULT_TCP_PORT
}
fn default_udp_port() -> u16 {
    DEFAULT_UDP_PORT
}

impl Default for FlowsSpec {
    fn default() -> Self {
        Self {
            count: thousand(),
            proto: proto_tcp(),
            duration_s: thirty(),
            open_rate_per_s: 0.0,
            churn: false,
            flow_lifetime_s: one_second(),
            connect_timeout_s: ten_seconds(),
            source_ips: Vec::new(),
            tcp_port: DEFAULT_TCP_PORT,
            udp_port: DEFAULT_UDP_PORT,
        }
    }
}

impl FlowsSpec {
    pub fn validate(&self) -> Result<(), FlowsError> {
        if !matches!(self.proto.as_str(), "tcp" | "udp") {
            return Err(FlowsError(format!(
                "proto must be 'tcp' or 'udp', got {:?}",
                self.proto
            )));
        }
        if !(1..=MAX_FLOWS).contains(&self.count) {
            return Err(FlowsError(format!(
                "count {} out of range 1..{MAX_FLOWS}",
                self.count
            )));
        }
        if !(1..=86400).contains(&self.duration_s) {
            return Err(FlowsError(format!(
                "duration_s {} out of range 1..86400",
                self.duration_s
            )));
        }
        if self.open_rate_per_s < 0.0 {
            return Err(FlowsError("open_rate_per_s cannot be negative".into()));
        }
        if self.churn && self.proto != "tcp" {
            return Err(FlowsError(
                "churn applies to tcp only; a udp flow has no close to churn".into(),
            ));
        }
        if !(0.05..=3600.0).contains(&self.flow_lifetime_s) {
            return Err(FlowsError(format!(
                "flow_lifetime_s {} out of range 0.05..3600",
                self.flow_lifetime_s
            )));
        }
        Ok(())
    }
}

/// Fill a device's flow table, then report what the two ends each counted.
pub async fn flows_run(
    src_ns: &str,
    dst_ns: &str,
    dst_ip: &str,
    bind_ip: &str,
    spec: &FlowsSpec,
) -> Result<Value, FlowsError> {
    spec.validate()?;

    let mut sink = helper_spawn(dst_ns, "flow-sink")?;
    let sink_spec = json!({
        "bind": bind_ip,
        "tcp_port": spec.tcp_port,
        "udp_port": spec.udp_port,
        "expect_flows": spec.count,
    });
    stdin_write(&mut sink, &sink_spec).await?;
    let ready = match ready_wait(&mut sink).await {
        Ok(ready) => ready,
        Err(err) => {
            let _ = sink.kill().await;
            return Err(err.into());
        }
    };

    let mut source = helper_spawn(src_ns, "flow-source")?;
    let source_spec = json!({
        "dst_ip": dst_ip,
        "tcp_port": spec.tcp_port,
        "udp_port": spec.udp_port,
        "count": spec.count,
        "proto": spec.proto,
        "duration_s": spec.duration_s,
        "open_rate_per_s": spec.open_rate_per_s,
        "churn": spec.churn,
        "flow_lifetime_s": spec.flow_lifetime_s,
        "connect_timeout_s": spec.connect_timeout_s,
        "source_ips": spec.source_ips,
    });
    stdin_write(&mut source, &source_spec).await?;

    let source_output = match tokio::time::timeout(
        Duration::from_secs(spec.duration_s as u64) + REAP_GRACE,
        source.wait_with_output(),
    )
    .await
    {
        Ok(Ok(output)) => output,
        other => {
            let _ = sink.kill().await;
            return Err(FlowsError(match other {
                Err(_) => "flow source did not finish in time".to_string(),
                Ok(Err(err)) => format!("flow source failed: {err}"),
                Ok(Ok(_)) => unreachable!(),
            }));
        }
    };

    // SIGTERM rather than kill, so the sink prints its totals before exiting.
    terminate(&mut sink).await;
    let sink_output = tokio::time::timeout(Duration::from_secs(5), sink.wait_with_output())
        .await
        .ok()
        .and_then(|result| result.ok());

    let source_stats = json_tail(&String::from_utf8_lossy(&source_output.stdout)).ok_or_else(|| {
        FlowsError(format!(
            "flow source produced no result: {}",
            String::from_utf8_lossy(&source_output.stderr).trim()
        ))
    })?;
    let sink_stats = sink_output
        .as_ref()
        .and_then(|out| json_tail(&String::from_utf8_lossy(&out.stdout)));

    Ok(merge(&source_stats, sink_stats.as_ref(), spec, ready["fd_limit"].clone()))
}

pub fn merge(
    source_stats: &Value,
    sink_stats: Option<&Value>,
    spec: &FlowsSpec,
    sink_fd_limit: Value,
) -> Value {
    let mut out = source_stats.clone();
    let map = out.as_object_mut().expect("source stats are an object");
    map.insert("fd_limit_sink".into(), sink_fd_limit);

    if let Some(sink) = sink_stats {
        map.insert("sink".into(), sink.clone());
        // The gap between the two is what the device dropped or never forwarded.
        let accepted = if spec.proto == "tcp" {
            sink["tcp_accepted"].as_u64()
        } else {
            sink["udp_flows"].as_u64()
        };
        let opened = source_stats["opened"].as_u64().unwrap_or(0);
        if let Some(accepted) = accepted {
            if opened > 0 {
                map.insert("reached_sink".into(), accepted.into());
                map.insert("not_reached".into(), opened.saturating_sub(accepted).into());
            }
        }
    }
    out
}

async fn terminate(child: &mut tokio::process::Child) {
    if let Some(pid) = child.id() {
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn churn_is_tcp_only() {
        let spec = FlowsSpec { churn: true, proto: "udp".into(), ..Default::default() };
        assert!(spec.validate().unwrap_err().to_string().contains("churn applies to tcp only"));
    }

    #[test]
    fn a_zero_lifetime_is_refused() {
        // Closing each flow at once means they never overlap, so concurrency
        // stays at one and the flow table never fills.
        let spec = FlowsSpec { churn: true, flow_lifetime_s: 0.0, ..Default::default() };
        assert!(spec.validate().unwrap_err().to_string().contains("flow_lifetime_s"));
    }

    #[test]
    fn out_of_range_refused() {
        assert!(FlowsSpec { count: 0, ..Default::default() }.validate().is_err());
        assert!(FlowsSpec { count: MAX_FLOWS + 1, ..Default::default() }.validate().is_err());
        assert!(FlowsSpec { proto: "sctp".into(), ..Default::default() }.validate().is_err());
        assert!(FlowsSpec { open_rate_per_s: -1.0, ..Default::default() }.validate().is_err());
        assert!(FlowsSpec::default().validate().is_ok());
    }

    #[test]
    fn merge_reports_the_shortfall_between_the_two_ends() {
        let source = json!({"opened": 10000, "failed": 0, "concurrent_peak": 10000});
        let sink = json!({"tcp_accepted": 9800, "tcp_concurrent_peak": 9800});
        let out = merge(&source, Some(&sink), &FlowsSpec::default(), json!(14096));
        assert_eq!(out["reached_sink"], 9800);
        assert_eq!(out["not_reached"], 200);
        assert_eq!(out["sink"]["tcp_concurrent_peak"], 9800);
        assert_eq!(out["fd_limit_sink"], 14096);
    }

    #[test]
    fn merge_uses_udp_flows_for_udp() {
        let source = json!({"opened": 20000});
        let sink = json!({"udp_flows": 20000, "tcp_accepted": 0});
        let spec = FlowsSpec { proto: "udp".into(), ..Default::default() };
        let out = merge(&source, Some(&sink), &spec, Value::Null);
        assert_eq!(out["reached_sink"], 20000);
        assert_eq!(out["not_reached"], 0);
    }

    #[test]
    fn merge_survives_a_sink_that_said_nothing() {
        let out = merge(&json!({"opened": 5}), None, &FlowsSpec::default(), Value::Null);
        assert!(out.get("sink").is_none());
        assert!(out.get("not_reached").is_none());
        assert_eq!(out["opened"], 5);
    }
}
