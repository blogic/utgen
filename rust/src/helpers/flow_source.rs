// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpSocket, UdpSocket};
use tokio::sync::Mutex;

use super::{emit, fd_limit_raise, spec_read};

const KEEPALIVE: &[u8] = b"tgen-flow";

#[derive(Debug, Deserialize)]
pub struct SourceSpec {
    pub dst_ip: String,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub count: u64,
    #[serde(default = "proto_tcp")]
    pub proto: String,
    pub duration_s: f64,
    #[serde(default)]
    pub open_rate_per_s: f64,
    #[serde(default)]
    pub churn: bool,
    #[serde(default = "one_second")]
    pub flow_lifetime_s: f64,
    #[serde(default = "ten_seconds")]
    pub connect_timeout_s: f64,
    #[serde(default)]
    pub source_ips: Vec<String>,
}

fn proto_tcp() -> String {
    "tcp".into()
}
fn one_second() -> f64 {
    1.0
}
fn ten_seconds() -> f64 {
    10.0
}

#[derive(Default)]
pub struct Tally {
    pub opened: AtomicU64,
    pub failed: AtomicU64,
    pub closed: AtomicU64,
    pub concurrent: AtomicU64,
    pub peak: AtomicU64,
    pub last_open_ms: AtomicU64,
    pub failures: Mutex<BTreeMap<String, u64>>,
}

impl Tally {
    fn opened_at(&self, since_start_ms: u64) {
        self.opened.fetch_add(1, Ordering::Relaxed);
        self.last_open_ms.fetch_max(since_start_ms, Ordering::Relaxed);
        let now = self.concurrent.fetch_add(1, Ordering::Relaxed) + 1;
        self.peak.fetch_max(now, Ordering::Relaxed);
    }

    fn closed(&self) {
        self.concurrent.fetch_sub(1, Ordering::Relaxed);
        self.closed.fetch_add(1, Ordering::Relaxed);
    }

    async fn failure(&self, kind: &str) {
        self.failed.fetch_add(1, Ordering::Relaxed);
        *self.failures.lock().await.entry(kind.to_string()).or_insert(0) += 1;
    }

    pub async fn report(&self, spec: &SourceSpec, elapsed_s: f64) -> Value {
        let opened = self.opened.load(Ordering::Relaxed);
        // Measured over the opening phase only. Dividing by the whole run would
        // mix in the hold time and understate how fast flows were established.
        let open_phase = self.last_open_ms.load(Ordering::Relaxed) as f64 / 1000.0;
        json!({
            "proto": spec.proto,
            "churn": spec.churn,
            "requested": spec.count,
            "opened": opened,
            "failed": self.failed.load(Ordering::Relaxed),
            "closed": self.closed.load(Ordering::Relaxed),
            "concurrent_peak": self.peak.load(Ordering::Relaxed),
            "open_rate_per_s": (open_phase > 0.0).then(|| (opened as f64 / open_phase * 10.0).round() / 10.0),
            "open_phase_s": (open_phase * 1000.0).round() / 1000.0,
            "duration_s": (elapsed_s * 100.0).round() / 100.0,
            "source_ips_used": spec.source_ips.len().max(1),
            "failures_by_type": *self.failures.lock().await,
        })
    }
}

fn source_for(spec: &SourceSpec, index: u64) -> Option<String> {
    if spec.source_ips.is_empty() {
        return None;
    }
    Some(spec.source_ips[(index as usize) % spec.source_ips.len()].clone())
}

/// Each flow is a distinct 5-tuple because the kernel assigns a fresh ephemeral
/// source port; `source_ips` spreads them over several source addresses too.
async fn tcp_flow(
    spec: Arc<SourceSpec>,
    source_ip: Option<String>,
    tally: Arc<Tally>,
    started: Instant,
    hold_until: Instant,
) {
    let socket = match TcpSocket::new_v4() {
        Ok(socket) => socket,
        Err(err) => return tally.failure(&kind_of(&err)).await,
    };
    if let Some(ip) = source_ip {
        if let Ok(addr) = format!("{ip}:0").parse() {
            if let Err(err) = socket.bind(addr) {
                return tally.failure(&kind_of(&err)).await;
            }
        }
    }
    let Ok(target) = format!("{}:{}", spec.dst_ip, spec.tcp_port).parse() else {
        return tally.failure("InvalidAddress").await;
    };

    let connect = tokio::time::timeout(
        Duration::from_secs_f64(spec.connect_timeout_s),
        socket.connect(target),
    )
    .await;
    let mut stream = match connect {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => return tally.failure(&kind_of(&err)).await,
        Err(_) => return tally.failure("TimedOut").await,
    };

    tally.opened_at(started.elapsed().as_millis() as u64);
    let _ = stream.write_all(KEEPALIVE).await;
    let now = Instant::now();
    if hold_until > now {
        tokio::time::sleep(hold_until - now).await;
    }
    let _ = stream.shutdown().await;
    tally.closed();
}

fn kind_of(err: &std::io::Error) -> String {
    format!("{:?}", err.kind())
}

pub async fn run() -> anyhow::Result<()> {
    let spec = Arc::new(spec_read::<SourceSpec>()?);
    let limit = fd_limit_raise(spec.count);
    let tally = Arc::new(Tally::default());
    let started = Instant::now();
    let deadline = started + Duration::from_secs_f64(spec.duration_s);
    let rate = (spec.open_rate_per_s > 0.0).then_some(spec.open_rate_per_s);

    if spec.proto == "udp" {
        let mut sockets = Vec::new();
        for index in 0..spec.count {
            if let Some(rate) = rate {
                pace(started, index, rate).await;
            }
            if Instant::now() >= deadline {
                break;
            }
            let bind = source_for(&spec, index).unwrap_or_else(|| "0.0.0.0".into());
            match UdpSocket::bind(format!("{bind}:0")).await {
                Err(err) => tally.failure(&kind_of(&err)).await,
                Ok(socket) => {
                    let target = format!("{}:{}", spec.dst_ip, spec.udp_port);
                    if let Err(err) = socket.send_to(KEEPALIVE, &target).await {
                        tally.failure(&kind_of(&err)).await;
                    } else {
                        tally.opened_at(started.elapsed().as_millis() as u64);
                        sockets.push(socket);
                    }
                }
            }
        }
        let now = Instant::now();
        if deadline > now {
            tokio::time::sleep(deadline - now).await;
        }
        for _ in sockets.drain(..) {
            tally.closed();
        }
    } else {
        // In churn mode each flow lives for flow_lifetime_s rather than closing
        // at once; holding for zero means they never overlap, so concurrency
        // stays at one and the flow table never fills.
        let lifetime = Duration::from_secs_f64(spec.flow_lifetime_s);
        let mut tasks = Vec::new();
        for index in 0..spec.count {
            if let Some(rate) = rate {
                pace(started, index, rate).await;
            }
            if Instant::now() >= deadline {
                break;
            }
            let hold = if spec.churn {
                deadline.min(Instant::now() + lifetime)
            } else {
                deadline
            };
            tasks.push(tokio::spawn(tcp_flow(
                Arc::clone(&spec),
                source_for(&spec, index),
                Arc::clone(&tally),
                started,
                hold,
            )));
        }
        if spec.churn {
            // Keep replacing finished flows until the deadline, so the device
            // sees insertions and ageing rather than one static set.
            while Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(50)).await;
                tasks.retain(|task| !task.is_finished());
                while (tasks.len() as u64) < spec.count && Instant::now() < deadline {
                    let index = tally.opened.load(Ordering::Relaxed);
                    tasks.push(tokio::spawn(tcp_flow(
                        Arc::clone(&spec),
                        source_for(&spec, index),
                        Arc::clone(&tally),
                        started,
                        deadline.min(Instant::now() + lifetime),
                    )));
                }
            }
        }
        for task in tasks {
            let _ = task.await;
        }
    }

    let mut report = tally.report(&spec, started.elapsed().as_secs_f64()).await;
    report["fd_limit"] = limit.into();
    emit(&report);
    Ok(())
}

async fn pace(started: Instant, index: u64, rate: f64) {
    let due = index as f64 / rate;
    let elapsed = started.elapsed().as_secs_f64();
    if due > elapsed {
        tokio::time::sleep(Duration::from_secs_f64((due - elapsed).min(0.05))).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(source_ips: Vec<String>) -> SourceSpec {
        SourceSpec {
            dst_ip: "10.0.0.2".into(),
            tcp_port: 25501,
            udp_port: 25502,
            count: 10,
            proto: "tcp".into(),
            duration_s: 5.0,
            open_rate_per_s: 0.0,
            churn: false,
            flow_lifetime_s: 1.0,
            connect_timeout_s: 10.0,
            source_ips,
        }
    }

    #[test]
    fn source_addresses_cycle() {
        let spec = spec(vec!["10.0.0.1".into(), "10.0.0.5".into()]);
        assert_eq!(source_for(&spec, 0).unwrap(), "10.0.0.1");
        assert_eq!(source_for(&spec, 1).unwrap(), "10.0.0.5");
        assert_eq!(source_for(&spec, 2).unwrap(), "10.0.0.1");
    }

    #[test]
    fn no_source_addresses_means_let_the_kernel_choose() {
        assert!(source_for(&spec(Vec::new()), 0).is_none());
    }

    #[tokio::test]
    async fn peak_is_the_high_water_mark() {
        let tally = Tally::default();
        tally.opened_at(10);
        tally.opened_at(20);
        tally.closed();
        tally.opened_at(30);
        let report = tally.report(&spec(Vec::new()), 5.0).await;
        assert_eq!(report["opened"], 3);
        assert_eq!(report["concurrent_peak"], 2);
        assert_eq!(report["closed"], 1);
    }

    #[tokio::test]
    async fn open_rate_uses_the_opening_phase_not_the_whole_run() {
        let tally = Tally::default();
        for ms in [100u64, 200, 300, 400] {
            tally.opened_at(ms);
        }
        // Four flows, last opened 0.4s in, so 10/s even though the run was 20s.
        let report = tally.report(&spec(Vec::new()), 20.0).await;
        assert_eq!(report["open_phase_s"], 0.4);
        assert_eq!(report["open_rate_per_s"], 10.0);
        assert_eq!(report["duration_s"], 20.0);
    }

    #[tokio::test]
    async fn failures_are_grouped_by_kind() {
        let tally = Tally::default();
        tally.failure("ConnectionRefused").await;
        tally.failure("ConnectionRefused").await;
        tally.failure("TimedOut").await;
        let report = tally.report(&spec(Vec::new()), 1.0).await;
        assert_eq!(report["failed"], 3);
        assert_eq!(report["failures_by_type"]["ConnectionRefused"], 2);
        assert_eq!(report["failures_by_type"]["TimedOut"], 1);
    }
}
