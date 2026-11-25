// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;

use super::{emit, fd_limit_raise, spec_read};

const READ_CHUNK: usize = 4096;
const UDP_RECV_BUFFER: libc::c_int = 64 << 20;

#[derive(Debug, Deserialize)]
pub struct SinkSpec {
    pub bind: String,
    pub tcp_port: u16,
    pub udp_port: u16,
    #[serde(default = "thousand")]
    pub expect_flows: u64,
}

fn thousand() -> u64 {
    1000
}

#[derive(Default)]
pub struct Counters {
    pub tcp_accepted: AtomicU64,
    pub tcp_concurrent: AtomicU64,
    pub tcp_peak: AtomicU64,
    pub tcp_closed: AtomicU64,
    pub udp_datagrams: AtomicU64,
    pub bytes_in: AtomicU64,
    pub errors: AtomicU64,
    pub udp_flows: Mutex<HashSet<String>>,
}

impl Counters {
    fn opened(&self) {
        self.tcp_accepted.fetch_add(1, Ordering::Relaxed);
        let now = self.tcp_concurrent.fetch_add(1, Ordering::Relaxed) + 1;
        self.tcp_peak.fetch_max(now, Ordering::Relaxed);
    }

    fn closed(&self) {
        self.tcp_concurrent.fetch_sub(1, Ordering::Relaxed);
        self.tcp_closed.fetch_add(1, Ordering::Relaxed);
    }

    pub async fn snapshot(&self) -> Value {
        json!({
            "tcp_accepted": self.tcp_accepted.load(Ordering::Relaxed),
            "tcp_concurrent_peak": self.tcp_peak.load(Ordering::Relaxed),
            "tcp_closed": self.tcp_closed.load(Ordering::Relaxed),
            "tcp_open_at_end": self.tcp_concurrent.load(Ordering::Relaxed),
            "udp_datagrams": self.udp_datagrams.load(Ordering::Relaxed),
            "udp_flows": self.udp_flows.lock().await.len(),
            "bytes_in": self.bytes_in.load(Ordering::Relaxed),
            "errors": self.errors.load(Ordering::Relaxed),
        })
    }
}

pub async fn run() -> anyhow::Result<()> {
    let spec: SinkSpec = spec_read()?;
    let limit = fd_limit_raise(spec.expect_flows);
    let counters = Arc::new(Counters::default());

    let tcp = TcpListener::bind(format!("{}:{}", spec.bind, spec.tcp_port)).await?;
    let udp = UdpSocket::bind(format!("{}:{}", spec.bind, spec.udp_port)).await?;
    // Without a large receive buffer a fast burst of new udp flows overruns this
    // single reader, and the shortfall reads as device loss when there is no
    // device in the path at all.
    unsafe {
        libc::setsockopt(
            std::os::unix::io::AsRawFd::as_raw_fd(&udp),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &UDP_RECV_BUFFER as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    emit(&json!({"ready": true, "fd_limit": limit}));

    let accepting = Arc::clone(&counters);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = tcp.accept().await else {
                accepting.errors.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            let counters = Arc::clone(&accepting);
            tokio::spawn(async move {
                counters.opened();
                let mut buffer = [0u8; READ_CHUNK];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(read) => {
                            counters.bytes_in.fetch_add(read as u64, Ordering::Relaxed);
                        }
                    }
                }
                counters.closed();
            });
        }
    });

    let receiving = Arc::clone(&counters);
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65535];
        loop {
            let Ok((length, from)) = udp.recv_from(&mut buffer).await else {
                continue;
            };
            receiving.udp_datagrams.fetch_add(1, Ordering::Relaxed);
            receiving.bytes_in.fetch_add(length as u64, Ordering::Relaxed);
            receiving.udp_flows.lock().await.insert(from.to_string());
        }
    });

    // Both signals are awaited here rather than around run(), because a select
    // at the call site drops this future on SIGTERM and the totals are never
    // printed. The orchestrator then reports sink=None for every run.
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    emit(&counters.snapshot().await);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn peak_tracks_the_high_water_mark_not_the_current_count() {
        let counters = Counters::default();
        counters.opened();
        counters.opened();
        counters.opened();
        counters.closed();
        counters.closed();
        let snapshot = counters.snapshot().await;
        assert_eq!(snapshot["tcp_accepted"], 3);
        assert_eq!(snapshot["tcp_concurrent_peak"], 3);
        assert_eq!(snapshot["tcp_open_at_end"], 1);
        assert_eq!(snapshot["tcp_closed"], 2);
    }

    #[tokio::test]
    async fn udp_flows_are_counted_by_distinct_source() {
        let counters = Counters::default();
        let mut flows = counters.udp_flows.lock().await;
        flows.insert("10.0.0.1:1000".into());
        flows.insert("10.0.0.1:1001".into());
        flows.insert("10.0.0.1:1000".into());
        drop(flows);
        assert_eq!(counters.snapshot().await["udp_flows"], 2);
    }

    #[test]
    fn fd_limit_is_raised_towards_the_request() {
        // Only ever raised within the hard limit, so the result is a ceiling
        // rather than exactly what was asked for.
        let raised = fd_limit_raise(1000);
        assert!(raised >= 1000, "{raised}");
    }
}
