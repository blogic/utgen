// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;

use super::{emit, spec_read};
use crate::leases::now_s;

const MAX_OBSERVATIONS: usize = 10_000;

#[derive(Debug, Deserialize)]
pub struct EchoSpec {
    pub bind: String,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub observations_path: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct Observation {
    pub proto: String,
    pub source_ip: String,
    pub source_port: u16,
    pub packets: u64,
    pub bytes: u64,
    pub first_seen: f64,
    pub last_seen: f64,
}

/// Every distinct source seen, kept so a caller can read what arrived.
///
/// The point is NAT verification: a client learns the address the device
/// translated it to, because the reply states what actually arrived here.
#[derive(Default)]
pub struct Observations {
    seen: BTreeMap<(String, String, u16), Observation>,
}

impl Observations {
    pub fn record(&mut self, proto: &str, ip: &str, port: u16, size: u64) {
        let key = (proto.to_string(), ip.to_string(), port);
        let now = now_s();
        let entry = self.seen.entry(key).or_insert_with(|| Observation {
            proto: proto.to_string(),
            source_ip: ip.to_string(),
            source_port: port,
            packets: 0,
            bytes: 0,
            first_seen: now,
            last_seen: now,
        });
        entry.packets += 1;
        entry.bytes += size;
        entry.last_seen = now;
    }

    pub fn full(&self) -> bool {
        self.seen.len() >= MAX_OBSERVATIONS
    }

    pub fn list(&self) -> Vec<&Observation> {
        self.seen.values().collect()
    }

    pub fn write(&self, path: &PathBuf) {
        let Ok(text) = serde_json::to_string_pretty(&self.list()) else {
            return;
        };
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, text).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
}

pub async fn run() -> anyhow::Result<()> {
    let spec: EchoSpec = spec_read()?;
    if let Some(parent) = spec.observations_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let observations = Arc::new(Mutex::new(Observations::default()));
    observations.lock().await.write(&spec.observations_path);

    let udp = UdpSocket::bind(format!("{}:{}", spec.bind, spec.udp_port)).await?;
    let tcp = TcpListener::bind(format!("{}:{}", spec.bind, spec.tcp_port)).await?;
    emit(&json!({"ready": true, "udp": spec.udp_port, "tcp": spec.tcp_port}));

    let udp_log = Arc::clone(&observations);
    let udp_path = spec.observations_path.clone();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65535];
        loop {
            let Ok((length, from)) = udp.recv_from(&mut buffer).await else {
                continue;
            };
            {
                let mut seen = udp_log.lock().await;
                if !seen.full() {
                    seen.record("udp", &from.ip().to_string(), from.port(), length as u64);
                    seen.write(&udp_path);
                }
            }
            let reply = json!({
                "observed_ip": from.ip().to_string(),
                "observed_port": from.port(),
                "bytes": length,
            });
            let _ = udp.send_to(reply.to_string().as_bytes(), from).await;
        }
    });

    let tcp_log = Arc::clone(&observations);
    let tcp_path = spec.observations_path.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, from)) = tcp.accept().await else {
                continue;
            };
            let observations = Arc::clone(&tcp_log);
            let path = tcp_path.clone();
            tokio::spawn(async move {
                {
                    let mut seen = observations.lock().await;
                    if !seen.full() {
                        seen.record("tcp", &from.ip().to_string(), from.port(), 0);
                        seen.write(&path);
                    }
                }
                let reply = json!({
                    "observed_ip": from.ip().to_string(),
                    "observed_port": from.port(),
                });
                let _ = stream.write_all(format!("{reply}\n").as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    observations.lock().await.write(&spec.observations_path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_sources_accumulate_rather_than_duplicate() {
        let mut seen = Observations::default();
        seen.record("udp", "10.0.0.1", 54321, 8);
        seen.record("udp", "10.0.0.1", 54321, 12);
        seen.record("udp", "10.0.0.1", 54322, 5);
        seen.record("tcp", "10.0.0.1", 54321, 0);

        let list = seen.list();
        assert_eq!(list.len(), 3, "same proto/ip/port is one observation");
        let first = list.iter().find(|o| o.proto == "udp" && o.source_port == 54321).unwrap();
        assert_eq!(first.packets, 2);
        assert_eq!(first.bytes, 20);
        assert!(first.last_seen >= first.first_seen);
    }

    #[test]
    fn protocol_is_part_of_the_identity() {
        let mut seen = Observations::default();
        seen.record("udp", "10.0.0.1", 1000, 1);
        seen.record("tcp", "10.0.0.1", 1000, 0);
        assert_eq!(seen.list().len(), 2);
    }

    #[test]
    fn observations_round_trip_to_disk() {
        let dir = tempdir::TempDir::new("tgen-echo").unwrap();
        let path = dir.path().join("echo.json");
        let mut seen = Observations::default();
        seen.record("udp", "192.168.1.5", 40000, 64);
        seen.write(&path);

        let text = std::fs::read_to_string(&path).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["source_ip"], "192.168.1.5");
        assert_eq!(parsed[0]["source_port"], 40000);
        assert_eq!(parsed[0]["bytes"], 64);
    }
}
