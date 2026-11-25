// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

use std::path::{Path, PathBuf};

use rand::RngExt;
use serde_json::{json, Value};
use tokio::process::Child;

use crate::engines::probe::{helper_spawn, ready_wait, stdin_write};
use crate::leases::now_s;

pub const DEFAULT_UDP_PORT: u16 = 25401;
pub const DEFAULT_TCP_PORT: u16 = 25402;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct EchoError(pub String);

/// An echo server in one port's namespace, reporting what arrives at it.
pub struct EchoService {
    pub echo_id: String,
    pub port: String,
    pub ns: String,
    pub bind: String,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub observations_path: PathBuf,
    pub started_at: f64,
    pub stopped_at: Option<f64>,
    child: Option<Child>,
}

impl EchoService {
    pub fn new(
        port: &str,
        ns: &str,
        bind: &str,
        udp_port: u16,
        tcp_port: u16,
        state_dir: &Path,
    ) -> Result<Self, EchoError> {
        std::fs::create_dir_all(state_dir)
            .map_err(|e| EchoError(format!("cannot create {}: {e}", state_dir.display())))?;
        let echo_id = id_new();
        Ok(Self {
            observations_path: state_dir.join(format!("{echo_id}.json")),
            echo_id,
            port: port.to_string(),
            ns: ns.to_string(),
            bind: bind.to_string(),
            udp_port,
            tcp_port,
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

    pub async fn start(&mut self) -> Result<(), EchoError> {
        let mut child = helper_spawn(&self.ns, "echo").map_err(|e| EchoError(e.0))?;
        let spec = json!({
            "bind": self.bind,
            "udp_port": self.udp_port,
            "tcp_port": self.tcp_port,
            "observations_path": self.observations_path.display().to_string(),
        });
        stdin_write(&mut child, &spec).await.map_err(|e| EchoError(e.0))?;
        if let Err(err) = ready_wait(&mut child).await {
            let _ = child.kill().await;
            return Err(EchoError(err.0));
        }
        self.child = Some(child);
        Ok(())
    }

    pub async fn stop(&mut self) -> Value {
        if let Some(child) = self.child.as_mut() {
            if let Some(pid) = child.id() {
                // SIGTERM rather than kill, so the helper writes its final
                // observations before exiting.
                unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
            }
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait()).await;
        }
        self.stopped_at = Some(now_s());
        self.state()
    }

    /// Stop without awaiting, for teardown paths that cannot be async.
    pub fn kill(&mut self) {
        if let Some(child) = self.child.as_mut() {
            if let Some(pid) = child.id() {
                unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
            }
        }
        self.stopped_at = Some(now_s());
    }

    pub fn observations(&self) -> Vec<Value> {
        std::fs::read_to_string(&self.observations_path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    pub fn state(&self) -> Value {
        json!({
            "echo_id": self.echo_id,
            "port": self.port,
            "netns": self.ns,
            "bind": self.bind,
            "udp_port": self.udp_port,
            "tcp_port": self.tcp_port,
            "running": self.stopped_at.is_none(),
            "sources_seen": self.observations().len(),
            "uptime_s": ((self.stopped_at.unwrap_or_else(now_s) - self.started_at) * 100.0).round() / 100.0,
        })
    }
}

fn id_new() -> String {
    // Eight random bytes, not two: a narrow suffix collides inside one second
    // by the birthday paradox, and a collision would evict a live entry from
    // the registry keyed on this id.
    let suffix: [u8; 8] = rand::rng().random();
    let hex: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    format!("echo-{}-{hex}", now_s() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_reports_what_the_helper_wrote() {
        let dir = tempdir::TempDir::new("tgen-echo-state").unwrap();
        let mut service =
            EchoService::new("p1", "tgen-p1", "10.80.0.2", 25401, 25402, dir.path()).unwrap();
        assert_eq!(service.state()["sources_seen"], 0);

        std::fs::write(
            &service.observations_path,
            r#"[{"proto":"udp","source_ip":"10.80.0.1","source_port":54321}]"#,
        )
        .unwrap();
        assert_eq!(service.state()["sources_seen"], 1);
        assert_eq!(service.observations()[0]["source_port"], 54321);
        assert!(!service.running(), "never started");
    }

    #[test]
    fn stopping_marks_it_not_running() {
        let dir = tempdir::TempDir::new("tgen-echo-state").unwrap();
        let mut service =
            EchoService::new("p1", "tgen-p1", "10.80.0.2", 25401, 25402, dir.path()).unwrap();
        assert_eq!(service.state()["running"], true);
        service.kill();
        assert_eq!(service.state()["running"], false);
    }

    #[test]
    fn ids_are_distinct() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            assert!(seen.insert(id_new()));
        }
    }
}
