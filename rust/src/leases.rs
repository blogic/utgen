// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngExt;
use serde::{Deserialize, Serialize};

pub const DEFAULT_TTL: f64 = 3600.0;
pub const MAX_TTL: f64 = 86400.0;
const TOKEN_BYTES: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error("unknown lease token")]
    Unknown,
    #[error("unknown or already released lease token")]
    AlreadyReleased,
    #[error("lease {0}... expired; acquire a new one")]
    Expired(String),
    #[error("lease {token}... does not hold port {port}; it holds {held:?}")]
    PortNotHeld {
        token: String,
        port: String,
        held: Vec<String>,
    },
    #[error("ports already leased: {0}")]
    Contended(String),
    #[error("{0}")]
    Rejected(String),
}

pub fn now_s() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub token: String,
    pub owner: String,
    pub ports: Vec<String>,
    pub created_at: f64,
    pub expires_at: f64,
    #[serde(default)]
    pub note: String,
}

impl Lease {
    pub fn expired(&self) -> bool {
        now_s() >= self.expires_at
    }

    pub fn remaining_s(&self) -> f64 {
        (self.expires_at - now_s()).max(0.0)
    }

    /// Public form. `redact` keeps a token out of a listing that anyone may read.
    pub fn public(&self, redact: bool) -> serde_json::Value {
        let token = if redact {
            format!("{}...", &self.token[..6.min(self.token.len())])
        } else {
            self.token.clone()
        };
        serde_json::json!({
            "token": token,
            "owner": self.owner,
            "ports": self.ports,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "note": self.note,
            "ttl_remaining_s": (self.remaining_s() * 10.0).round() / 10.0,
        })
    }
}

/// Port ownership. One lease may hold several ports; a port has one lease.
///
/// `sweep` returns the leases it dropped rather than invoking a callback, so the
/// caller owns the teardown and there is no cycle back into it.
pub struct LeaseStore {
    state_path: PathBuf,
    leases: HashMap<String, Lease>,
}

impl LeaseStore {
    pub fn open(state_path: &Path) -> Self {
        let mut store = Self {
            state_path: state_path.to_path_buf(),
            leases: HashMap::new(),
        };
        store.load();
        store
    }

    pub fn acquire(
        &mut self,
        owner: &str,
        ports: Vec<String>,
        ttl_s: f64,
        note: &str,
    ) -> Result<Lease, LeaseError> {
        if owner.is_empty() {
            return Err(LeaseError::Rejected(
                "owner must be a non-empty string naming who is claiming the ports".into(),
            ));
        }
        if ports.is_empty() {
            return Err(LeaseError::Rejected("no ports requested".into()));
        }
        let ttl = self.ttl_check(ttl_s)?;
        self.sweep();

        let taken: Vec<String> = ports
            .iter()
            .filter_map(|port| {
                self.owner_of(port)
                    .map(|lease| format!("{port} held by {} ({}s left)", lease.owner, lease.remaining_s().round()))
            })
            .collect();
        if !taken.is_empty() {
            return Err(LeaseError::Contended(taken.join(", ")));
        }

        let now = now_s();
        let lease = Lease {
            token: token_new(),
            owner: owner.to_string(),
            ports,
            created_at: now,
            expires_at: now + ttl,
            note: note.to_string(),
        };
        tracing::info!(token = &lease.token[..6], owner, ports = ?lease.ports, "lease acquired");
        self.leases.insert(lease.token.clone(), lease.clone());
        self.save();
        Ok(lease)
    }

    pub fn release(&mut self, token: &str) -> Result<Lease, LeaseError> {
        let lease = self
            .leases
            .remove(token)
            .ok_or(LeaseError::AlreadyReleased)?;
        self.save();
        tracing::info!(token = &token[..6.min(token.len())], owner = %lease.owner, "lease released");
        Ok(lease)
    }

    pub fn renew(&mut self, token: &str, ttl_s: f64) -> Result<Lease, LeaseError> {
        let ttl = self.ttl_check(ttl_s)?;
        self.get(token)?;
        let lease = self.leases.get_mut(token).ok_or(LeaseError::Unknown)?;
        lease.expires_at = now_s() + ttl;
        let copy = lease.clone();
        self.save();
        Ok(copy)
    }

    pub fn get(&self, token: &str) -> Result<&Lease, LeaseError> {
        let lease = self.leases.get(token).ok_or(LeaseError::Unknown)?;
        if lease.expired() {
            return Err(LeaseError::Expired(
                token[..6.min(token.len())].to_string(),
            ));
        }
        Ok(lease)
    }

    pub fn require(&self, token: &str, port: &str) -> Result<&Lease, LeaseError> {
        let lease = self.get(token)?;
        if !lease.ports.iter().any(|held| held == port) {
            return Err(LeaseError::PortNotHeld {
                token: token[..6.min(token.len())].to_string(),
                port: port.to_string(),
                held: lease.ports.clone(),
            });
        }
        Ok(lease)
    }

    pub fn owner_of(&self, port: &str) -> Option<&Lease> {
        self.leases
            .values()
            .find(|lease| !lease.expired() && lease.ports.iter().any(|held| held == port))
    }

    pub fn all(&mut self) -> Vec<Lease> {
        self.sweep();
        let mut leases: Vec<Lease> = self.leases.values().cloned().collect();
        leases.sort_by(|a, b| a.created_at.total_cmp(&b.created_at));
        leases
    }

    /// Drop expired leases and hand them back so the caller can reclaim hardware.
    pub fn sweep(&mut self) -> Vec<Lease> {
        let expired: Vec<Lease> = self
            .leases
            .values()
            .filter(|lease| lease.expired())
            .cloned()
            .collect();
        for lease in &expired {
            self.leases.remove(&lease.token);
            tracing::warn!(
                token = &lease.token[..6],
                owner = %lease.owner,
                ports = ?lease.ports,
                "lease expired"
            );
        }
        if !expired.is_empty() {
            self.save();
        }
        expired
    }

    pub fn held_ports(&self) -> Vec<String> {
        self.leases
            .values()
            .filter(|lease| !lease.expired())
            .flat_map(|lease| lease.ports.clone())
            .collect()
    }

    fn ttl_check(&self, ttl_s: f64) -> Result<f64, LeaseError> {
        if ttl_s <= 0.0 {
            return Err(LeaseError::Rejected(
                "ttl_s must be positive; an unbounded lease would strand ports on a client crash"
                    .into(),
            ));
        }
        if ttl_s > MAX_TTL {
            return Err(LeaseError::Rejected(format!(
                "ttl_s {ttl_s} exceeds the {MAX_TTL}s maximum"
            )));
        }
        Ok(ttl_s)
    }

    fn save(&self) {
        if let Some(parent) = self.state_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let leases: Vec<&Lease> = self.leases.values().collect();
        let Ok(text) = serde_json::to_string_pretty(&leases) else {
            return;
        };
        let tmp = self.state_path.with_extension("tmp");
        if std::fs::write(&tmp, text).is_ok() {
            let _ = std::fs::rename(&tmp, &self.state_path);
        }
    }

    fn load(&mut self) {
        let Ok(text) = std::fs::read_to_string(&self.state_path) else {
            return;
        };
        match serde_json::from_str::<Vec<Lease>>(&text) {
            Ok(leases) => {
                for lease in leases {
                    self.leases.insert(lease.token.clone(), lease);
                }
            }
            Err(err) => tracing::warn!(%err, "discarding unreadable lease state"),
        }
        self.sweep();
    }
}

fn token_new() -> String {
    let bytes: [u8; TOKEN_BYTES] = rand::rng().random();
    // URL-safe, unpadded, so a token survives a shell or a query string intact.
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    bytes
        .iter()
        .map(|b| ALPHABET[(*b % 64) as usize] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (LeaseStore, tempdir::TempDir) {
        let dir = tempdir::TempDir::new("tgen-leases").unwrap();
        let path = dir.path().join("leases.json");
        (LeaseStore::open(&path), dir)
    }

    #[test]
    fn acquire_then_require() {
        let (mut store, _dir) = store();
        let lease = store
            .acquire("alice@dev", vec!["p0".into(), "p1".into()], 60.0, "")
            .unwrap();
        assert!(store.require(&lease.token, "p0").is_ok());
        assert!(store.require(&lease.token, "p1").is_ok());
    }

    #[test]
    fn require_rejects_a_port_not_in_the_lease() {
        let (mut store, _dir) = store();
        let lease = store.acquire("alice@dev", vec!["p0".into()], 60.0, "").unwrap();
        let message = store.require(&lease.token, "p1").unwrap_err().to_string();
        assert!(message.contains("does not hold port p1"), "{message}");
    }

    #[test]
    fn contention_names_the_holder() {
        let (mut store, _dir) = store();
        store.acquire("alice@dev", vec!["p0".into()], 60.0, "").unwrap();
        let message = store
            .acquire("bob@dev", vec!["p0".into(), "p2".into()], 60.0, "")
            .unwrap_err()
            .to_string();
        assert!(message.contains("already leased"), "{message}");
        assert!(message.contains("alice@dev"), "{message}");
    }

    #[test]
    fn release_frees_the_ports() {
        let (mut store, _dir) = store();
        let lease = store.acquire("alice@dev", vec!["p0".into()], 60.0, "").unwrap();
        store.release(&lease.token).unwrap();
        assert!(store.owner_of("p0").is_none());
        assert!(store.acquire("bob@dev", vec!["p0".into()], 60.0, "").is_ok());
    }

    #[test]
    fn double_release_rejected() {
        let (mut store, _dir) = store();
        let lease = store.acquire("alice@dev", vec!["p0".into()], 60.0, "").unwrap();
        store.release(&lease.token).unwrap();
        assert!(matches!(
            store.release(&lease.token),
            Err(LeaseError::AlreadyReleased)
        ));
    }

    #[test]
    fn unknown_token_rejected() {
        let (store, _dir) = store();
        assert!(matches!(store.get("not-a-token"), Err(LeaseError::Unknown)));
    }

    #[test]
    fn expired_lease_stops_owning_its_ports() {
        let (mut store, _dir) = store();
        store.acquire("alice@dev", vec!["p0".into()], 0.05, "").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(store.owner_of("p0").is_none());
    }

    #[test]
    fn sweep_returns_what_it_dropped() {
        let (mut store, _dir) = store();
        let lease = store.acquire("alice@dev", vec!["p0".into()], 0.05, "").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let dropped = store.sweep();
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].token, lease.token);
        assert!(store.sweep().is_empty());
    }

    #[test]
    fn expired_token_is_rejected_with_advice() {
        let (mut store, _dir) = store();
        let lease = store.acquire("alice@dev", vec!["p0".into()], 0.05, "").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let message = store.get(&lease.token).unwrap_err().to_string();
        assert!(message.contains("acquire a new one"), "{message}");
    }

    #[test]
    fn renew_extends() {
        let (mut store, _dir) = store();
        let lease = store.acquire("alice@dev", vec!["p0".into()], 1.0, "").unwrap();
        let renewed = store.renew(&lease.token, 600.0).unwrap();
        assert!(renewed.expires_at > lease.expires_at);
    }

    #[test]
    fn unbounded_ttl_refused() {
        let (mut store, _dir) = store();
        assert!(store
            .acquire("alice@dev", vec!["p0".into()], 0.0, "")
            .unwrap_err()
            .to_string()
            .contains("must be positive"));
        assert!(store
            .acquire("alice@dev", vec!["p0".into()], 1e9, "")
            .unwrap_err()
            .to_string()
            .contains("exceeds"));
    }

    #[test]
    fn empty_owner_refused() {
        let (mut store, _dir) = store();
        assert!(store
            .acquire("", vec!["p0".into()], 60.0, "")
            .unwrap_err()
            .to_string()
            .contains("owner must be"));
    }

    #[test]
    fn state_survives_a_restart() {
        let dir = tempdir::TempDir::new("tgen-leases").unwrap();
        let path = dir.path().join("leases.json");
        let token = {
            let mut store = LeaseStore::open(&path);
            store
                .acquire("alice@dev", vec!["p0".into(), "p1".into()], 600.0, "")
                .unwrap()
                .token
        };
        let restarted = LeaseStore::open(&path);
        assert_eq!(restarted.require(&token, "p0").unwrap().owner, "alice@dev");
    }

    #[test]
    fn public_redacts_the_token_by_default() {
        let (mut store, _dir) = store();
        let lease = store.acquire("alice@dev", vec!["p0".into()], 60.0, "").unwrap();
        let redacted = lease.public(true)["token"].as_str().unwrap().to_string();
        assert!(redacted.ends_with("..."), "{redacted}");
        assert_eq!(lease.public(false)["token"].as_str().unwrap(), lease.token);
    }

    #[test]
    fn tokens_are_distinct_and_url_safe() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let token = token_new();
            assert_eq!(token.len(), TOKEN_BYTES);
            assert!(token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
            assert!(seen.insert(token));
        }
    }

    #[test]
    fn held_ports_lists_every_live_lease() {
        let (mut store, _dir) = store();
        store.acquire("a", vec!["p0".into()], 60.0, "").unwrap();
        store.acquire("b", vec!["p2".into(), "p3".into()], 60.0, "").unwrap();
        let mut held = store.held_ports();
        held.sort();
        assert_eq!(held, vec!["p0", "p2", "p3"]);
    }
}
