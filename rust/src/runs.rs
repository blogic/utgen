// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

use std::collections::VecDeque;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use rand::RngExt;
use serde::{Deserialize, Serialize};

use crate::leases::now_s;

pub const STATUS_RUNNING: &str = "running";
pub const STATUS_DONE: &str = "done";
pub const STATUS_FAILED: &str = "failed";
pub const STATUS_STOPPED: &str = "stopped";

const SAMPLES_NAME: &str = "samples.ndjson";
const STDERR_NAME: &str = "stderr.log";
const META_NAME: &str = "meta.json";

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("unknown run {0}")]
    Unknown(String),
    #[error("invalid run id {0:?}")]
    InvalidId(String),
    #[error("run {run_id} metadata is unreadable: {message}")]
    Unreadable { run_id: String, message: String },
    #[error("{0:?} is not a terminal status")]
    NotTerminal(String),
    #[error("{0}")]
    Io(String),
}

/// One measurement.
///
/// Persistence serialises this struct directly, never the public projection,
/// which injects a derived `duration_s` key the constructor will not accept and
/// so makes every run read back as corrupt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    pub run_id: String,
    pub kind: String,
    pub owner: String,
    pub params: serde_json::Value,
    pub status: String,
    pub started_at: f64,
    #[serde(default)]
    pub finished_at: Option<f64>,
    #[serde(default)]
    pub rc: Option<i32>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub summary: Option<serde_json::Value>,
}

impl Run {
    pub fn running(&self) -> bool {
        self.status == STATUS_RUNNING
    }

    pub fn duration_s(&self) -> f64 {
        let end = self.finished_at.unwrap_or_else(now_s);
        ((end - self.started_at) * 100.0).round() / 100.0
    }

    pub fn public(&self) -> serde_json::Value {
        let mut value = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
        if let Some(map) = value.as_object_mut() {
            map.insert("duration_s".into(), self.duration_s().into());
        }
        value
    }
}

pub struct RunStore {
    runs_dir: PathBuf,
}

impl RunStore {
    pub fn open(runs_dir: &Path) -> Result<Self, RunError> {
        std::fs::create_dir_all(runs_dir).map_err(|e| RunError::Io(e.to_string()))?;
        Ok(Self {
            runs_dir: runs_dir.to_path_buf(),
        })
    }

    pub fn create(
        &self,
        kind: &str,
        owner: &str,
        params: serde_json::Value,
    ) -> Result<Run, RunError> {
        let run = Run {
            run_id: id_new(),
            kind: kind.to_string(),
            owner: owner.to_string(),
            params,
            status: STATUS_RUNNING.into(),
            started_at: now_s(),
            finished_at: None,
            rc: None,
            error: None,
            summary: None,
        };
        let dir = self.dir_of(&run.run_id)?;
        std::fs::create_dir_all(&dir).map_err(|e| RunError::Io(e.to_string()))?;
        let _ = std::fs::File::create(dir.join(SAMPLES_NAME));
        self.meta_write(&run)?;
        Ok(run)
    }

    pub fn dir_of(&self, run_id: &str) -> Result<PathBuf, RunError> {
        id_check(run_id)?;
        Ok(self.runs_dir.join(run_id))
    }

    pub fn samples_path(&self, run_id: &str) -> Result<PathBuf, RunError> {
        Ok(self.dir_of(run_id)?.join(SAMPLES_NAME))
    }

    pub fn stderr_path(&self, run_id: &str) -> Result<PathBuf, RunError> {
        Ok(self.dir_of(run_id)?.join(STDERR_NAME))
    }

    pub fn get(&self, run_id: &str) -> Result<Run, RunError> {
        let meta = self.dir_of(run_id)?.join(META_NAME);
        let text = std::fs::read_to_string(&meta)
            .map_err(|_| RunError::Unknown(run_id.to_string()))?;
        serde_json::from_str(&text).map_err(|err| RunError::Unreadable {
            run_id: run_id.to_string(),
            message: err.to_string(),
        })
    }

    pub fn list(&self, limit: usize) -> Vec<Run> {
        let Ok(entries) = std::fs::read_dir(&self.runs_dir) else {
            return Vec::new();
        };
        let mut ids: Vec<String> = entries
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().join(META_NAME).is_file())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        ids.sort_by(|a, b| b.cmp(a));
        ids.iter()
            .take(limit)
            .filter_map(|id| self.get(id).ok())
            .collect()
    }

    pub fn finalise(
        &self,
        mut run: Run,
        status: &str,
        rc: Option<i32>,
        summary: Option<serde_json::Value>,
        error: Option<String>,
    ) -> Result<Run, RunError> {
        if !matches!(status, STATUS_DONE | STATUS_FAILED | STATUS_STOPPED) {
            return Err(RunError::NotTerminal(status.to_string()));
        }
        run.status = status.to_string();
        run.finished_at = Some(now_s());
        run.rc = rc;
        run.summary = summary;
        run.error = error;
        self.meta_write(&run)?;
        tracing::info!(
            run_id = %run.run_id,
            status,
            rc = ?rc,
            duration_s = run.duration_s(),
            "run finished"
        );
        Ok(run)
    }

    /// The last `limit` decodable samples.
    ///
    /// The window holds parsed records rather than raw lines, so a blank or
    /// half-written trailing line does not count against the caller's limit.
    pub fn samples_tail(&self, run_id: &str, limit: usize) -> Vec<serde_json::Value> {
        let Ok(path) = self.samples_path(run_id) else {
            return Vec::new();
        };
        let Ok(file) = std::fs::File::open(path) else {
            return Vec::new();
        };
        let mut recent: VecDeque<serde_json::Value> = VecDeque::with_capacity(limit);
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(value) = serde_json::from_str(trimmed) {
                if recent.len() == limit {
                    recent.pop_front();
                }
                recent.push_back(value);
            }
        }
        recent.into()
    }

    pub fn samples_count(&self, run_id: &str) -> usize {
        let Ok(path) = self.samples_path(run_id) else {
            return 0;
        };
        let Ok(file) = std::fs::File::open(path) else {
            return 0;
        };
        BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .filter(|line| !line.trim().is_empty())
            .count()
    }

    fn meta_write(&self, run: &Run) -> Result<(), RunError> {
        let dir = self.dir_of(&run.run_id)?;
        let path = dir.join(META_NAME);
        let text = serde_json::to_string_pretty(run).map_err(|e| RunError::Io(e.to_string()))?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, text).map_err(|e| RunError::Io(e.to_string()))?;
        std::fs::rename(&tmp, &path).map_err(|e| RunError::Io(e.to_string()))
    }
}

fn id_new() -> String {
    // Eight random bytes, not three: a narrow suffix collides inside one second
    // by the birthday paradox, and two runs sharing an id share a directory.
    let suffix: [u8; 8] = rand::rng().random();
    let hex: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{hex}", now_s() as u64)
}

/// run_id arrives straight from an API caller and is used as a path component.
fn id_check(run_id: &str) -> Result<(), RunError> {
    if run_id.is_empty()
        || run_id.contains('/')
        || run_id.contains('\\')
        || run_id.starts_with('.')
    {
        return Err(RunError::InvalidId(run_id.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (RunStore, tempdir::TempDir) {
        let dir = tempdir::TempDir::new("tgen-runs").unwrap();
        let store = RunStore::open(&dir.path().join("runs")).unwrap();
        (store, dir)
    }

    #[test]
    fn create_then_get_round_trips() {
        let (store, _dir) = store();
        let run = store
            .create("iperf3", "tester", serde_json::json!({"src": "p0", "dst": "p1"}))
            .unwrap();
        let again = store.get(&run.run_id).unwrap();
        assert_eq!(again.run_id, run.run_id);
        assert_eq!(again.owner, "tester");
        assert_eq!(again.params["src"], "p0");
        assert!(again.running());
    }

    #[test]
    fn finalised_run_round_trips() {
        let (store, _dir) = store();
        let run = store.create("iperf3", "t", serde_json::json!({})).unwrap();
        store
            .finalise(run.clone(), STATUS_DONE, Some(0), Some(serde_json::json!({"tx_mbps": 9410.7})), None)
            .unwrap();
        let again = store.get(&run.run_id).unwrap();
        assert_eq!(again.status, STATUS_DONE);
        assert_eq!(again.summary.as_ref().unwrap()["tx_mbps"], 9410.7);
        assert!(!again.running());
        assert!(again.finished_at.is_some());
    }

    #[test]
    fn public_exposes_duration_but_the_file_does_not() {
        let (store, _dir) = store();
        let run = store.create("iperf3", "t", serde_json::json!({})).unwrap();
        assert!(run.public().get("duration_s").is_some());
        let text = std::fs::read_to_string(store.dir_of(&run.run_id).unwrap().join(META_NAME)).unwrap();
        let on_disk: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(on_disk.get("duration_s").is_none());
    }

    #[test]
    fn list_sees_every_run() {
        let (store, _dir) = store();
        let mut expected = std::collections::HashSet::new();
        for _ in 0..3 {
            // Ids carry a random suffix, so same-second runs stay distinct.
            expected.insert(store.create("iperf3", "t", serde_json::json!({})).unwrap().run_id);
        }
        let seen: std::collections::HashSet<String> =
            store.list(25).into_iter().map(|r| r.run_id).collect();
        assert_eq!(seen, expected);
    }

    #[test]
    fn unknown_run_rejected() {
        let (store, _dir) = store();
        assert!(matches!(store.get("1795596644-deadbe"), Err(RunError::Unknown(_))));
    }

    #[test]
    fn path_traversal_in_run_id_rejected() {
        let (store, _dir) = store();
        for bad in ["../escape", "a/b", ".hidden", ""] {
            assert!(store.get(bad).is_err(), "{bad} was accepted");
        }
        assert!(matches!(store.dir_of("../escape"), Err(RunError::InvalidId(_))));
    }

    #[test]
    fn non_terminal_status_rejected() {
        let (store, _dir) = store();
        let run = store.create("iperf3", "t", serde_json::json!({})).unwrap();
        assert!(matches!(
            store.finalise(run, STATUS_RUNNING, None, None, None),
            Err(RunError::NotTerminal(_))
        ));
    }

    #[test]
    fn samples_tail_counts_decodable_samples_not_lines() {
        let (store, _dir) = store();
        let run = store.create("iperf3", "t", serde_json::json!({})).unwrap();
        let path = store.samples_path(&run.run_id).unwrap();
        let mut text = String::new();
        for n in 0..5 {
            text.push_str(&format!("{{\"event\":\"interval\",\"n\":{n}}}\n"));
        }
        text.push('\n');
        text.push_str("{bad json\n");
        std::fs::write(&path, text).unwrap();

        assert_eq!(store.samples_count(&run.run_id), 6);
        let tail: Vec<i64> = store
            .samples_tail(&run.run_id, 3)
            .iter()
            .map(|v| v["n"].as_i64().unwrap())
            .collect();
        assert_eq!(tail, vec![2, 3, 4]);
        let all: Vec<i64> = store
            .samples_tail(&run.run_id, 99)
            .iter()
            .map(|v| v["n"].as_i64().unwrap())
            .collect();
        assert_eq!(all, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn failed_run_keeps_the_error() {
        let (store, _dir) = store();
        let run = store.create("iperf3", "t", serde_json::json!({})).unwrap();
        store
            .finalise(run.clone(), STATUS_FAILED, None, None, Some("server did not listen".into()))
            .unwrap();
        assert_eq!(
            store.get(&run.run_id).unwrap().error.unwrap(),
            "server did not listen"
        );
    }

    #[test]
    fn ids_are_distinct_within_one_second() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..500 {
            assert!(seen.insert(id_new()));
        }
    }
}
