// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::capture::{Capture, CaptureError, CaptureSpec};
use crate::config::{Config, ConfigError, PortConfig};
use crate::echo::{EchoError, EchoService};
use crate::engines::iperf3::{Iperf3Error, Iperf3Flow, Iperf3Spec, Live};
use crate::engines::flows::{flows_run, FlowsError, FlowsSpec};
use crate::engines::probe::{probe_run, ProbeError, ProbeSpec};
use crate::engines::trafgen::{summary_build, TrafgenError, TrafgenFlow, TrafgenSpec};
use crate::leases::{Lease, LeaseError, LeaseStore};
use crate::netns::{self, NetnsError};
use crate::runs::{RunError, RunStore, STATUS_DONE, STATUS_FAILED, STATUS_STOPPED};

const LINK_POLL: Duration = Duration::from_millis(500);
const MAX_LINK_WAIT: f64 = 300.0;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error(transparent)]
    Iperf3(#[from] Iperf3Error),
    #[error(transparent)]
    Trafgen(#[from] TrafgenError),
    #[error(transparent)]
    Probe(#[from] ProbeError),
    #[error(transparent)]
    Flows(#[from] FlowsError),
    #[error(transparent)]
    Capture(#[from] CaptureError),
    #[error(transparent)]
    Echo(#[from] EchoError),
    #[error("{0}")]
    Rejected(String),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Lease(#[from] LeaseError),
    #[error(transparent)]
    Netns(#[from] NetnsError),
    #[error(transparent)]
    Run(#[from] RunError),
}

type Result<T> = std::result::Result<T, CoreError>;

/// What a caller asked for on an endpoint, kept so a listing can show intent
/// alongside the live kernel state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub port: String,
    pub iface: String,
    pub dev: String,
    pub netns: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub gateway4: Option<String>,
    pub gateway6: Option<String>,
    pub vlan: Option<u16>,
    pub vlan_s: Option<u16>,
    pub mtu: Option<u32>,
    pub created_at: f64,
}

/// The single orchestrator. Every face calls only this.
pub struct Core {
    pub cfg: Config,
    leases: Mutex<LeaseStore>,
    endpoints: Mutex<BTreeMap<String, Endpoint>>,
    endpoints_path: PathBuf,
    pub runs: RunStore,
    flows: Mutex<BTreeMap<String, FlowHandle>>,
    ports_in_use: Mutex<std::collections::BTreeSet<u16>>,
    ports_held: Mutex<BTreeMap<String, Vec<u16>>>,
    captures: Mutex<BTreeMap<String, Capture>>,
    echoes: Mutex<BTreeMap<String, EchoService>>,
    counters_before: Mutex<BTreeMap<String, BTreeMap<String, BTreeMap<String, i64>>>>,
}

/// A flow in flight: what a poller reads, and how to end it early.
struct FlowHandle {
    live: Arc<Live>,
    cancel: tokio_util::sync::CancellationToken,
}

impl Core {
    pub fn new(cfg: Config) -> Result<Self> {
        std::fs::create_dir_all(&cfg.state_dir)
            .map_err(|e| CoreError::Rejected(format!("{}: {e}", cfg.state_dir.display())))?;
        let leases = LeaseStore::open(&cfg.state_dir.join("leases.json"));
        let endpoints_path = cfg.state_dir.join("endpoints.json");
        let endpoints = endpoints_load(&endpoints_path);
        let runs = RunStore::open(&cfg.runs_dir)?;
        Ok(Self {
            cfg,
            leases: Mutex::new(leases),
            endpoints: Mutex::new(endpoints),
            endpoints_path,
            runs,
            flows: Mutex::new(BTreeMap::new()),
            ports_in_use: Mutex::new(std::collections::BTreeSet::new()),
            ports_held: Mutex::new(BTreeMap::new()),
            captures: Mutex::new(BTreeMap::new()),
            echoes: Mutex::new(BTreeMap::new()),
            counters_before: Mutex::new(BTreeMap::new()),
        })
    }

    /// Release namespaces a previous daemon left behind.
    ///
    /// Namespaces are kernel state pinned in /run/netns and outlive the process,
    /// so without this a crash or restart strands the NICs permanently. The lease
    /// file is the record of intent: anything claimed without a live lease is an
    /// orphan.
    pub async fn reconcile(&self) -> Value {
        let held = self.leases.lock().await.held_ports();
        let mut cleaned = Vec::new();
        let mut kept = Vec::new();
        let mut failed = Vec::new();
        let mut foreign = Vec::new();

        for port in &self.cfg.ports {
            let ns = self.cfg.netns_of(port);
            if !netns::ns_exists(&ns) {
                continue;
            }
            // A namespace of ours that does not hold our device belongs to
            // something else wearing the same prefix. Tearing it down would
            // move whatever it does hold, so it is reported and left.
            if self.port_ns(port).await.is_none() {
                foreign.push(ns);
                continue;
            }
            if held.contains(&port.label) {
                kept.push(port.label.clone());
                continue;
            }
            match self.endpoint_teardown(&port.label).await {
                Ok(()) => cleaned.push(port.label.clone()),
                Err(err) => {
                    tracing::warn!(port = %port.label, %err, "teardown during reconcile failed");
                    failed.push(port.label.clone());
                }
            }
        }

        let pool: Vec<String> = self.cfg.ports.iter().map(|p| self.cfg.netns_of(p)).collect();
        let strays: Vec<String> = netns::ns_list()
            .into_iter()
            .filter(|ns| ns.starts_with(&self.cfg.netns_prefix) && !pool.contains(ns))
            .collect();

        if !cleaned.is_empty() || !strays.is_empty() || !failed.is_empty() || !foreign.is_empty() {
            tracing::warn!(?cleaned, ?kept, ?failed, ?foreign, ?strays, "reconcile");
        }
        json!({
            "orphans_cleaned": cleaned,
            "kept_under_lease": kept,
            "teardown_failed": failed,
            "foreign": foreign,
            "strays": strays,
        })
    }

    // ---------- ports ----------

    pub async fn ports_list(&self) -> Result<Vec<Value>> {
        let mut out = Vec::with_capacity(self.cfg.ports.len());
        for port in &self.cfg.ports {
            out.push(self.port_state(&port.label).await?);
        }
        Ok(out)
    }

    pub async fn port_state(&self, reference: &str) -> Result<Value> {
        let port = self.cfg.port_find(reference)?.clone();
        let ns = self.cfg.netns_of(&port);
        let claimed = self.port_ns(&port).await.is_some();
        let owner = self
            .leases
            .lock()
            .await
            .owner_of(&port.label)
            .map(|lease| lease.owner.clone());

        let active = if claimed { Some(ns.as_str()) } else { None };
        let mut state = netns::link_state_get(active, &port.iface).await;
        let addresses = if state["present"].as_bool() == Some(true) {
            netns::addrs_get(active, &port.iface).await
        } else {
            Vec::new()
        };

        if let Some(map) = state.as_object_mut() {
            map.insert("label".into(), port.label.clone().into());
            map.insert("description".into(), port.description.clone().into());
            map.insert("claimed".into(), claimed.into());
            map.insert(
                "netns".into(),
                if claimed { json!(ns) } else { Value::Null },
            );
            map.insert("lease_owner".into(), serde_json::to_value(owner).unwrap());
            map.insert("addresses".into(), serde_json::to_value(addresses).unwrap());
        }
        Ok(state)
    }

    /// Wait for carrier, then report the negotiated speed.
    pub async fn link_wait(
        &self,
        reference: &str,
        timeout_s: f64,
        expect_mbps: Option<u32>,
    ) -> Result<Value> {
        if !(timeout_s > 0.0 && timeout_s <= MAX_LINK_WAIT) {
            return Err(CoreError::Rejected(format!(
                "timeout_s must be in 0..{MAX_LINK_WAIT}"
            )));
        }
        let port = self.cfg.port_find(reference)?.clone();
        let deadline = tokio::time::Instant::now() + Duration::from_secs_f64(timeout_s);

        loop {
            let mut state = self.port_state(&port.label).await?;
            let up = state["carrier"].as_bool() == Some(true)
                && state["speed_mbps"].as_u64().is_some();
            if up {
                state["link_wait"] = "up".into();
                return Ok(speed_verdict(state, expect_mbps));
            }
            if tokio::time::Instant::now() >= deadline {
                state["link_wait"] = "timeout".into();
                state["detail"] =
                    format!("no carrier on {} after {timeout_s}s", port.iface).into();
                return Ok(state);
            }
            tokio::time::sleep(LINK_POLL).await;
        }
    }

    // ---------- per-port settings ----------

    pub async fn port_offloads(
        &self,
        token: &str,
        reference: &str,
        settings: Option<BTreeMap<String, bool>>,
    ) -> Result<Value> {
        let port = self.cfg.port_find(reference)?.clone();
        let ns = self.port_ns(&port).await;
        let Some(settings) = settings else {
            return Ok(json!({
                "port": port.label,
                "offloads": netns::offloads_get(ns.as_deref(), &port.iface).await,
            }));
        };
        self.leases.lock().await.require(token, &port.label)?;
        let after = netns::offloads_set(ns.as_deref(), &port.iface, &settings).await?;
        Ok(json!({"port": port.label, "offloads": after, "requested": settings}))
    }

    pub async fn port_pause(
        &self,
        token: &str,
        reference: &str,
        autoneg: Option<bool>,
        rx: Option<bool>,
        tx: Option<bool>,
    ) -> Result<Value> {
        let port = self.cfg.port_find(reference)?.clone();
        let ns = self.port_ns(&port).await;
        if autoneg.is_none() && rx.is_none() && tx.is_none() {
            return Ok(json!({
                "port": port.label,
                "pause": netns::pause_get(ns.as_deref(), &port.iface).await,
            }));
        }
        self.leases.lock().await.require(token, &port.label)?;
        netns::pause_set(ns.as_deref(), &port.iface, autoneg, rx, tx).await?;

        // The change can bounce the link, and the state mid-renegotiation is not
        // the settled result.
        tokio::time::sleep(netns::PAUSE_SETTLE).await;
        let after = netns::pause_get(ns.as_deref(), &port.iface).await;
        let mut ignored = BTreeMap::new();
        for (field, wanted) in [("autoneg", autoneg), ("rx", rx), ("tx", tx)] {
            if let Some(wanted) = wanted {
                if after.get(field) != Some(&wanted) {
                    ignored.insert(field.to_string(), wanted);
                }
            }
        }
        let mut out = json!({"port": port.label, "pause": after, "applied": ignored.is_empty()});
        if !ignored.is_empty() {
            out["ignored"] = serde_json::to_value(&ignored).unwrap();
            out["detail"] = format!(
                "the driver accepted ethtool -A but did not apply {ignored:?}. i40e negotiates \
                 pause and cannot have it forced, so only the negotiated result and the xon/xoff \
                 counters are available."
            )
            .into();
        }
        Ok(out)
    }

    pub async fn port_speed_force(
        &self,
        token: &str,
        reference: &str,
        mbps: Option<u32>,
    ) -> Result<Value> {
        let port = self.cfg.port_find(reference)?.clone();
        self.leases.lock().await.require(token, &port.label)?;
        let ns = self.port_ns(&port).await;
        netns::advertise_set(ns.as_deref(), &port.iface, mbps).await?;
        Ok(json!({
            "port": port.label,
            "advertising": match mbps {
                None => "all supported modes".to_string(),
                Some(speed) => format!("{speed} Mbps only"),
            },
            "detail": "link renegotiates, so poll link_wait for the result",
        }))
    }

    pub async fn port_mac_set(&self, token: &str, reference: &str, mac: &str) -> Result<Value> {
        let port = self.cfg.port_find(reference)?.clone();
        self.leases.lock().await.require(token, &port.label)?;
        if !mac_valid(mac) {
            return Err(CoreError::Rejected(format!(
                "{mac:?} is not a MAC address in aa:bb:cc:dd:ee:ff form"
            )));
        }
        let ns = self.port_ns(&port).await;
        netns::link_up_set(ns.as_deref(), &port.iface, false).await?;
        netns::mac_set(ns.as_deref(), &port.iface, mac).await?;
        netns::link_up_set(ns.as_deref(), &port.iface, true).await?;
        Ok(json!({"port": port.label, "mac": mac}))
    }

    pub async fn port_counters(&self, reference: &str, full: bool) -> Result<Value> {
        let port = self.cfg.port_find(reference)?.clone();
        let ns = self.port_ns(&port).await;
        Ok(json!({
            "port": port.label,
            "full": full,
            "counters": netns::counters_get(ns.as_deref(), &port.iface, full).await,
        }))
    }

    // ---------- leases ----------

    pub async fn lease_acquire(
        &self,
        owner: &str,
        ports: Vec<String>,
        ttl_s: f64,
        note: &str,
    ) -> Result<Value> {
        let mut labels = Vec::with_capacity(ports.len());
        for reference in &ports {
            labels.push(self.cfg.port_find(reference)?.label.clone());
        }
        let lease = self.leases.lock().await.acquire(owner, labels, ttl_s, note)?;
        Ok(lease.public(false))
    }

    pub async fn lease_release(&self, token: &str) -> Result<Value> {
        let lease = self.leases.lock().await.get(token)?.clone();
        for label in &lease.ports {
            if let Err(err) = self.endpoint_teardown(label).await {
                tracing::warn!(port = %label, %err, "teardown during release failed");
            }
        }
        self.leases.lock().await.release(token)?;
        Ok(json!({"released": lease.public(true), "ports_freed": lease.ports}))
    }

    pub async fn lease_renew(&self, token: &str, ttl_s: f64) -> Result<Value> {
        Ok(self.leases.lock().await.renew(token, ttl_s)?.public(true))
    }

    pub async fn leases_list(&self) -> Vec<Value> {
        self.leases
            .lock()
            .await
            .all()
            .iter()
            .map(|lease| lease.public(true))
            .collect()
    }

    /// Drop expired leases and reclaim their hardware.
    ///
    /// Sweeping only on API entry means a client that crashes without releasing
    /// holds its physical ports until some unrelated call happens to sweep.
    pub async fn sweep(&self) -> Vec<Lease> {
        let expired = self.leases.lock().await.sweep();
        for lease in &expired {
            for label in &lease.ports {
                if let Err(err) = self.endpoint_teardown(label).await {
                    tracing::warn!(port = %label, %err, "teardown after lease expiry failed");
                }
            }
        }
        expired
    }

    // ---------- traffic ----------

    /// Start an iperf3 flow and return at once; the caller polls traffic_status.
    /// Takes `&Arc<Self>` so the reaper task can hold a share of the core;
    /// the run outlives the request that started it.
    pub async fn traffic_start(
        self: &Arc<Self>,
        token: &str,
        src: &str,
        dst: &str,
        family: &str,
        spec: Iperf3Spec,
    ) -> Result<Value> {
        let src_port = self.cfg.port_find(src)?.clone();
        let dst_port = self.cfg.port_find(dst)?.clone();
        if src_port.label == dst_port.label {
            return Err(CoreError::Rejected(
                "src and dst must be different ports; a flow has to leave the host".into(),
            ));
        }
        self.leases.lock().await.require(token, &src_port.label)?;
        let owner = self.lease_owner_for(token, &dst_port.label).await?;

        let src_ep = self.endpoint_require(&src_port.label).await?;
        let dst_ep = self.endpoint_require(&dst_port.label).await?;
        let dst_addresses = netns::addrs_get(Some(&dst_ep.netns), &dst_ep.dev).await;
        let dst_ip = endpoint_address(&dst_addresses, family)?;
        spec.validate()?;

        let mut spec = spec;
        spec.port = self.listen_port_take(spec.port).await?;

        let mut params = serde_json::to_value(&spec).unwrap_or(json!({}));
        if let Some(map) = params.as_object_mut() {
            map.insert("src".into(), src_port.label.clone().into());
            map.insert("dst".into(), dst_port.label.clone().into());
            map.insert("dst_ip".into(), dst_ip.clone().into());
            map.insert("family".into(), family.into());
        }
        let run = match self.runs.create("iperf3", &owner, params) {
            Ok(run) => run,
            Err(err) => {
                self.listen_ports_drop(&[spec.port]).await;
                return Err(err.into());
            }
        };
        self.listen_ports_record(&run.run_id, vec![spec.port]).await;

        self.counters_snapshot(&run.run_id, &src_port, &dst_port, &src_ep, &dst_ep).await;

        let live = Arc::new(Live::default());
        let cancel = tokio_util::sync::CancellationToken::new();
        self.flows.lock().await.insert(
            run.run_id.clone(),
            FlowHandle { live: Arc::clone(&live), cancel: cancel.clone() },
        );

        let flow = Iperf3Flow {
            src_ns: src_ep.netns.clone(),
            dst_ns: dst_ep.netns.clone(),
            dst_ip: dst_ip.clone(),
            spec: spec.clone(),
        };
        let samples = self.runs.samples_path(&run.run_id)?;
        let stderr = self.runs.stderr_path(&run.run_id)?;
        let run_id = run.run_id.clone();
        let core = Arc::clone(self);
        tokio::spawn(async move {
            let outcome = flow.run(&samples, &stderr, live, cancel).await;
            core.flow_reap(&run_id, outcome).await;
        });

        Ok(json!({
            "run_id": run.run_id,
            "status": run.status,
            "src": src_port.label,
            "dst": dst_port.label,
            "dst_ip": dst_ip,
            "duration_s": spec.duration_s,
            "poll_with": format!("traffic_status(run_id={:?})", run.run_id),
        }))
    }

    pub async fn traffic_status(&self, run_id: &str) -> Result<Value> {
        let run = self.runs.get(run_id)?;
        let mut out = run.public();
        out["samples"] = self.runs.samples_count(run_id).into();
        if run.running() {
            if let Some(handle) = self.flows.lock().await.get(run_id) {
                out["live"] = handle.live.snapshot().await;
            }
        }
        Ok(out)
    }

    pub async fn traffic_stop(&self, run_id: &str) -> Result<Value> {
        let run = self.runs.get(run_id)?;
        if !run.running() {
            return Ok(json!({"run_id": run_id, "status": run.status, "detail": "already finished"}));
        }
        let cancel = self.flows.lock().await.get(run_id).map(|h| h.cancel.clone());
        match cancel {
            None => {
                self.runs.finalise(run, STATUS_STOPPED, None, None, Some("no live flow for this run".into()))?;
                Ok(json!({"run_id": run_id, "status": STATUS_STOPPED}))
            }
            Some(cancel) => {
                cancel.cancel();
                // The reaper finalises; wait for it rather than reporting a
                // status the run has not reached.
                for _ in 0..100 {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    if !self.runs.get(run_id).map(|r| r.running()).unwrap_or(false) {
                        break;
                    }
                }
                self.traffic_status(run_id).await
            }
        }
    }

    /// Claim a free listen port, starting from the requested one.
    ///
    /// Held until the run finishes, so simultaneous runs never share a
    /// listener. Every engine binds a server in the destination namespace, so
    /// every engine goes through here: iperf3 answers a second client with "the
    /// server is busy running a test", and the probe and flow sinks simply fail
    /// to bind. 64 is well past what one port pair can saturate.
    async fn listen_port_take(&self, wanted: u16) -> Result<u16> {
        let mut in_use = self.ports_in_use.lock().await;
        for candidate in wanted..wanted.saturating_add(64) {
            if in_use.insert(candidate) {
                return Ok(candidate);
            }
        }
        Err(CoreError::Rejected(format!(
            "no free listen port in {wanted}..{}; too many runs are in flight",
            wanted.saturating_add(64)
        )))
    }

    /// Tie claimed ports to a run, so reaping it returns exactly those.
    async fn listen_ports_record(&self, run_id: &str, ports: Vec<u16>) {
        self.ports_held.lock().await.insert(run_id.into(), ports);
    }

    async fn listen_ports_free(&self, run_id: &str) {
        let Some(ports) = self.ports_held.lock().await.remove(run_id) else {
            return;
        };
        let mut in_use = self.ports_in_use.lock().await;
        for port in ports {
            in_use.remove(&port);
        }
    }

    /// Hand back ports claimed for a run that then failed to start.
    async fn listen_ports_drop(&self, ports: &[u16]) {
        let mut in_use = self.ports_in_use.lock().await;
        for port in ports {
            in_use.remove(port);
        }
    }

    async fn flow_reap(&self, run_id: &str, outcome: std::result::Result<Value, Iperf3Error>) {
        let Ok(run) = self.runs.get(run_id) else { return };
        let finished = match outcome {
            Err(err) => self.runs.finalise(run, STATUS_FAILED, None, None, Some(err.to_string())),
            Ok(mut summary) => {
                summary["counters"] = self.counters_collect(run_id, &run.params).await;
                let status = if summary.get("stopped_early").is_some() {
                    STATUS_STOPPED
                } else {
                    STATUS_DONE
                };
                let rc = summary["rc"].as_i64().map(|v| v as i32);
                self.runs.finalise(run, status, rc, Some(summary), None)
            }
        };
        if let Err(err) = finished {
            tracing::error!(run_id, %err, "could not finalise run");
        }
        self.flows.lock().await.remove(run_id);
        self.counters_before.lock().await.remove(run_id);
        self.listen_ports_free(run_id).await;
    }

    async fn counters_snapshot(
        &self,
        run_id: &str,
        src: &PortConfig,
        dst: &PortConfig,
        src_ep: &Endpoint,
        dst_ep: &Endpoint,
    ) {
        let mut taken = BTreeMap::new();
        taken.insert(
            src.label.clone(),
            netns::counters_get(Some(&src_ep.netns), &src.iface, false).await,
        );
        taken.insert(
            dst.label.clone(),
            netns::counters_get(Some(&dst_ep.netns), &dst.iface, false).await,
        );
        self.counters_before.lock().await.insert(run_id.to_string(), taken);
    }

    /// Counters that moved on each port during the run.
    async fn counters_collect(&self, run_id: &str, params: &Value) -> Value {
        let before = self.counters_before.lock().await.get(run_id).cloned().unwrap_or_default();
        let mut out = serde_json::Map::new();
        for key in ["src", "dst"] {
            let Some(label) = params[key].as_str() else { continue };
            let Some(baseline) = before.get(label) else { continue };
            let Ok(port) = self.cfg.port_find(label) else { continue };
            let ns = self.port_ns(port).await;
            let after = netns::counters_get(ns.as_deref(), &port.iface, false).await;
            out.insert(
                label.to_string(),
                serde_json::to_value(netns::counters_diff(baseline, &after)).unwrap(),
            );
        }
        Value::Object(out)
    }

    /// Small-frame load from src to dst, measured by counters on both ports.
    pub async fn pps_start(
        self: &Arc<Self>,
        token: &str,
        src: &str,
        dst: &str,
        spec: TrafgenSpec,
    ) -> Result<Value> {
        let src_port = self.cfg.port_find(src)?.clone();
        let dst_port = self.cfg.port_find(dst)?.clone();
        if src_port.label == dst_port.label {
            return Err(CoreError::Rejected("src and dst must be different ports".into()));
        }
        self.leases.lock().await.require(token, &src_port.label)?;
        let owner = self.lease_owner_for(token, &dst_port.label).await?;

        let src_ep = self.endpoint_require(&src_port.label).await?;
        let dst_ep = self.endpoint_require(&dst_port.label).await?;
        spec.validate()?;

        let src_state = netns::link_state_get(Some(&src_ep.netns), &src_port.iface).await;
        let dst_state = netns::link_state_get(Some(&dst_ep.netns), &dst_port.iface).await;
        let (Some(src_mac), Some(dst_mac)) =
            (src_state["mac"].as_str(), dst_state["mac"].as_str())
        else {
            return Err(CoreError::Rejected(
                "could not read both ports' MAC addresses".into(),
            ));
        };

        let mut params = serde_json::to_value(&spec).unwrap_or(json!({}));
        if let Some(map) = params.as_object_mut() {
            map.insert("src".into(), src_port.label.clone().into());
            map.insert("dst".into(), dst_port.label.clone().into());
        }
        let run = self.runs.create("trafgen", &owner, params)?;

        let mut flow = TrafgenFlow::new(
            &src_ep.netns,
            &src_ep.dev,
            spec.clone(),
            self.runs.dir_of(&run.run_id)?.join("trafgen.cfg"),
            src_mac,
            dst_mac,
        )?;

        self.counters_snapshot(&run.run_id, &src_port, &dst_port, &src_ep, &dst_ep).await;
        if let Err(err) = flow.start(&src_port.iface).await {
            self.counters_before.lock().await.remove(&run.run_id);
            let _ = self.runs.finalise(run, STATUS_FAILED, None, None, Some(err.to_string()));
            return Err(err.into());
        }

        let run_id = run.run_id.clone();
        let core = Arc::clone(self);
        let duration = Duration::from_secs(spec.duration_s as u64);
        tokio::spawn(async move {
            let started = tokio::time::Instant::now();
            tokio::time::sleep(duration).await;
            flow.stop().await;
            core.pps_reap(&run_id, flow, started.elapsed().as_secs_f64()).await;
        });

        Ok(json!({
            "run_id": run.run_id,
            "status": run.status,
            "src": src_port.label,
            "dst": dst_port.label,
            "frame_bytes": spec.frame_bytes,
            "duration_s": spec.duration_s,
            "poll_with": format!("traffic_status(run_id={:?})", run.run_id),
        }))
    }

    async fn pps_reap(&self, run_id: &str, flow: TrafgenFlow, elapsed_s: f64) {
        let Ok(run) = self.runs.get(run_id) else { return };
        let before = self.counters_before.lock().await.get(run_id).cloned().unwrap_or_default();

        let mut deltas = BTreeMap::new();
        for key in ["src", "dst"] {
            let Some(label) = run.params[key].as_str() else { continue };
            let Some(baseline) = before.get(label) else { continue };
            let Ok(port) = self.cfg.port_find(label) else { continue };
            let ns = self.port_ns(port).await;
            let after = netns::counters_get(ns.as_deref(), &port.iface, true).await;
            deltas.insert(label.to_string(), netns::counters_diff(baseline, &after));
        }
        let empty = BTreeMap::new();
        let tx = run.params["src"].as_str().and_then(|l| deltas.get(l)).unwrap_or(&empty);
        let rx = run.params["dst"].as_str().and_then(|l| deltas.get(l)).unwrap_or(&empty);

        let mut summary = summary_build(&flow.spec, elapsed_s, tx, rx);
        let flush_errors = flow.flush_errors();
        summary["workers"] = flow.spec.cpus.into();
        summary["tx_ring_flush_errors"] = flush_errors.into();
        if flush_errors > 0 {
            summary["detail"] = format!(
                "{flush_errors} TX_RING flush errors (EAGAIN) across {} workers. This is a \
                 transient i40e condition, not lost traffic; judge the run by packets_sent \
                 and loss_percent",
                flow.spec.cpus
            )
            .into();
        }
        summary["counters"] = serde_json::to_value(
            deltas
                .iter()
                .map(|(label, moved)| {
                    (label.clone(), netns::counters_interesting(moved))
                })
                .collect::<BTreeMap<_, _>>(),
        )
        .unwrap_or(Value::Null);

        if let Err(err) = self.runs.finalise(run, STATUS_DONE, None, Some(summary), None) {
            tracing::error!(run_id, %err, "could not finalise pps run");
        }
        self.counters_before.lock().await.remove(run_id);
    }

    /// One-way delay, loss and reordering from a sequence-numbered UDP stream.
    pub async fn probe_start(
        self: &Arc<Self>,
        token: &str,
        src: &str,
        dst: &str,
        family: &str,
        spec: ProbeSpec,
    ) -> Result<Value> {
        let (src_port, dst_port, src_ep, dst_ep, dst_ip, owner) =
            self.pair_resolve(token, src, dst, family).await?;
        spec.validate()?;

        let mut spec = spec;
        spec.port = self.listen_port_take(spec.port).await?;

        let mut params = serde_json::to_value(&spec).unwrap_or(json!({}));
        if let Some(map) = params.as_object_mut() {
            map.insert("src".into(), src_port.label.clone().into());
            map.insert("dst".into(), dst_port.label.clone().into());
            map.insert("dst_ip".into(), dst_ip.clone().into());
            map.insert("family".into(), family.into());
        }
        let run = match self.runs.create("probe", &owner, params) {
            Ok(run) => run,
            Err(err) => {
                self.listen_ports_drop(&[spec.port]).await;
                return Err(err.into());
            }
        };
        self.listen_ports_record(&run.run_id, vec![spec.port]).await;
        self.counters_snapshot(&run.run_id, &src_port, &dst_port, &src_ep, &dst_ep).await;

        let run_id = run.run_id.clone();
        let core = Arc::clone(self);
        let bind_ip = dst_ip.clone();
        let duration = spec.duration_s;
        tokio::spawn(async move {
            let outcome = probe_run(&src_ep.netns, &dst_ep.netns, &dst_ip, &bind_ip, &spec).await;
            core.helper_reap(&run_id, outcome.map_err(CoreError::from)).await;
        });

        Ok(json!({
            "run_id": run.run_id,
            "status": run.status,
            "src": src_port.label,
            "dst": dst_port.label,
            "duration_s": duration,
            "poll_with": format!("traffic_status(run_id={:?})", run.run_id),
        }))
    }

    /// Many concurrent flows, to fill and age a device's flow table.
    pub async fn flows_start(
        self: &Arc<Self>,
        token: &str,
        src: &str,
        dst: &str,
        family: &str,
        spec: FlowsSpec,
    ) -> Result<Value> {
        let (src_port, dst_port, src_ep, dst_ep, dst_ip, owner) =
            self.pair_resolve(token, src, dst, family).await?;
        spec.validate()?;

        // The sink binds both, whatever proto the flows use.
        let mut spec = spec;
        spec.tcp_port = self.listen_port_take(spec.tcp_port).await?;
        spec.udp_port = match self.listen_port_take(spec.udp_port).await {
            Ok(port) => port,
            Err(err) => {
                self.listen_ports_drop(&[spec.tcp_port]).await;
                return Err(err.into());
            }
        };
        let held = vec![spec.tcp_port, spec.udp_port];

        let mut params = serde_json::to_value(&spec).unwrap_or(json!({}));
        if let Some(map) = params.as_object_mut() {
            map.insert("src".into(), src_port.label.clone().into());
            map.insert("dst".into(), dst_port.label.clone().into());
            map.insert("dst_ip".into(), dst_ip.clone().into());
            map.insert("family".into(), family.into());
        }
        let run = match self.runs.create("flows", &owner, params) {
            Ok(run) => run,
            Err(err) => {
                self.listen_ports_drop(&held).await;
                return Err(err.into());
            }
        };
        self.listen_ports_record(&run.run_id, held).await;
        self.counters_snapshot(&run.run_id, &src_port, &dst_port, &src_ep, &dst_ep).await;

        let run_id = run.run_id.clone();
        let core = Arc::clone(self);
        let bind_ip = dst_ip.clone();
        let flows = spec.count;
        let proto = spec.proto.clone();
        let duration = spec.duration_s;
        tokio::spawn(async move {
            let outcome = flows_run(&src_ep.netns, &dst_ep.netns, &dst_ip, &bind_ip, &spec).await;
            core.helper_reap(&run_id, outcome.map_err(CoreError::from)).await;
        });

        Ok(json!({
            "run_id": run.run_id,
            "status": run.status,
            "src": src_port.label,
            "dst": dst_port.label,
            "flows": flows,
            "proto": proto,
            "duration_s": duration,
            "poll_with": format!("traffic_status(run_id={:?})", run.run_id),
        }))
    }

    /// Resolve a src/dst pair: lease, endpoints and the target address.
    async fn pair_resolve(
        &self,
        token: &str,
        src: &str,
        dst: &str,
        family: &str,
    ) -> Result<(PortConfig, PortConfig, Endpoint, Endpoint, String, String)> {
        let src_port = self.cfg.port_find(src)?.clone();
        let dst_port = self.cfg.port_find(dst)?.clone();
        if src_port.label == dst_port.label {
            return Err(CoreError::Rejected(
                "src and dst must be different ports; a flow has to leave the host".into(),
            ));
        }
        self.leases.lock().await.require(token, &src_port.label)?;
        let owner = self.lease_owner_for(token, &dst_port.label).await?;
        let src_ep = self.endpoint_require(&src_port.label).await?;
        let dst_ep = self.endpoint_require(&dst_port.label).await?;
        let addresses = netns::addrs_get(Some(&dst_ep.netns), &dst_ep.dev).await;
        let dst_ip = endpoint_address(&addresses, family)?;
        Ok((src_port, dst_port, src_ep, dst_ep, dst_ip, owner))
    }

    /// Finalise a run whose engine produced its whole summary in one go.
    async fn helper_reap(&self, run_id: &str, outcome: Result<Value>) {
        let Ok(run) = self.runs.get(run_id) else { return };
        let finished = match outcome {
            Err(err) => self.runs.finalise(run, STATUS_FAILED, None, None, Some(err.to_string())),
            Ok(mut summary) => {
                summary["counters"] = self.counters_collect(run_id, &run.params).await;
                self.runs.finalise(run, STATUS_DONE, None, Some(summary), None)
            }
        };
        if let Err(err) = finished {
            tracing::error!(run_id, %err, "could not finalise run");
        }
        self.counters_before.lock().await.remove(run_id);
        self.listen_ports_free(run_id).await;
    }

    // ---------- capture ----------

    pub async fn capture_start(
        &self,
        token: &str,
        port: &str,
        bpf: &str,
        seconds: Option<u32>,
        max_packets: Option<u64>,
    ) -> Result<Value> {
        let cfg_port = self.cfg.port_find(port)?.clone();
        self.leases.lock().await.require(token, &cfg_port.label)?;
        let endpoint = self.endpoint_require(&cfg_port.label).await?;

        if let Some(existing) = self.capture_on(&cfg_port.label).await {
            return Err(CoreError::Rejected(format!(
                "{} already has capture {existing} running; stop it first",
                cfg_port.label
            )));
        }

        let spec = CaptureSpec {
            bpf: bpf.to_string(),
            seconds,
            max_packets,
            snaplen: crate::capture::DEFAULT_SNAPLEN,
        };
        let mut capture = Capture::new(
            &cfg_port.label,
            &endpoint.netns,
            &endpoint.dev,
            spec,
            &self.cfg.captures_dir,
        )?;
        capture.start().await?;
        let state = capture.state().await;
        self.captures.lock().await.insert(capture.capture_id.clone(), capture);
        Ok(state)
    }

    pub async fn capture_stop(&self, capture_id: &str) -> Result<Value> {
        let mut captures = self.captures.lock().await;
        let capture = captures
            .get_mut(capture_id)
            .ok_or_else(|| CoreError::Rejected(format!("unknown capture {capture_id}")))?;
        Ok(capture.stop().await)
    }

    pub async fn capture_status(&self, capture_id: &str) -> Result<Value> {
        let mut captures = self.captures.lock().await;
        let capture = captures
            .get_mut(capture_id)
            .ok_or_else(|| CoreError::Rejected(format!("unknown capture {capture_id}")))?;
        Ok(capture.state().await)
    }

    pub async fn capture_decode(&self, capture_id: &str, limit: usize, verbose: bool) -> Result<Value> {
        let captures = self.captures.lock().await;
        let capture = captures
            .get(capture_id)
            .ok_or_else(|| CoreError::Rejected(format!("unknown capture {capture_id}")))?;
        Ok(json!({
            "capture_id": capture_id,
            "port": capture.port,
            "packets": capture.packets_count().await,
            "shown": limit,
            "lines": capture.decode(limit, verbose).await,
        }))
    }

    pub async fn captures_list(&self) -> Vec<Value> {
        let mut captures = self.captures.lock().await;
        let mut out = Vec::with_capacity(captures.len());
        for capture in captures.values_mut() {
            out.push(capture.state().await);
        }
        out
    }

    async fn capture_on(&self, label: &str) -> Option<String> {
        let mut captures = self.captures.lock().await;
        for capture in captures.values_mut() {
            if capture.port == label && capture.running() {
                return Some(capture.capture_id.clone());
            }
        }
        None
    }

    // ---------- echo ----------

    /// An echo service whose reply states the address that actually arrived,
    /// which is how a client learns what a device translated it to.
    pub async fn echo_start(
        &self,
        token: &str,
        port: &str,
        udp_port: u16,
        tcp_port: u16,
        family: &str,
    ) -> Result<Value> {
        let cfg_port = self.cfg.port_find(port)?.clone();
        self.leases.lock().await.require(token, &cfg_port.label)?;
        let endpoint = self.endpoint_require(&cfg_port.label).await?;

        if let Some(existing) = self.echo_on(&cfg_port.label).await {
            return Err(CoreError::Rejected(format!(
                "{} already runs echo {existing}; stop it first",
                cfg_port.label
            )));
        }
        let addresses = netns::addrs_get(Some(&endpoint.netns), &endpoint.dev).await;
        let bind = endpoint_address(&addresses, family)?;

        let mut service = EchoService::new(
            &cfg_port.label,
            &endpoint.netns,
            &bind,
            udp_port,
            tcp_port,
            &self.cfg.state_dir.join("echo"),
        )?;
        service.start().await?;
        let state = service.state();
        self.echoes.lock().await.insert(service.echo_id.clone(), service);
        Ok(state)
    }

    pub async fn echo_stop(&self, echo_id: &str) -> Result<Value> {
        let mut echoes = self.echoes.lock().await;
        let service = echoes
            .get_mut(echo_id)
            .ok_or_else(|| CoreError::Rejected(format!("unknown echo service {echo_id}")))?;
        Ok(service.stop().await)
    }

    pub async fn echo_observations(&self, echo_id: &str) -> Result<Value> {
        let echoes = self.echoes.lock().await;
        let service = echoes
            .get(echo_id)
            .ok_or_else(|| CoreError::Rejected(format!("unknown echo service {echo_id}")))?;
        let mut out = service.state();
        out["observations"] = serde_json::to_value(service.observations()).unwrap_or(Value::Null);
        Ok(out)
    }

    pub async fn echoes_list(&self) -> Vec<Value> {
        self.echoes.lock().await.values().map(|s| s.state()).collect()
    }

    async fn echo_on(&self, label: &str) -> Option<String> {
        let mut echoes = self.echoes.lock().await;
        for service in echoes.values_mut() {
            if service.port == label && service.running() {
                return Some(service.echo_id.clone());
            }
        }
        None
    }

    // ---------- injection ----------

    /// Send crafted frames out of a port.
    pub async fn inject_frames(&self, token: &str, port: &str, mut spec: Value) -> Result<Value> {
        let cfg_port = self.cfg.port_find(port)?.clone();
        self.leases.lock().await.require(token, &cfg_port.label)?;
        let endpoint = self.endpoint_require(&cfg_port.label).await?;

        // A crafted bad checksum is recomputed by the NIC unless TX checksum
        // offload is off, so the frame would leave valid and the test would pass
        // for the wrong reason.
        let wants_malformed = spec["bad_checksum"].as_bool().unwrap_or(false)
            || spec["zero_checksum"].as_bool().unwrap_or(false);
        if wants_malformed {
            let offloads = netns::offloads_get(Some(&endpoint.netns), &cfg_port.iface).await;
            let state = offloads.get("tx_checksum").map(String::as_str).unwrap_or("unknown");
            if !matches!(state, "off" | "fixed-off") {
                return Err(CoreError::Rejected(format!(
                    "tx_checksum is {state} on {}, so the NIC would recompute the checksum and the \
                     frame would leave valid. Call port_offloads with {{\"tx_checksum\": false}} \
                     first, and turn it back on afterwards.",
                    cfg_port.iface
                )));
            }
        }

        spec["iface"] = endpoint.dev.clone().into();
        // Resolve the next hop unless the caller named one. Broadcast reaches a
        // directly cabled peer but a device will not forward it.
        if spec["dst_mac"].as_str().is_none() {
            if let Some(dst_ip) = spec["dst_ip"].as_str() {
                match netns::neigh_mac_get(Some(&endpoint.netns), dst_ip).await {
                    Some(mac) => spec["dst_mac"] = mac.into(),
                    None => spec["dst_mac_fallback"] = "broadcast".into(),
                }
            }
        }
        let mut child = crate::engines::probe::helper_spawn(&endpoint.netns, "inject")
            .map_err(|e| CoreError::Rejected(e.to_string()))?;
        crate::engines::probe::stdin_write(&mut child, &spec)
            .await
            .map_err(|e| CoreError::Rejected(e.to_string()))?;
        let output = child
            .wait_with_output()
            .await
            .map_err(|e| CoreError::Rejected(format!("injector failed: {e}")))?;

        let text = String::from_utf8_lossy(&output.stdout);
        let parsed = crate::engines::probe::json_tail(&text).ok_or_else(|| {
            CoreError::Rejected(format!(
                "injector returned no result: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        })?;
        if let Some(message) = parsed["error"].as_str() {
            return Err(CoreError::Rejected(message.to_string()));
        }
        let mut out = parsed;
        if let Some(mac) = spec["dst_mac"].as_str() {
            out["dst_mac"] = mac.into();
        }
        if spec.get("dst_mac_fallback").is_some() {
            out["dst_mac"] = "ff:ff:ff:ff:ff:ff".into();
            out["detail"] = format!(
                "no neighbour entry for {}, so the frames went to broadcast; a device will not \
                 forward those, pass dst_mac explicitly for a forwarding test",
                spec["dst_ip"].as_str().unwrap_or("the destination")
            )
            .into();
        }
        out["port"] = cfg_port.label.into();
        out["dev"] = endpoint.dev.into();
        Ok(out)
    }

    // ---------- endpoints ----------

    #[allow(clippy::too_many_arguments)]
    pub async fn endpoint_create(
        &self,
        token: &str,
        reference: &str,
        ipv4: Option<String>,
        gateway4: Option<String>,
        ipv6: Option<String>,
        gateway6: Option<String>,
        vlan: Option<u16>,
        vlan_s: Option<u16>,
        mtu: Option<u32>,
    ) -> Result<Value> {
        let port = self.cfg.port_find(reference)?.clone();
        self.leases.lock().await.require(token, &port.label)?;
        if ipv4.is_none() && ipv6.is_none() {
            return Err(CoreError::Rejected(
                "an endpoint needs at least one of ipv4 or ipv6".into(),
            ));
        }
        cidr_check(ipv4.as_deref(), 4, "ipv4")?;
        cidr_check(ipv6.as_deref(), 6, "ipv6")?;
        addr_check(gateway4.as_deref(), 4, "gateway4")?;
        addr_check(gateway6.as_deref(), 6, "gateway6")?;
        for (name, vid) in [("vlan", vlan), ("vlan_s", vlan_s)] {
            if let Some(vid) = vid {
                if !(1..=4094).contains(&vid) {
                    return Err(CoreError::Rejected(format!("{name} {vid} out of range 1..4094")));
                }
            }
        }
        if vlan_s.is_some() && vlan.is_none() {
            return Err(CoreError::Rejected(
                "vlan_s is the outer 802.1ad tag, so vlan must carry the inner 802.1Q tag too".into(),
            ));
        }
        if let Some(mtu) = mtu {
            if !(576..=9216).contains(&mtu) {
                return Err(CoreError::Rejected(format!("mtu {mtu} out of range 576..9216")));
            }
        }

        let ns = self.cfg.netns_of(&port);
        netns::ns_create(&ns).await?;
        netns::port_adopt(&port.iface, &ns).await?;
        netns::link_up_set(Some(&ns), &port.iface, true).await?;

        let mut dev = port.iface.clone();
        if let Some(svid) = vlan_s {
            dev = netns::vlan_add(
                Some(&ns),
                &dev,
                svid,
                "802.1ad",
                Some(&format!("{}.{svid}", port.label)),
            )
            .await?;
            netns::link_up_set(Some(&ns), &dev, true).await?;
        }
        if let Some(cvid) = vlan {
            let name = match vlan_s {
                None => format!("{dev}.{cvid}"),
                Some(svid) => format!("{}.{svid}.{cvid}", port.label),
            };
            dev = netns::vlan_add(Some(&ns), &dev, cvid, "802.1Q", Some(&name)).await?;
            netns::link_up_set(Some(&ns), &dev, true).await?;
        }
        if let Some(mtu) = mtu {
            netns::link_mtu_set(Some(&ns), &dev, mtu).await?;
        }

        netns::addr_flush(Some(&ns), &dev).await;
        for cidr in [ipv4.as_deref(), ipv6.as_deref()].into_iter().flatten() {
            netns::addr_add(Some(&ns), &dev, cidr).await?;
        }
        for gateway in [gateway4.as_deref(), gateway6.as_deref()].into_iter().flatten() {
            netns::route_default_add(Some(&ns), gateway, &dev).await?;
        }

        let endpoint = Endpoint {
            port: port.label.clone(),
            iface: port.iface.clone(),
            dev: dev.clone(),
            netns: ns.clone(),
            ipv4,
            ipv6,
            gateway4,
            gateway6,
            vlan,
            vlan_s,
            mtu,
            created_at: crate::leases::now_s(),
        };
        tracing::info!(port = %port.label, %dev, %ns, "endpoint created");
        self.endpoints.lock().await.insert(port.label.clone(), endpoint);
        self.endpoints_save().await;
        self.endpoint_state(&port.label).await
    }

    pub async fn endpoint_destroy(&self, token: &str, reference: &str) -> Result<Value> {
        let port = self.cfg.port_find(reference)?.clone();
        self.leases.lock().await.require(token, &port.label)?;
        self.endpoint_teardown(&port.label).await?;
        Ok(json!({"port": port.label, "destroyed": true}))
    }

    pub async fn endpoint_state(&self, reference: &str) -> Result<Value> {
        let port = self.cfg.port_find(reference)?.clone();
        let declared = self.endpoints.lock().await.get(&port.label).cloned();
        let Some(declared) = declared else {
            return Ok(json!({"port": port.label, "exists": false}));
        };
        let state = netns::link_state_get(Some(&declared.netns), &declared.dev).await;
        Ok(json!({
            "port": port.label,
            "exists": true,
            "declared": declared,
            "netns": declared.netns,
            "dev": declared.dev,
            "addresses": netns::addrs_get(Some(&declared.netns), &declared.dev).await,
            "carrier": state["carrier"],
            "speed_mbps": state["speed_mbps"],
            "operstate": state["operstate"],
        }))
    }

    pub async fn endpoints_list(&self) -> Result<Vec<Value>> {
        let labels: Vec<String> = self.endpoints.lock().await.keys().cloned().collect();
        let mut out = Vec::with_capacity(labels.len());
        for label in labels {
            out.push(self.endpoint_state(&label).await?);
        }
        Ok(out)
    }

    /// Where a flow must originate and land, resolved for the engines.
    pub async fn endpoint_require(&self, label: &str) -> Result<Endpoint> {
        self.endpoints
            .lock()
            .await
            .get(label)
            .cloned()
            .ok_or_else(|| {
                CoreError::Rejected(format!("port {label} has no endpoint; call endpoint_create first"))
            })
    }

    async fn endpoint_teardown(&self, label: &str) -> Result<()> {
        let port = self.cfg.port_find(label)?.clone();
        let ns = self.cfg.netns_of(&port);
        // Both live inside the namespace about to be deleted, so they are
        // stopped first rather than killed by the kernel mid-write.
        for capture in self.captures.lock().await.values_mut() {
            if capture.port == label {
                capture.kill();
            }
        }
        for service in self.echoes.lock().await.values_mut() {
            if service.port == label {
                service.kill();
            }
        }
        netns::port_release(&port.iface, &ns).await?;
        netns::ns_delete(&ns).await?;
        if self.endpoints.lock().await.remove(label).is_some() {
            self.endpoints_save().await;
        }
        tracing::info!(port = %label, iface = %port.iface, "endpoint torn down");
        Ok(())
    }

    /// The namespace holding the port, or None while it is still on the host.
    pub async fn port_ns(&self, port: &PortConfig) -> Option<String> {
        let ns = self.cfg.netns_of(port);
        if netns::ns_exists(&ns) && netns::link_names(Some(&ns)).await.contains(&port.iface) {
            Some(ns)
        } else {
            None
        }
    }

    pub async fn lease_owner_for(&self, token: &str, port: &str) -> Result<String> {
        Ok(self.leases.lock().await.require(token, port)?.owner.clone())
    }

    async fn endpoints_save(&self) {
        let endpoints = self.endpoints.lock().await;
        let Ok(text) = serde_json::to_string_pretty(&*endpoints) else {
            return;
        };
        let tmp = self.endpoints_path.with_extension("tmp");
        if std::fs::write(&tmp, text).is_ok() {
            let _ = std::fs::rename(&tmp, &self.endpoints_path);
        }
    }
}

fn endpoints_load(path: &PathBuf) -> BTreeMap<String, Endpoint> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    match serde_json::from_str(&text) {
        Ok(map) => map,
        Err(err) => {
            tracing::warn!(%err, "discarding unreadable endpoint state");
            BTreeMap::new()
        }
    }
}

fn speed_verdict(mut state: Value, expect_mbps: Option<u32>) -> Value {
    let Some(expected) = expect_mbps else {
        return state;
    };
    let actual = state["speed_mbps"].as_u64().map(|v| v as u32);
    state["expected_mbps"] = expected.into();
    state["speed_match"] = (actual == Some(expected)).into();
    if actual != Some(expected) {
        let supported = state["supported_modes"].clone();
        state["detail"] = format!(
            "negotiated {actual:?} Mbps, expected {expected}; host port supports {supported}"
        )
        .into();
    }
    state
}

pub fn mac_valid(mac: &str) -> bool {
    let parts: Vec<&str> = mac.split(':').collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

fn cidr_check(value: Option<&str>, version: u8, field: &str) -> Result<()> {
    let Some(value) = value else { return Ok(()) };
    let Some((addr, prefix)) = value.split_once('/') else {
        return Err(CoreError::Rejected(format!(
            "{field}: {value:?} needs an explicit prefix length, for example {value}/24"
        )));
    };
    let parsed: IpAddr = addr.parse().map_err(|_| {
        CoreError::Rejected(format!("{field}: {value:?} is not a valid address/prefix"))
    })?;
    let bits: u8 = prefix.parse().map_err(|_| {
        CoreError::Rejected(format!("{field}: {value:?} has a non-numeric prefix length"))
    })?;
    let (want_v4, max) = (version == 4, if version == 4 { 32 } else { 128 });
    if parsed.is_ipv4() != want_v4 {
        return Err(CoreError::Rejected(format!(
            "{field}: {value:?} is the wrong address family, expected IPv{version}"
        )));
    }
    if bits > max {
        return Err(CoreError::Rejected(format!(
            "{field}: prefix length {bits} exceeds {max}"
        )));
    }
    Ok(())
}

fn addr_check(value: Option<&str>, version: u8, field: &str) -> Result<()> {
    let Some(value) = value else { return Ok(()) };
    let parsed: IpAddr = value
        .parse()
        .map_err(|_| CoreError::Rejected(format!("{field}: {value:?} is not a valid address")))?;
    if parsed.is_ipv4() != (version == 4) {
        return Err(CoreError::Rejected(format!(
            "{field}: {value:?} is the wrong address family, expected IPv{version}"
        )));
    }
    Ok(())
}

/// Pick the endpoint address of the requested family, for an engine to target.
pub fn endpoint_address(addresses: &[String], family: &str) -> Result<String> {
    if !matches!(family, "ipv4" | "ipv6") {
        return Err(CoreError::Rejected(format!(
            "family must be 'ipv4' or 'ipv6', got {family:?}"
        )));
    }
    let want_v4 = family == "ipv4";
    for cidr in addresses {
        let bare = cidr.split('/').next().unwrap_or(cidr);
        if let Ok(parsed) = bare.parse::<IpAddr>() {
            if parsed.is_ipv4() == want_v4 {
                return Ok(bare.to_string());
            }
        }
    }
    Err(CoreError::Rejected(format!(
        "endpoint has no {family} address; it has {addresses:?}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_validation() {
        assert!(mac_valid("3c:fd:fe:97:8e:98"));
        assert!(mac_valid("02:DE:AD:BE:EF:01"));
        assert!(!mac_valid("3c:fd:fe:97:8e"));
        assert!(!mac_valid("3c-fd-fe-97-8e-98"));
        assert!(!mac_valid("3c:fd:fe:97:8e:9z"));
        assert!(!mac_valid(""));
    }

    #[test]
    fn cidr_needs_a_prefix() {
        let err = cidr_check(Some("192.168.1.5"), 4, "ipv4").unwrap_err().to_string();
        assert!(err.contains("needs an explicit prefix length"), "{err}");
    }

    #[test]
    fn cidr_family_is_checked() {
        assert!(cidr_check(Some("10.0.0.1/24"), 4, "ipv4").is_ok());
        assert!(cidr_check(Some("fd00::1/64"), 6, "ipv6").is_ok());
        let err = cidr_check(Some("fd00::1/64"), 4, "ipv4").unwrap_err().to_string();
        assert!(err.contains("wrong address family"), "{err}");
    }

    #[test]
    fn cidr_prefix_bounds_checked() {
        assert!(cidr_check(Some("10.0.0.1/33"), 4, "ipv4").is_err());
        assert!(cidr_check(Some("fd00::1/129"), 6, "ipv6").is_err());
        assert!(cidr_check(None, 4, "ipv4").is_ok());
    }

    #[test]
    fn gateway_must_be_bare() {
        assert!(addr_check(Some("10.0.0.254"), 4, "gateway4").is_ok());
        assert!(addr_check(Some("10.0.0.254/24"), 4, "gateway4").is_err());
    }

    #[test]
    fn endpoint_address_picks_the_family() {
        let addresses = vec!["10.80.0.1/24".to_string(), "fd00:80::1/64".to_string()];
        assert_eq!(endpoint_address(&addresses, "ipv4").unwrap(), "10.80.0.1");
        assert_eq!(endpoint_address(&addresses, "ipv6").unwrap(), "fd00:80::1");
    }

    #[test]
    fn endpoint_address_reports_what_it_has() {
        let addresses = vec!["10.80.0.1/24".to_string()];
        let err = endpoint_address(&addresses, "ipv6").unwrap_err().to_string();
        assert!(err.contains("no ipv6 address"), "{err}");
        assert!(err.contains("10.80.0.1/24"), "{err}");
        assert!(endpoint_address(&addresses, "ipx").is_err());
    }

    #[test]
    fn speed_verdict_flags_a_mismatch_with_what_the_port_supports() {
        let state = json!({"speed_mbps": 1000, "supported_modes": ["100baseT/Full", "1000baseT/Full"]});
        let out = speed_verdict(state, Some(2500));
        assert_eq!(out["speed_match"], false);
        assert!(out["detail"].as_str().unwrap().contains("1000baseT/Full"));
    }

    #[test]
    fn speed_verdict_is_quiet_when_it_matches() {
        let state = json!({"speed_mbps": 10000});
        let out = speed_verdict(state, Some(10000));
        assert_eq!(out["speed_match"], true);
        assert!(out.get("detail").is_none());
    }

    fn core() -> (Arc<Core>, tempdir::TempDir) {
        let dir = tempdir::TempDir::new("tgen-core").unwrap();
        // Its own prefix, so a test never sees the namespaces of a daemon
        // running on the same machine.
        let text = format!(
            r#"{{
                "state_dir": {:?},
                "runs_dir": {:?},
                "netns_prefix": "tgen-test-{}-",
                "ports": [{{"label": "p0", "iface": "eth0"}}, {{"label": "p1", "iface": "eth1"}}],
                "mcp": {{"host": "127.0.0.1", "port": 9140, "path": "/mcp", "token": "t"}}
            }}"#,
            dir.path().join("state"),
            dir.path().join("runs"),
            std::process::id(),
        );
        let cfg = crate::config::config_parse(&text, dir.path()).unwrap();
        (Arc::new(Core::new(cfg).unwrap()), dir)
    }

    #[tokio::test]
    async fn concurrent_runs_get_distinct_listen_ports() {
        let (core, _dir) = core();
        assert_eq!(core.listen_port_take(25201).await.unwrap(), 25201);
        assert_eq!(core.listen_port_take(25201).await.unwrap(), 25202);
        assert_eq!(core.listen_port_take(25201).await.unwrap(), 25203);
    }

    #[tokio::test]
    async fn reaping_a_run_returns_exactly_its_ports() {
        let (core, _dir) = core();
        let first = core.listen_port_take(25501).await.unwrap();
        let second = core.listen_port_take(25502).await.unwrap();
        core.listen_ports_record("run-a", vec![first, second]).await;
        let other = core.listen_port_take(25501).await.unwrap();
        core.listen_ports_record("run-b", vec![other]).await;

        core.listen_ports_free("run-a").await;
        assert_eq!(core.ports_in_use.lock().await.len(), 1);
        assert_eq!(core.listen_port_take(25501).await.unwrap(), first);
    }

    #[tokio::test]
    async fn freeing_an_unknown_run_is_harmless() {
        let (core, _dir) = core();
        let port = core.listen_port_take(25301).await.unwrap();
        core.listen_ports_record("run-a", vec![port]).await;
        core.listen_ports_free("never-existed").await;
        assert!(core.ports_in_use.lock().await.contains(&port));
    }

    #[tokio::test]
    async fn reconcile_reports_every_category_it_can_return() {
        let (core, _dir) = core();
        let state = core.reconcile().await;
        for key in ["orphans_cleaned", "kept_under_lease", "teardown_failed", "foreign", "strays"] {
            assert!(state[key].is_array(), "{key} missing from {state}");
            assert!(state[key].as_array().unwrap().is_empty(), "{key} in {state}");
        }
    }

    #[tokio::test]
    async fn exhausting_the_window_is_rejected_with_the_range() {
        let (core, _dir) = core();
        for _ in 0..64 {
            core.listen_port_take(25201).await.unwrap();
        }
        let err = core.listen_port_take(25201).await.unwrap_err().to_string();
        assert!(err.contains("25201..25265"), "{err}");
    }
}
