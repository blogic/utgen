// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

//! `tgen`, the command-line client.
//!
//! Talks to the daemon over its MCP endpoint rather than driving netns and
//! ethtool itself, so the daemon stays the only owner of leases, namespaces and
//! capture processes.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use tgend::config::{config_load, Config, ConfigError, CONFIG_ENV_VAR};

const TOKEN_FILE: &str = "cli-lease";
const POLL: Duration = Duration::from_millis(1500);
const CALL_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Parser, Debug)]
#[command(name = "tgen", about = "traffic-generator client")]
struct Args {
    #[arg(long, help = "config path (default $TGEN_CONFIG)")]
    config: Option<PathBuf>,
    #[arg(long, help = "daemon address, if not the configured one")]
    host: Option<String>,
    #[arg(long, help = "lease token, if not the saved one")]
    token: Option<String>,
    #[arg(short, long, help = "raw JSON output")]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// List the port pool with live link state.
    Ports,
    /// Claim and release ports.
    Lease {
        #[command(subcommand)]
        action: LeaseAction,
    },
    /// Address a port inside its namespace.
    Endpoint {
        #[command(subcommand)]
        action: EndpointAction,
    },
    /// Wait for carrier and report the negotiated speed.
    LinkWait {
        port: String,
        #[arg(long, default_value = "30")]
        timeout: f64,
        #[arg(long, help = "assert this speed in Mbps")]
        expect: Option<u32>,
    },
    /// Throughput flow through the device, via iperf3.
    Traffic {
        src: String,
        dst: String,
        #[arg(long, default_value = "tcp")]
        proto: String,
        #[arg(long, default_value = "10")]
        duration: u32,
        #[arg(long)]
        bitrate: Option<String>,
        #[arg(long, default_value = "1")]
        streams: u32,
        #[arg(long)]
        reverse: bool,
        #[arg(long)]
        bidir: bool,
    },
    /// Small-frame packet rate, via trafgen.
    Pps {
        src: String,
        dst: String,
        #[arg(long, default_value = "64")]
        frame_bytes: u32,
        #[arg(long, default_value = "10")]
        duration: u32,
        #[arg(long, default_value = "4")]
        cpus: u32,
        #[arg(long)]
        rate: Option<String>,
        #[arg(long, default_value = "1")]
        src_mac_count: u32,
    },
    /// One-way delay, loss and reordering.
    Probe {
        src: String,
        dst: String,
        #[arg(long, default_value = "10")]
        duration: u32,
        #[arg(long, default_value = "1000")]
        rate: f64,
        #[arg(long, default_value = "200")]
        packet_size: u32,
    },
    /// Many concurrent flows, for flow-table fill.
    Flows {
        src: String,
        dst: String,
        #[arg(long, default_value = "1000")]
        count: u64,
        #[arg(long, default_value = "tcp")]
        proto: String,
        #[arg(long, default_value = "30")]
        duration: u32,
        #[arg(long)]
        churn: bool,
    },
    /// Capture on a port and optionally decode.
    Capture {
        port: String,
        bpf: Option<String>,
        #[arg(long, default_value = "10")]
        seconds: u32,
        #[arg(long, help = "decode the first N packets")]
        decode: Option<usize>,
    },
    /// List recent runs.
    Runs {
        #[arg(long, default_value = "25")]
        limit: usize,
    },
    /// Call any tool directly.
    Call {
        tool: String,
        #[arg(help = "JSON object")]
        arguments: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum LeaseAction {
    Acquire {
        ports: Vec<String>,
        #[arg(long)]
        owner: Option<String>,
        #[arg(long, default_value = "3600")]
        ttl: f64,
        #[arg(long, default_value = "")]
        note: String,
    },
    Release,
    Renew {
        #[arg(long, default_value = "3600")]
        ttl: f64,
    },
    List,
}

#[derive(Subcommand, Debug)]
enum EndpointAction {
    Create {
        port: String,
        #[arg(long)]
        ipv4: Option<String>,
        #[arg(long)]
        gateway4: Option<String>,
        #[arg(long)]
        ipv6: Option<String>,
        #[arg(long)]
        gateway6: Option<String>,
        #[arg(long)]
        vlan: Option<u16>,
        #[arg(long, help = "outer 802.1ad service tag for QinQ")]
        vlan_s: Option<u16>,
        #[arg(long)]
        mtu: Option<u32>,
    },
    Destroy {
        port: String,
    },
    List,
}

struct Client {
    url: String,
    token: String,
    cfg: Config,
    id: std::cell::Cell<u64>,
}

impl Client {
    fn new(cfg: Config, host: Option<String>) -> Self {
        let bind = host.unwrap_or_else(|| match cfg.mcp.host.as_str() {
            "0.0.0.0" | "::" => "127.0.0.1".to_string(),
            other => other.to_string(),
        });
        Self {
            url: format!("http://{bind}:{}{}", cfg.mcp.port, cfg.mcp.path),
            token: cfg.mcp.token.clone(),
            cfg,
            id: std::cell::Cell::new(0),
        }
    }

    fn call(&self, tool: &str, arguments: Value) -> anyhow::Result<Value> {
        self.id.set(self.id.get() + 1);
        let body = json!({
            "jsonrpc": "2.0",
            "id": self.id.get(),
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        });
        let reply: Value = ureq::post(&self.url)
            .header("Authorization", &format!("Bearer {}", self.token))
            .header("Accept", "application/json, text/event-stream")
            .config()
            .timeout_global(Some(CALL_TIMEOUT))
            .build()
            .send_json(&body)
            .map_err(|e| anyhow::anyhow!("cannot reach tgend at {}: {e}", self.url))?
            .body_mut()
            .read_json()?;

        if let Some(error) = reply.get("error") {
            anyhow::bail!("{tool}: {}", error["message"].as_str().unwrap_or("unknown error"));
        }
        let result = &reply["result"];
        if result["isError"].as_bool() == Some(true) {
            anyhow::bail!(
                "{}",
                result["content"][0]["text"].as_str().unwrap_or("tool failed")
            );
        }
        if let Some(structured) = result.get("structuredContent") {
            if let Some(inner) = structured.get("result") {
                return Ok(inner.clone());
            }
            return Ok(structured.clone());
        }
        let blocks: Vec<Value> = result["content"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter(|item| item["type"] == "text")
                    .filter_map(|item| serde_json::from_str(item["text"].as_str()?).ok())
                    .collect()
            })
            .unwrap_or_default();
        Ok(match blocks.len() {
            1 => blocks.into_iter().next().expect("checked length"),
            _ => Value::Array(blocks),
        })
    }

    fn token_path(&self) -> PathBuf {
        self.cfg.state_dir.join(TOKEN_FILE)
    }

    fn token_load(&self, explicit: Option<&String>) -> anyhow::Result<String> {
        if let Some(token) = explicit {
            return Ok(token.clone());
        }
        std::fs::read_to_string(self.token_path())
            .map(|text| text.trim().to_string())
            .map_err(|_| {
                anyhow::anyhow!("no lease held; run 'tgen lease acquire <ports>' first, or pass --token")
            })
    }
}

/// A JSON value as a bare table cell: no quotes, and "-" for absent.
fn cell(value: &Value) -> String {
    match value {
        Value::Null => "-".into(),
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn emit(value: &Value) {
    println!("{}", serde_json::to_string_pretty(value).unwrap_or_default());
}

fn run_and_wait(client: &Client, tool: &str, arguments: Value, quiet: bool) -> anyhow::Result<Value> {
    let started = client.call(tool, arguments)?;
    let run_id = started["run_id"].as_str().unwrap_or_default().to_string();
    if !quiet {
        eprintln!("run {run_id} started, {}s", started["duration_s"]);
    }
    loop {
        std::thread::sleep(POLL);
        let status = client.call("traffic_status", json!({"run_id": run_id}))?;
        if status["status"] != "running" {
            return Ok(status);
        }
        if !quiet {
            if let Some(live) = status.get("live") {
                eprintln!(
                    "  {} Mbps, interval {}",
                    cell(&live["mbps"]),
                    cell(&live["intervals"])
                );
            }
        }
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let cfg = match config_load(args.config.clone()) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("tgen: {err}");
            if matches!(err, ConfigError::Missing { .. }) {
                eprintln!("tgen: set ${CONFIG_ENV_VAR} or pass --config");
            }
            std::process::exit(2);
        }
    };
    let client = Client::new(cfg, args.host.clone());

    match dispatch(&client, &args) {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("tgen: {err}");
            std::process::exit(1);
        }
    }
}

fn dispatch(client: &Client, args: &Args) -> anyhow::Result<i32> {
    match &args.command {
        Command::Ports => {
            let ports = client.call("ports_list", json!({}))?;
            if args.json {
                emit(&ports);
                return Ok(0);
            }
            println!(
                "{:5} {:14} {:>7} {:8} {:>7} {:8} owner",
                "port", "iface", "speed", "carrier", "max", "claimed"
            );
            for port in ports.as_array().unwrap_or(&Vec::new()) {
                // Formatted through plain strings: a width specifier has no
                // effect on serde_json::Value, and its Display keeps the quotes.
                println!(
                    "{:5} {:14} {:>7} {:8} {:>7} {:8} {}",
                    port["label"].as_str().unwrap_or("?"),
                    port["iface"].as_str().unwrap_or(""),
                    cell(&port["speed_mbps"]),
                    cell(&port["carrier"]),
                    cell(&port["max_speed_mbps"]),
                    cell(&port["claimed"]),
                    port["lease_owner"].as_str().unwrap_or("-"),
                );
            }
            Ok(0)
        }
        Command::Lease { action } => lease(client, args, action),
        Command::Endpoint { action } => endpoint(client, args, action),
        Command::LinkWait { port, timeout, expect } => {
            let out = client.call(
                "link_wait",
                json!({"port": port, "timeout_s": timeout, "expect_mbps": expect}),
            )?;
            println!(
                "{port}: {} speed={} duplex={} match={}",
                out["link_wait"].as_str().unwrap_or("?"),
                cell(&out["speed_mbps"]),
                cell(&out["duplex"]),
                cell(&out["speed_match"])
            );
            if let Some(detail) = out["detail"].as_str() {
                println!("  {detail}");
            }
            let good = out["link_wait"] == "up" && out["speed_match"] != false;
            Ok(if good { 0 } else { 1 })
        }
        Command::Traffic { src, dst, proto, duration, bitrate, streams, reverse, bidir } => {
            let status = run_and_wait(client, "traffic_start", json!({
                "token": client.token_load(args.token.as_ref())?,
                "src": src, "dst": dst, "proto": proto, "duration_s": duration,
                "bitrate": bitrate, "streams": streams, "reverse": reverse, "bidir": bidir,
            }), args.json)?;
            emit(if args.json { &status["summary"] } else { &status });
            Ok(if status["status"] == "done" { 0 } else { 1 })
        }
        Command::Pps { src, dst, frame_bytes, duration, cpus, rate, src_mac_count } => {
            let status = run_and_wait(client, "pps_start", json!({
                "token": client.token_load(args.token.as_ref())?,
                "src": src, "dst": dst, "frame_bytes": frame_bytes,
                "duration_s": duration, "cpus": cpus, "rate": rate,
                "src_mac_count": src_mac_count,
            }), args.json)?;
            emit(if args.json { &status["summary"] } else { &status });
            Ok(if status["status"] == "done" { 0 } else { 1 })
        }
        Command::Probe { src, dst, duration, rate, packet_size } => {
            let status = run_and_wait(client, "probe_start", json!({
                "token": client.token_load(args.token.as_ref())?,
                "src": src, "dst": dst, "duration_s": duration,
                "rate_pps": rate, "packet_size": packet_size,
            }), args.json)?;
            emit(if args.json { &status["summary"] } else { &status });
            Ok(if status["status"] == "done" { 0 } else { 1 })
        }
        Command::Flows { src, dst, count, proto, duration, churn } => {
            let status = run_and_wait(client, "flows_start", json!({
                "token": client.token_load(args.token.as_ref())?,
                "src": src, "dst": dst, "count": count, "proto": proto,
                "duration_s": duration, "churn": churn,
            }), args.json)?;
            emit(if args.json { &status["summary"] } else { &status });
            Ok(if status["status"] == "done" { 0 } else { 1 })
        }
        Command::Capture { port, bpf, seconds, decode } => {
            let started = client.call("capture_start", json!({
                "token": client.token_load(args.token.as_ref())?,
                "port": port, "bpf": bpf.clone().unwrap_or_default(), "seconds": seconds,
            }))?;
            let capture_id = started["capture_id"].as_str().unwrap_or_default().to_string();
            eprintln!("capture {capture_id} on {port}, {seconds}s");
            std::thread::sleep(Duration::from_secs(*seconds as u64));
            let stopped = client.call("capture_stop", json!({"capture_id": capture_id}))?;
            eprintln!(
                "{} packets, pcap at {}",
                cell(&stopped["packets"]),
                cell(&stopped["pcap"])
            );
            if let Some(limit) = decode {
                let decoded = client.call("capture_decode", json!({"capture_id": capture_id, "limit": limit}))?;
                for line in decoded["lines"].as_array().unwrap_or(&Vec::new()) {
                    println!("{}", line.as_str().unwrap_or(""));
                }
            }
            Ok(0)
        }
        Command::Runs { limit } => {
            emit(&client.call("runs_list", json!({"limit": limit}))?);
            Ok(0)
        }
        Command::Call { tool, arguments } => {
            let parsed: Value = match arguments {
                None => json!({}),
                Some(text) => serde_json::from_str(text)
                    .map_err(|e| anyhow::anyhow!("arguments must be JSON: {e}"))?,
            };
            emit(&client.call(tool, parsed)?);
            Ok(0)
        }
    }
}

fn lease(client: &Client, args: &Args, action: &LeaseAction) -> anyhow::Result<i32> {
    match action {
        LeaseAction::Acquire { ports, owner, ttl, note } => {
            let owner = owner.clone().unwrap_or_else(|| {
                let host = std::fs::read_to_string("/etc/hostname")
                    .map(|text| text.trim().to_string())
                    .unwrap_or_else(|_| "host".into());
                format!("tgen-cli@{host}")
            });
            let lease = client.call("lease_acquire", json!({
                "owner": owner, "ports": ports, "ttl_s": ttl, "note": note,
            }))?;
            let path = client.token_path();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, lease["token"].as_str().unwrap_or_default())?;
            println!(
                "lease {}... on {} for {}s",
                &lease["token"].as_str().unwrap_or("")[..8.min(lease["token"].as_str().unwrap_or("").len())],
                lease["ports"],
                lease["ttl_remaining_s"]
            );
            println!("token saved to {}", path.display());
            Ok(0)
        }
        LeaseAction::Release => {
            let out = client.call("lease_release", json!({"token": client.token_load(args.token.as_ref())?}))?;
            let _ = std::fs::remove_file(client.token_path());
            println!("released, ports freed: {}", cell(&out["ports_freed"]));
            Ok(0)
        }
        LeaseAction::Renew { ttl } => {
            let lease = client.call("lease_renew", json!({
                "token": client.token_load(args.token.as_ref())?, "ttl_s": ttl,
            }))?;
            println!("renewed, {}s remaining", lease["ttl_remaining_s"]);
            Ok(0)
        }
        LeaseAction::List => {
            emit(&client.call("leases_list", json!({}))?);
            Ok(0)
        }
    }
}

fn endpoint(client: &Client, args: &Args, action: &EndpointAction) -> anyhow::Result<i32> {
    match action {
        EndpointAction::List => {
            emit(&client.call("endpoints_list", json!({}))?);
            Ok(0)
        }
        EndpointAction::Destroy { port } => {
            emit(&client.call("endpoint_destroy", json!({
                "token": client.token_load(args.token.as_ref())?, "port": port,
            }))?);
            Ok(0)
        }
        EndpointAction::Create { port, ipv4, gateway4, ipv6, gateway6, vlan, vlan_s, mtu } => {
            emit(&client.call("endpoint_create", json!({
                "token": client.token_load(args.token.as_ref())?, "port": port,
                "ipv4": ipv4, "gateway4": gateway4, "ipv6": ipv6, "gateway6": gateway6,
                "vlan": vlan, "vlan_s": vlan_s, "mtu": mtu,
            }))?);
            Ok(0)
        }
    }
}
