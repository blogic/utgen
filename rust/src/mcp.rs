// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

use std::collections::BTreeMap;
use std::sync::Arc;

use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::{
    ErrorData as McpError, Implementation, ListResourcesResult, PaginatedRequestParams,
    ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult, Resource,
    ResourceContents, ServerCapabilities, ServerConfig,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{tool, tool_handler, tool_router, ServerHandler};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

use crate::core::{Core, CoreError};
use crate::engines::iperf3::Iperf3Spec;
use crate::engines::flows::FlowsSpec;
use crate::engines::probe::ProbeSpec;
use crate::engines::trafgen::TrafgenSpec;

/// The full guide, shipped inside the binary so it always matches the tools.
///
/// A session driving this runs on another machine and cannot read the
/// repository, so the document has to travel over the connection.
pub const GUIDE: &str = include_str!("../../docs/TOOLS.md");
pub const GUIDE_URI: &str = "tgen://guide";

pub const INSTRUCTIONS: &str = "\
Traffic generator for OpenWrt device bring-up. It owns a pool of physical NICs on
the lab host and nothing else: it never logs into the device under test, so
configure the device over your own channel and tell this tool what to expect.

Each port is placed in its own network namespace, so a flow from one port to
another genuinely leaves the host, crosses the device, and comes back. The kernel
cannot short-circuit it locally.

Normal order of work:
  1. ports_list                     see the pool and what each port's link can do
  2. lease_acquire                  claim the ports you need, keep the token
  3. endpoint_create (per port)     address the port inside its namespace
  4. link_wait                      confirm carrier and the negotiated speed
  5. traffic_start -> traffic_status start a flow, then poll it
  6. lease_release                  free the ports and tear the namespaces down

A measurement tool returns a run_id immediately and never blocks for the duration
of the run; poll traffic_status. Per-interval samples go to disk, not into your
context; run_samples returns the tail when you actually need detail.

Read the resource tgen://guide before planning real work. It carries the rest of
the tool surface, packet-rate and flow-table generation, capture, NAT checks and
frame injection, and the traps that yield a plausible wrong number rather than an
error. Every tool's own description and schema stays authoritative for its
arguments.";

/// Anticipated failures reach the model as readable content with is_error set,
/// not as a JSON-RPC protocol error.
///
/// rmcp converts an `ErrorData` error branch into a transport-level error, which
/// a client surfaces as a broken call rather than a message the model can read
/// and correct. A `String` branch becomes a text block with is_error=true, which
/// is what a tool failure should be.
fn fault(err: CoreError) -> String {
    err.to_string()
}

#[derive(Clone)]
pub struct TgenServer {
    core: Arc<Core>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PortRef {
    /// Port label such as "p0", or a kernel interface name.
    pub port: String,
    /// Return every counter key rather than the filtered set.
    #[serde(default)]
    pub full: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LeaseAcquire {
    /// Who is claiming the hardware, so a human can tell. Name yourself and your machine.
    pub owner: String,
    /// Port labels ("p0") or kernel names ("enp1s0f0np0").
    pub ports: Vec<String>,
    #[serde(default = "default_ttl")]
    pub ttl_s: f64,
    #[serde(default)]
    pub note: String,
}

fn default_ttl() -> f64 {
    3600.0
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TokenOnly {
    pub token: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LeaseRenew {
    pub token: String,
    #[serde(default = "default_ttl")]
    pub ttl_s: f64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EndpointCreate {
    pub token: String,
    pub port: String,
    /// Address with prefix, for example 192.168.10.2/24.
    #[serde(default)]
    pub ipv4: Option<String>,
    /// Plain address installed as a default route, which is how traffic reaches
    /// the far port through the device.
    #[serde(default)]
    pub gateway4: Option<String>,
    #[serde(default)]
    pub ipv6: Option<String>,
    #[serde(default)]
    pub gateway6: Option<String>,
    /// Inner 802.1Q customer tag.
    #[serde(default)]
    pub vlan: Option<u16>,
    /// Outer 802.1ad service tag for QinQ. Requires vlan as well.
    #[serde(default)]
    pub vlan_s: Option<u16>,
    /// Up to 9216 for jumbo tests.
    #[serde(default)]
    pub mtu: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EndpointDestroy {
    pub token: String,
    pub port: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LinkWait {
    pub port: String,
    #[serde(default = "default_link_timeout")]
    pub timeout_s: f64,
    /// Assert the negotiated rate. A mismatch reports speed_match=false and the
    /// host port's supported_modes.
    #[serde(default)]
    pub expect_mbps: Option<u32>,
}

fn default_link_timeout() -> f64 {
    30.0
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PortOffloads {
    pub token: String,
    pub port: String,
    /// Flag to boolean, for example {"tx_checksum": false, "tso": false}.
    /// Accepted: rx_checksum, tx_checksum, tso, gso, gro, lro, sg, rx_vlan, tx_vlan.
    /// Omit to read.
    #[serde(default)]
    pub settings: Option<BTreeMap<String, bool>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PortPause {
    pub token: String,
    pub port: String,
    #[serde(default)]
    pub autoneg: Option<bool>,
    #[serde(default)]
    pub rx: Option<bool>,
    #[serde(default)]
    pub tx: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PortSpeedForce {
    pub token: String,
    pub port: String,
    /// 100, 1000, 2500, 5000 or 10000. Omit to restore full autoneg.
    #[serde(default)]
    pub mbps: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PortMacSet {
    pub token: String,
    pub port: String,
    /// aa:bb:cc:dd:ee:ff form.
    pub mac: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TrafficStart {
    pub token: String,
    /// Source port label. Must differ from dst: a flow has to leave the host.
    pub src: String,
    pub dst: String,
    #[serde(default = "family_ipv4")]
    pub family: String,
    #[serde(flatten)]
    pub spec: Iperf3Spec,
}

fn family_ipv4() -> String {
    "ipv4".into()
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PpsStart {
    pub token: String,
    pub src: String,
    pub dst: String,
    #[serde(flatten)]
    pub spec: TrafgenSpec,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ProbeStart {
    pub token: String,
    pub src: String,
    pub dst: String,
    #[serde(default = "family_ipv4")]
    pub family: String,
    #[serde(flatten)]
    pub spec: ProbeSpec,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FlowsStart {
    pub token: String,
    pub src: String,
    pub dst: String,
    #[serde(default = "family_ipv4")]
    pub family: String,
    #[serde(flatten)]
    pub spec: FlowsSpec,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CaptureStart {
    pub token: String,
    pub port: String,
    /// tcpdump filter, for example 'ether proto 0x8808' for pause frames,
    /// 'vlan' for tagged traffic, or 'icmp6'. Empty captures everything, which
    /// at 10G fills a disk quickly.
    #[serde(default)]
    pub bpf: String,
    #[serde(default)]
    pub seconds: Option<u32>,
    #[serde(default)]
    pub max_packets: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CaptureRef {
    pub capture_id: String,
    #[serde(default = "fifty")]
    pub limit: usize,
    #[serde(default = "yes")]
    pub verbose: bool,
}

fn fifty() -> usize {
    50
}
fn yes() -> bool {
    true
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EchoStart {
    pub token: String,
    pub port: String,
    #[serde(default = "udp_echo_port")]
    pub udp_port: u16,
    #[serde(default = "tcp_echo_port")]
    pub tcp_port: u16,
    #[serde(default = "family_ipv4")]
    pub family: String,
}

fn udp_echo_port() -> u16 {
    crate::echo::DEFAULT_UDP_PORT
}
fn tcp_echo_port() -> u16 {
    crate::echo::DEFAULT_TCP_PORT
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EchoRef {
    pub echo_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InjectFrames {
    pub token: String,
    pub port: String,
    /// 'ether', 'udp' or 'tcp'.
    pub kind: String,
    #[serde(default = "one_u32")]
    pub count: u32,
    /// Required for kind 'ether', for example 34997 for 0x88b5.
    #[serde(default)]
    pub ethertype: Option<u16>,
    #[serde(default)]
    pub src_ip: Option<String>,
    #[serde(default)]
    pub dst_ip: Option<String>,
    #[serde(default = "sport_default")]
    pub sport: u16,
    #[serde(default = "dport_default")]
    pub dport: u16,
    /// 4 or 6.
    #[serde(default = "four_u8")]
    pub version: u8,
    /// TCP flag letters, any of FSRPAU.
    #[serde(default = "syn_default")]
    pub flags: String,
    #[serde(default)]
    pub payload: Option<String>,
    #[serde(default)]
    pub src_mac: Option<String>,
    #[serde(default)]
    pub dst_mac: Option<String>,
    #[serde(default)]
    pub bad_checksum: bool,
    #[serde(default)]
    pub zero_checksum: bool,
    /// Splits an IPv4 packet into fragments of this many bytes, a multiple of 8.
    #[serde(default)]
    pub fragment_size: Option<usize>,
}

fn one_u32() -> u32 {
    1
}
fn sport_default() -> u16 {
    12345
}
fn dport_default() -> u16 {
    9999
}
fn four_u8() -> u8 {
    4
}
fn syn_default() -> String {
    "S".into()
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunsList {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    25
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunRef {
    pub run_id: String,
    #[serde(default = "default_samples")]
    pub limit: usize,
}

fn default_samples() -> usize {
    20
}

#[tool_router]
impl TgenServer {
    pub fn new(core: Arc<Core>) -> Self {
        Self { core }
    }

    /// List every port in the pool with its live link state.
    ///
    /// Returns per port: label, kernel iface, mac, carrier, negotiated speed_mbps,
    /// supported_modes and max_speed_mbps from the PHY, whether it is claimed into
    /// a namespace, and which lease owner holds it.
    ///
    /// Read supported_modes before planning a test. A port whose modes lack
    /// 2500baseT cannot link at 2.5G; it will negotiate 1000baseT instead and look
    /// healthy while measuring 1G.
    #[tool]
    async fn ports_list(&self) -> Result<Json<Vec<Value>>, String> {
        self.core.ports_list().await.map(Json).map_err(fault)
    }

    /// Driver and link counters for a port, merged from ethtool -S and ip -s link.
    ///
    /// Filtered by default to errors, drops, discards, pause (xon/xoff), bad-frame
    /// counters and packet/byte totals. Pass full=true for every key, but note
    /// i40e alone reports 298 of them.
    #[tool]
    async fn port_counters(&self, Parameters(args): Parameters<PortRef>) -> Result<Json<Value>, String> {
        self.core
            .port_counters(&args.port, args.full)
            .await
            .map(Json)
            .map_err(fault)
    }

    /// Claim exclusive use of ports. Returns a token required by every mutating call.
    ///
    /// Fails if any requested port is already leased, naming the current holder.
    /// The lease expires after ttl_s and expiry tears down that lease's endpoints,
    /// returning the NICs to the host. Call lease_renew for long work.
    #[tool]
    async fn lease_acquire(&self, Parameters(args): Parameters<LeaseAcquire>) -> Result<Json<Value>, String> {
        self.core
            .lease_acquire(&args.owner, args.ports, args.ttl_s, &args.note)
            .await
            .map(Json)
            .map_err(fault)
    }

    /// Release a lease, destroy its endpoints and return its NICs to the host.
    #[tool]
    async fn lease_release(&self, Parameters(args): Parameters<TokenOnly>) -> Result<Json<Value>, String> {
        self.core.lease_release(&args.token).await.map(Json).map_err(fault)
    }

    /// Extend a lease by ttl_s from now.
    #[tool]
    async fn lease_renew(&self, Parameters(args): Parameters<LeaseRenew>) -> Result<Json<Value>, String> {
        self.core
            .lease_renew(&args.token, args.ttl_s)
            .await
            .map(Json)
            .map_err(fault)
    }

    /// List active leases, who owns them, which ports they hold and time remaining.
    #[tool]
    async fn leases_list(&self) -> Result<Json<Vec<Value>>, String> {
        Ok(Json(self.core.leases_list().await))
    }

    /// Move a port into its own namespace and address it.
    ///
    /// At least one of ipv4 or ipv6 is required. Because every port is in a
    /// separate namespace, two endpoints may use the same subnet on both sides of
    /// the device without the kernel short-circuiting.
    #[tool]
    async fn endpoint_create(&self, Parameters(args): Parameters<EndpointCreate>) -> Result<Json<Value>, String> {
        self.core
            .endpoint_create(
                &args.token, &args.port, args.ipv4, args.gateway4, args.ipv6, args.gateway6,
                args.vlan, args.vlan_s, args.mtu,
            )
            .await
            .map(Json)
            .map_err(fault)
    }

    /// Tear down a port's endpoint and return the NIC to the host namespace.
    #[tool]
    async fn endpoint_destroy(&self, Parameters(args): Parameters<EndpointDestroy>) -> Result<Json<Value>, String> {
        self.core
            .endpoint_destroy(&args.token, &args.port)
            .await
            .map(Json)
            .map_err(fault)
    }

    /// List configured endpoints with their declared config and live addresses.
    #[tool]
    async fn endpoints_list(&self) -> Result<Json<Vec<Value>>, String> {
        self.core.endpoints_list().await.map(Json).map_err(fault)
    }

    /// Wait for carrier on a port, then report the negotiated speed.
    ///
    /// Use after cabling or after changing the device's port config. Returns
    /// link_wait='up' with speed_mbps, or link_wait='timeout' with a reason.
    /// A speed mismatch carries the host port's supported_modes, which is how you
    /// tell "the device negotiated badly" from "this host port cannot do that rate".
    #[tool]
    async fn link_wait(&self, Parameters(args): Parameters<LinkWait>) -> Result<Json<Value>, String> {
        self.core
            .link_wait(&args.port, args.timeout_s, args.expect_mbps)
            .await
            .map(Json)
            .map_err(fault)
    }

    /// Read or change the generator's own offloads on a port.
    ///
    /// A value of fixed-on or fixed-off means the driver will not let it change.
    /// Turn tx_checksum off before injecting frames with a deliberately bad
    /// checksum, otherwise the NIC recomputes a correct one and the test passes
    /// for the wrong reason. Turn tso and gso off when wire segment sizes are what
    /// you are measuring.
    #[tool]
    async fn port_offloads(&self, Parameters(args): Parameters<PortOffloads>) -> Result<Json<Value>, String> {
        self.core
            .port_offloads(&args.token, &args.port, args.settings)
            .await
            .map(Json)
            .map_err(fault)
    }

    /// Read or set 802.3x pause on a port. Omit autoneg, rx and tx to read.
    ///
    /// Check 'applied' in the result. The X710's i40e driver accepts
    /// `ethtool -A rx on tx on` with a success code and applies nothing, so a
    /// write is verified by reading back after the link settles; anything the
    /// driver dropped is listed under 'ignored'. Expect applied=false for rx and
    /// tx on these ports and work from the negotiated result instead.
    ///
    /// Pause frames are counted even where they cannot be forced: port_counters
    /// carries port.link_xon_rx, port.link_xoff_rx, port.link_xon_tx and
    /// port.link_xoff_tx, plus per-priority keys for PFC.
    #[tool]
    async fn port_pause(&self, Parameters(args): Parameters<PortPause>) -> Result<Json<Value>, String> {
        self.core
            .port_pause(&args.token, &args.port, args.autoneg, args.rx, args.tx)
            .await
            .map(Json)
            .map_err(fault)
    }

    /// Restrict a port to advertising one speed, or omit mbps to restore autoneg.
    ///
    /// This is how you make a port act as a slower link partner, for downshift and
    /// pause-toward-a-slower-partner tests, with no extra hardware. A speed the
    /// PHY lacks is refused and the error names what the port does support. On the
    /// X710-T4 ports here, 2500 and 5000 are refused: that card has no multi-gig
    /// support, so a 2.5G device port cabled to it negotiates 1000 and looks
    /// healthy. The link renegotiates, so follow this with link_wait.
    #[tool]
    async fn port_speed_force(&self, Parameters(args): Parameters<PortSpeedForce>) -> Result<Json<Value>, String> {
        self.core
            .port_speed_force(&args.token, &args.port, args.mbps)
            .await
            .map(Json)
            .map_err(fault)
    }

    /// Set a port's MAC address. Useful where the device hashes on layer 2 only.
    /// The port is brought down and back up around the change.
    #[tool]
    async fn port_mac_set(&self, Parameters(args): Parameters<PortMacSet>) -> Result<Json<Value>, String> {
        self.core
            .port_mac_set(&args.token, &args.port, &args.mac)
            .await
            .map(Json)
            .map_err(fault)
    }

    /// List recent runs, newest first.
    #[tool]
    async fn runs_list(&self, Parameters(args): Parameters<RunsList>) -> Result<Json<Vec<Value>>, String> {
        Ok(Json(
            self.core.runs.list(args.limit).iter().map(|r| r.public()).collect(),
        ))
    }

    /// Start an iperf3 flow from src to dst through the device. Returns a run_id at once.
    ///
    /// The iperf3 server runs in dst's namespace and the client in src's, so the
    /// traffic crosses the device under test. Both ports need an endpoint and both
    /// must be on your lease.
    ///
    /// proto is tcp or udp. udp requires an explicit bitrate ('900M', or '0' for
    /// unlimited) because iperf3 otherwise defaults to 1 Mbit/s and the
    /// measurement is meaningless. bitrate also paces tcp. reverse swaps
    /// direction, bidir runs both at once, and the two are mutually exclusive.
    /// mss, dscp and bind are available; with several streams the summary also
    /// carries retransmits_per_stream.
    ///
    /// This call does not wait for the run. Poll traffic_status for live
    /// throughput and the final summary; traffic_stop ends one early.
    #[tool]
    async fn traffic_start(&self, Parameters(args): Parameters<TrafficStart>) -> Result<Json<Value>, String> {
        self.core
            .traffic_start(&args.token, &args.src, &args.dst, &args.family, args.spec)
            .await
            .map(Json)
            .map_err(fault)
    }

    /// Small-frame load at high packet rate, for line-rate and forwarding tests.
    ///
    /// Use this instead of traffic_start whenever packets per second is what
    /// matters. iperf3 tops out around 1.06 Mpps here against the 14.88 Mpps that
    /// 10G needs at 64 bytes; this engine is trafgen over AF_PACKET and reaches
    /// about 2.9 Mpps clean and 5.1 Mpps peak.
    ///
    /// Frames are valid Ethernet/IPv4/UDP with checksums computed by trafgen, so
    /// a device under test will route or forward them. frame_bytes counts from
    /// the Ethernet header and must be at least 60, the Ethernet minimum.
    /// rate paces the load, for example '1Mpps' or '5Gbit'; omit it to send as
    /// fast as the host can. cpus is the number of sending forks and is the main
    /// throttle on achieved rate. src_mac_count above 1 emits one packet block
    /// per source address so a device hashing on layer 2 sees a spread of flows.
    ///
    /// There is no per-interval sampling. The result comes from the NIC counters
    /// on both ports: packets sent and received, loss, rx_missed_errors, and
    /// tx_ring_flush_errors, which on i40e is a transient EAGAIN from the ring
    /// flush rather than lost traffic.
    ///
    /// Returns a run_id at once; poll traffic_status.
    #[tool]
    async fn pps_start(&self, Parameters(args): Parameters<PpsStart>) -> Result<Json<Value>, String> {
        self.core
            .pps_start(&args.token, &args.src, &args.dst, args.spec)
            .await
            .map(Json)
            .map_err(fault)
    }

    /// Sequence-numbered UDP probe: one-way delay, loss, reordering and duplicates.
    ///
    /// Use this rather than traffic_start when latency or packet ordering is what
    /// matters, and run it alongside a bulk flow to measure latency under load.
    ///
    /// The one-way delay is genuine, not a halved round trip. Both endpoints are
    /// namespaces on this one host, so CLOCK_MONOTONIC is the same clock at both
    /// ends and the receiver subtracts the sender's reading directly. The summary
    /// gives owd_min_ms, owd_mean_ms, owd_p50_ms, owd_p99_ms and owd_max_ms, plus
    /// ipdv_mean_ms, the mean absolute change between consecutive delays rather
    /// than iperf3's smoothed jitter.
    ///
    /// reordered counts packets arriving with a lower sequence number than their
    /// predecessor, which is what to watch once receive processing spreads across
    /// queues. duplicates counts sequence numbers seen more than once.
    ///
    /// Keep rate_pps modest: this is a measurement stream, not a load generator.
    /// Use pps_start for load. Returns a run_id at once; poll traffic_status.
    #[tool]
    async fn probe_start(&self, Parameters(args): Parameters<ProbeStart>) -> Result<Json<Value>, String> {
        self.core
            .probe_start(&args.token, &args.src, &args.dst, &args.family, args.spec)
            .await
            .map(Json)
            .map_err(fault)
    }

    /// Open many concurrent flows, to fill and age a device's flow table.
    ///
    /// Each flow is a distinct 5-tuple, because the kernel gives every connection
    /// a fresh ephemeral source port. This is the tool for conntrack and hardware
    /// NAT table work; iperf3 is not, it caps at 128 streams and is far too heavy
    /// per flow.
    ///
    /// proto 'tcp' opens real connections and holds them for duration_s. With
    /// churn=true they are closed and replaced continuously instead, each living
    /// for flow_lifetime_s, which must be long enough for count flows to overlap
    /// or concurrency never builds up. proto 'udp' sends one datagram per bound
    /// socket, which is enough to create the tuple.
    ///
    /// Pace udp with open_rate_per_s: unthrottled it creates flows faster than
    /// the sink can read them, and the shortfall looks like device loss when it is
    /// this tool saturating.
    ///
    /// The summary reports opened, failed with a breakdown by error type,
    /// concurrent_peak, and a 'sink' block with what the far end actually
    /// accepted. 'not_reached' is the difference, which is what the device dropped
    /// or never forwarded.
    #[tool]
    async fn flows_start(&self, Parameters(args): Parameters<FlowsStart>) -> Result<Json<Value>, String> {
        self.core
            .flows_start(&args.token, &args.src, &args.dst, &args.family, args.spec)
            .await
            .map(Json)
            .map_err(fault)
    }

    /// Start a packet capture on a port. Returns a capture_id at once.
    ///
    /// Prefer a filter plus max_packets: an empty filter at 10G fills a disk
    /// quickly. seconds and max_packets both stop the capture by themselves. One
    /// capture per port, and it is stopped automatically if the port's endpoint
    /// is torn down.
    #[tool]
    async fn capture_start(&self, Parameters(args): Parameters<CaptureStart>) -> Result<Json<Value>, String> {
        self.core
            .capture_start(&args.token, &args.port, &args.bpf, args.seconds, args.max_packets)
            .await
            .map(Json)
            .map_err(fault)
    }

    /// Stop a capture and report the pcap path, size and packet count.
    #[tool]
    async fn capture_stop(&self, Parameters(args): Parameters<CaptureRef>) -> Result<Json<Value>, String> {
        self.core.capture_stop(&args.capture_id).await.map(Json).map_err(fault)
    }

    /// Whether a capture is still running, with its packet count and pcap size.
    #[tool]
    async fn capture_status(&self, Parameters(args): Parameters<CaptureRef>) -> Result<Json<Value>, String> {
        self.core.capture_status(&args.capture_id).await.map(Json).map_err(fault)
    }

    /// Decode a capture to readable packet lines.
    ///
    /// Shows link-layer detail, so VLAN tags, ethertypes and per-port source
    /// MACs are visible. Keep limit small: a 10G capture holds millions of
    /// packets, and the pcap path from capture_stop is there for the whole file.
    #[tool]
    async fn capture_decode(&self, Parameters(args): Parameters<CaptureRef>) -> Result<Json<Value>, String> {
        self.core
            .capture_decode(&args.capture_id, args.limit, args.verbose)
            .await
            .map(Json)
            .map_err(fault)
    }

    /// List captures this daemon knows about, running or finished.
    #[tool]
    async fn captures_list(&self) -> Result<Json<Vec<Value>>, String> {
        Ok(Json(self.core.captures_list().await))
    }

    /// Start an echo service on a port that reports the source it observed.
    ///
    /// This is how you verify NAT. Send to it from the other side of the device
    /// and the reply states the address and port that actually arrived, which is
    /// what the device translated you to. UDP replies with a JSON object; a TCP
    /// connection receives one JSON line and is closed.
    #[tool]
    async fn echo_start(&self, Parameters(args): Parameters<EchoStart>) -> Result<Json<Value>, String> {
        self.core
            .echo_start(&args.token, &args.port, args.udp_port, args.tcp_port, &args.family)
            .await
            .map(Json)
            .map_err(fault)
    }

    /// Stop an echo service.
    #[tool]
    async fn echo_stop(&self, Parameters(args): Parameters<EchoRef>) -> Result<Json<Value>, String> {
        self.core.echo_stop(&args.echo_id).await.map(Json).map_err(fault)
    }

    /// Every distinct source address and port an echo service has observed.
    #[tool]
    async fn echo_observations(&self, Parameters(args): Parameters<EchoRef>) -> Result<Json<Value>, String> {
        self.core.echo_observations(&args.echo_id).await.map(Json).map_err(fault)
    }

    /// List echo services this daemon knows about.
    #[tool]
    async fn echoes_list(&self) -> Result<Json<Vec<Value>>, String> {
        Ok(Json(self.core.echoes_list().await))
    }

    /// Send crafted frames out of a port, with control over every field.
    ///
    /// kind 'ether' needs an ethertype and sends a raw frame; 'udp' and 'tcp'
    /// need src_ip and dst_ip and take version 4 or 6.
    ///
    /// bad_checksum writes a deliberately wrong L4 checksum, zero_checksum (udp
    /// only) writes 0. Both are refused unless tx_checksum is already off on that
    /// port, because the NIC would otherwise recompute a correct one and the test
    /// would pass for the wrong reason; use port_offloads first.
    ///
    /// fragment_size splits an IPv4 packet into fragments of that many bytes, a
    /// multiple of 8. src_mac spoofs the source address, which is proven to reach
    /// the wire here.
    ///
    /// Two things this hardware cannot do, measured: 802.3x pause frames
    /// (ethertype 0x8808) are dropped by the i40e MAC on transmit and never
    /// arrive, and bad FCS or true runt frames are impossible because the MAC
    /// appends the FCS and pads to 60 bytes. Pair this with capture_start on the
    /// receiving port to confirm what actually left.
    #[tool]
    async fn inject_frames(&self, Parameters(args): Parameters<InjectFrames>) -> Result<Json<Value>, String> {
        let spec = serde_json::json!({
            "kind": args.kind, "count": args.count, "ethertype": args.ethertype,
            "src_ip": args.src_ip, "dst_ip": args.dst_ip, "sport": args.sport,
            "dport": args.dport, "version": args.version, "flags": args.flags,
            "payload": args.payload, "src_mac": args.src_mac, "dst_mac": args.dst_mac,
            "bad_checksum": args.bad_checksum, "zero_checksum": args.zero_checksum,
            "fragment_size": args.fragment_size,
        });
        self.core
            .inject_frames(&args.token, &args.port, spec)
            .await
            .map(Json)
            .map_err(fault)
    }

    /// Status of a run: status, duration, sample count, and the final summary once done.
    ///
    /// While running, 'live' carries the most recent interval. When finished,
    /// 'summary' carries tx/rx mbps, retransmits and RTT for tcp, or throughput,
    /// jitter, lost packets and loss percent for udp, plus the counters that moved
    /// on each port.
    #[tool]
    async fn traffic_status(&self, Parameters(args): Parameters<RunRef>) -> Result<Json<Value>, String> {
        self.core.traffic_status(&args.run_id).await.map(Json).map_err(fault)
    }

    /// Stop a running flow early and finalise it. Returns the run's final status.
    #[tool]
    async fn traffic_stop(&self, Parameters(args): Parameters<RunRef>) -> Result<Json<Value>, String> {
        self.core.traffic_stop(&args.run_id).await.map(Json).map_err(fault)
    }

    /// Return the last 'limit' per-interval samples of a run.
    ///
    /// Use only when the summary is not enough; a long run holds thousands.
    #[tool]
    async fn run_samples(&self, Parameters(args): Parameters<RunRef>) -> Result<Json<Vec<Value>>, String> {
        Ok(Json(self.core.runs.samples_tail(&args.run_id, args.limit)))
    }
}

#[tool_handler]
impl ServerHandler for TgenServer {
    /// Written out rather than left to the macro, whose `instructions` field
    /// takes a string literal and so cannot reference the constant above.
    fn get_info(&self) -> ServerConfig {
        let mut info = ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        );
        // Implementation is #[non_exhaustive], so it is mutated rather than built.
        let mut implementation = Implementation::from_build_env();
        implementation.name = "traffic-generator".into();
        implementation.version = env!("CARGO_PKG_VERSION").into();
        info.server_info = implementation;
        info.instructions = Some(INSTRUCTIONS.to_string());
        info
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(ListResourcesResult::with_all_items(vec![
            Resource::new(GUIDE_URI, "guide")
                .with_title("Driving the traffic generator")
                .with_description(
                    "Which tool to reach for, the order calls go in, and the traps that \
                     yield a plausible wrong number rather than an error. Read before \
                     planning real work.",
                )
                .with_mime_type("text/markdown")
                .with_size(GUIDE.len() as u64),
        ]))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, McpError> {
        if request.uri != GUIDE_URI {
            return Err(McpError::resource_not_found(
                format!("unknown resource {:?}; this server serves {GUIDE_URI}", request.uri),
                None,
            ));
        }
        Ok(ReadResourceResult::new(vec![
            ResourceContents::text(GUIDE, GUIDE_URI).with_mime_type("text/markdown"),
        ])
        .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_instructions_point_at_the_guide() {
        assert!(INSTRUCTIONS.contains(GUIDE_URI), "nothing would lead a client to it");
    }

    #[test]
    fn the_guide_names_every_tool_the_server_serves() {
        // The written guide and the tool surface drift apart silently
        // otherwise, and a remote session has only these two to work from.
        let missing: Vec<String> = TgenServer::tool_router()
            .list_all()
            .iter()
            .map(|tool| tool.name.to_string())
            .filter(|name| !GUIDE.contains(name.as_str()))
            .collect();
        assert!(missing.is_empty(), "tools absent from docs/TOOLS.md: {missing:?}");
        assert_eq!(TgenServer::tool_router().list_all().len(), 32, "tool count changed");
    }
}
