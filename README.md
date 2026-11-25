# utgen

A multi-port traffic generator for network device bring-up, driven over MCP.

It owns a pool of physical NICs on a Linux host and generates and receives
traffic across them. It never logs into the device under test: an agent, or a
person, configures the device over its own channel, then drives this tool to find
out what the device actually does with traffic.

It was built so an agent porting OpenWrt to a new board could measure that board
from another machine, but nothing in it is specific to OpenWrt, or to an agent.
The CLI drives the same surface.

## What it measures

| | Engine | For |
|---|---|---|
| Throughput | iperf3 | bits per second, retransmits, RTT, jitter, UDP loss |
| Packet rate | trafgen | small-frame forwarding, millions of packets per second |
| Latency | built in | true one-way delay, loss, reordering, duplicates |
| Flow scale | built in | tens of thousands of concurrent flows, to fill a flow table |

Plus packet capture, an echo service that reports the source address it observed
so you can see what a NAT translated, raw frame injection, per-port offload,
pause, speed and MAC control, and merged driver counters snapshotted around every
run.

## Why network namespaces

Each port is moved into its own network namespace. A flow from one port to
another therefore has to leave the host, cross the device, and come back.

This is the whole point. In a single namespace both endpoint addresses are local,
so the kernel delivers internally and you measure loopback instead of the device.
VRFs only partly prevent this and need `udp_l3mdev_accept` and per-interface
`rp_filter` workarounds to get close. Namespaces remove the problem outright, and
let both sides of a device use the same subnet.

## Model

| Object | Meaning |
|---|---|
| Port | a physical NIC in the pool, declared in config. Never auto-discovered |
| Endpoint | a port moved into netns `tgen-<label>`, with optional VLAN and v4/v6 addressing |
| Lease | exclusive ownership of a port set by one client, with a TTL |
| Run | one measurement, with samples and a summary on disk |

Every mutating call needs a lease. A lease expiring tears down its endpoints and
returns the NICs, so a client that crashes cannot hold hardware; a sweeper
enforces that every 15 seconds. On startup the daemon reconciles namespaces
against the lease file, because namespaces are pinned in `/run/netns` and outlive
the process.

Nothing is auto-discovered. A NIC that is not in the config does not exist to the
daemon, which is what stops it moving your management interface into a namespace
and taking the host off the network.

## Requirements

Linux with network namespaces, which is any stock kernel, and root. The daemon
creates namespaces, moves NICs between them and drives `ethtool`, so there is no
useful unprivileged mode.

```
apt install iproute2 ethtool iperf3 netsniff-ng tcpdump iputils-ping
```

`iproute2` and `ethtool` are required. The rest each enable one engine or tool,
and a missing one is reported as return code 127 by the tool that needed it.

Two NICs that nothing else manages. One is enough to capture and inject, but a
flow needs a source and a destination.

## Install

```
cd rust
cargo build --release
sudo ./tools/install.sh
```

Then edit `/etc/traffic-generator/config.json`: set your ports, and replace the
placeholder token with one of your own. The daemon refuses to start until you do.

```
sudo systemctl enable --now tgend
sudo tgen ports
```

`docs/INSTALL.md` is the full version, including keeping NetworkManager or
systemd-networkd off the pool, which they will otherwise reclaim.

## Driving it from an agent

```
claude mcp add --transport http utgen http://<host>:9140/mcp \
  --header "Authorization: Bearer <token from config>"
```

The transport is MCP Streamable HTTP with `json_response` and no session manager:
replies are a single JSON body rather than SSE, and a client reconnect needs no
session recovery, because the state that matters lives in the lease. `Host` and
`Origin` allow-lists come from the config, as the specification requires against
DNS rebinding.

Everything a session needs travels over the connection, because a session driving
this is usually on another machine:

- 32 tools, each with its own description and a JSON schema carrying types,
  bounds and defaults
- `instructions` on initialize: the orientation and the call order
- the resource `tgen://guide`, which is `docs/TOOLS.md` compiled into the binary,
  so it always matches the running build
- the same document at `http://<host>:9150/guide.md`, for anything that would
  rather fetch a URL

A measurement tool returns a `run_id` at once and never blocks for the duration of
a run. Poll `traffic_status`. Per-interval samples go to disk, not into the
caller's context; `run_samples` returns the tail on request.

It is a generator, not a test framework. It reports what it measured and never
decides whether that is a pass, because the caller is the one that knows what the
device was configured to do.

## CLI

```
tgen ports                                    pool with live link state
tgen lease acquire p0 p1 --ttl 3600           token is saved for later commands
tgen endpoint create p0 --ipv4 10.80.0.1/24
tgen link-wait p0 --expect 10000              exit status reflects the match
tgen traffic p0 p1 --duration 10 --streams 4  throughput, iperf3
tgen pps p0 p1 --frame-bytes 64 --cpus 4      packet rate, trafgen
tgen probe p0 p1 --rate 2000                  one-way delay, loss, reordering
tgen flows p0 p1 --count 10000                concurrent flows, flow-table fill
tgen capture p1 icmp --seconds 5 --decode 10
tgen runs
tgen call <tool> '<json>'                     any tool directly
```

Needs root, and the global `-j` for raw JSON goes before the subcommand. `tgen
call` reaches arguments the subcommands do not expose. The CLI is an MCP client
rather than a second driver, so the daemon stays the only owner of leases and
namespaces.

## Status page

`http://<host>:9150/` while the daemon runs: ports with link state and who holds
them, leases, endpoints, captures and echo services, recent runs with their
results, and a tail of the journal. Hand-written HTML and JavaScript embedded in
the binary, no framework and no assets to install.

Read-only and unauthenticated, on a separate listener from MCP. It serves no
mutating route, and everything that touches hardware goes through the MCP
endpoint, which needs the token. The config refuses to start if the two share a
port. Omit the `web` block and no listener is started at all.

## Documentation

| | |
|---|---|
| `docs/INSTALL.md` | bringing it up on a host from nothing, and troubleshooting |
| `docs/CONFIG.md` | every config field, and what is rejected at load |
| `docs/TOOLS.md` | which tool to reach for, the call order, and the traps. Also served as `tgen://guide` |

## Choosing an engine

`traffic_start` and `pps_start` are not interchangeable, and the gap between them
is wide enough to matter. On a 10G link, line rate at 64 bytes is 14.88 Mpps;
iperf3 reaches roughly 1 Mpps of that, and trafgen 3 to 5 Mpps depending on how
many sending cpus you give it. Neither approaches line rate, which is why
`pps_start` exists at all: use it whenever the question is packets per second
rather than bits per second. Going faster would need DPDK or AF_XDP, which takes
the NIC out of the kernel and so out of the namespace model entirely.

Latency is a true one-way delay, not a halved round trip, and needs no PTP: both
namespaces are on one host, so `CLOCK_MONOTONIC` is the same clock at both ends.
That property disappears if the two ends ever become different machines.

## Know your NICs before planning a test

What the generator can ask for depends on the card, and a refusal is not always
loud. Worth confirming on your own hardware rather than assuming:

- A speed the PHY lacks is negotiated **down** silently, so a 2.5G device port
  cabled to a 10G/1G-only card links at 1G and looks healthy. `ports_list`
  reports `supported_modes`, and `link_wait` takes `expect_mbps` so a mismatch
  fails loudly instead.
- `ethtool -A` can return success and apply nothing, so `port_pause` verifies by
  reading back and reports `applied` alongside an `ignored` map.
- Transmitting crafted 802.3x pause frames, generating a bad FCS, and sending
  true runt frames are all things a MAC may simply refuse, since it appends the
  FCS and pads to the 60-byte minimum in hardware. Pair `inject_frames` with
  `capture_start` on the receiving port to see what actually left.
- Link partner advertised modes are not exposed by every driver.

## Licence

GPL-2.0-only. See `LICENSE` for the full text; every source file carries an SPDX
identifier.
