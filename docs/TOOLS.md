# Driving the traffic generator

This is the guide for a session on another machine, reached over MCP. It is
served by the daemon itself, as the resource `tgen://guide` and at
`http://<host>:<web.port>/guide.md`, so it always matches the running binary.

32 tools. Each carries its own description and a JSON schema with types, bounds
and defaults, read from `tools/list`. That is the authoritative per-call detail
and it cannot go stale. This file is what the schemas cannot express: which tool
to reach for, the order calls have to go in, and the traps that cost
measurements rather than calls.

## What this is

A pool of physical NICs on a lab host, and nothing else. It generates and
receives traffic; **it never logs into the device under test**. Configure the
device over your own channel, then tell this tool what to expect.

Each port is moved into its own network namespace, so a flow from one port to
another genuinely leaves the host, crosses the device and comes back. The kernel
cannot short-circuit it locally, and both sides of the device may use the same
subnet.

The host cannot see inside the device, so a result is what arrived on the wire,
not why. Pair a measurement with `capture_start` when you need to know which.

It is a generator, not a test framework. It reports what it measured and never
decides whether that is a pass: the logic that says "the high-priority stream
should have survived" belongs in your session, which knows what the device was
configured to do.

## Call order

Nothing works until a lease and an endpoint exist, in that order.

```
lease_acquire(owner, ports)        -> token, used by every mutating call
endpoint_create(token, port, ipv4) -> for each port a flow will use
link_wait(port, expect_mbps)       -> confirm the link before measuring
<measure>                          -> traffic_start, pps_start, probe_start, flows_start
traffic_status(run_id)             -> poll; every engine finishes here
lease_release(token)               -> tears down endpoints, returns the NICs
```

Read-only tools need no token: `ports_list`, `leases_list`, `endpoints_list`,
`link_wait`, `runs_list`, `traffic_status`, `run_samples`, `captures_list`,
`capture_status`, `capture_decode`, `echoes_list`, `echo_observations`.

The four measurement tools return a `run_id` immediately and never block for the
duration. They are all polled with `traffic_status`, whatever started them.

## The pool

| Tool | For |
|---|---|
| `ports_list` | the pool with live link state, speed, `supported_modes`, and who holds each port |
| `port_counters` | `ethtool -S` merged with `ip -s link`, filtered to what matters; `full=true` for all of it |

## Leases

| Tool | For |
|---|---|
| `lease_acquire` | claim ports exclusively; returns the `token` |
| `lease_renew` | extend by `ttl_s` from now |
| `lease_release` | give the ports back, destroying endpoints |
| `leases_list` | who holds what, and for how much longer |

A lease expiring is not benign: it tears down that lease's endpoints and returns
the NICs mid-measurement. The sweeper checks every 15 s. Ask for a `ttl_s` that
covers the whole job, or renew.

## Endpoints

| Tool | For |
|---|---|
| `endpoint_create` | move a port into `tgen-<label>` and address it; VLAN, QinQ and MTU here |
| `endpoint_destroy` | return one NIC without dropping the lease |
| `endpoints_list` | what exists, with addresses and link state |

Both sides may use the same subnet, because each port is in its own namespace.

QinQ is `vlan_s` (the 802.1ad outer tag) plus `vlan` (the inner 802.1Q tag).
Interface names are capped at 15 characters by `IFNAMSIZ`, which a long NIC name
plus two tags can exceed; the error says so.

## Per-port settings

| Tool | For |
|---|---|
| `port_offloads` | read or change rx/tx checksum, TSO, GSO, GRO, LRO, SG, rx/tx VLAN |
| `port_pause` | read or try to set 802.3x pause. Check `applied` and `ignored` |
| `port_speed_force` | advertise a single speed, so the host acts as a slower partner |
| `port_mac_set` | change a port's MAC |

`port_speed_force` renegotiates the link, so follow it with `link_wait`.

## Measurement

| Tool | Engine | Use it for |
|---|---|---|
| `traffic_start` | iperf3 | throughput, retransmits, RTT, jitter, UDP loss. Caps near 1 Mpps |
| `pps_start` | trafgen | small-frame packet rate, 2.4 to 5 Mpps at 64 bytes |
| `probe_start` | own helpers | one-way delay, loss, reordering, duplicates |
| `flows_start` | own helpers | many concurrent flows, to fill a device's flow table |
| `traffic_status` | | poll any run; carries the summary when done |
| `traffic_stop` | | end a run early and finalise it |
| `run_samples` | | per-interval samples, for iperf3 runs only |
| `runs_list` | | recent runs, newest first |

Pick by what is being measured: `traffic_start` for bits per second,
`pps_start` for packets per second. They are not interchangeable, and 10G line
rate at 64 bytes is 14.88 Mpps, which neither reaches.

Per-interval samples exist only for iperf3. `pps_start` derives its result from
NIC counters at both ends, and `probe_start` and `flows_start` report once at the
end.

## Inspection

| Tool | For |
|---|---|
| `capture_start` | tcpdump in a port's namespace, with a BPF filter |
| `capture_stop` | stop it; returns the pcap path, size and count |
| `capture_status` | still running, how many packets |
| `capture_decode` | readable packet lines, link-layer detail included |
| `captures_list` | what is running |
| `echo_start` | UDP and TCP echo whose reply states the source it saw |
| `echo_observations` | every distinct source seen, with packet and byte counts |
| `echo_stop`, `echoes_list` | lifecycle |
| `inject_frames` | craft and send specific frames |

`echo_start` is the NAT check: the reply says what address and port actually
arrived, which is what the device translated the sender to.

One capture per port. Always pass a filter and `max_packets`; an unfiltered
capture at 10G fills a disk.

## Traps that cost measurements

These are the ones that produce a plausible wrong number rather than an error.

- **A UDP `traffic_start` without `bitrate` measures 1 Mbit/s.** That is iperf3's
  default, and the run looks successful.
- **Unpaced `flows_start` over UDP saturates the generator, not the device.**
  20000 flows opened as fast as possible had 8812 never reach the sink with no
  device in the path. Set `open_rate_per_s`.
- **`churn` with no `flow_lifetime_s` never builds concurrency.** Flows close
  before the next opens, so the table never fills while the rate looks right.
- **A deliberately bad checksum is silently corrected** by TX checksum offload.
  Turn it off with `port_offloads` first, or the test passes for the wrong
  reason.
- **`port_pause` writes can be accepted and ignored.** The i40e driver returns
  success and applies nothing, so read `applied`, not the return code.
- **A port that cannot do the rate negotiates a lower one and looks healthy.**
  Check `supported_modes` from `ports_list` before planning, and assert with
  `link_wait --expect`.
- **Loss on a direct cable is this tool saturating.** Baseline a cabled loop
  before believing a loss figure from a device.
- **`veth` hides everything interesting.** It will exercise the plumbing, but
  offloads, negotiation and packet rate on it mean nothing.

## Errors

A failure arrives as tool content with `is_error` set, not as a JSON-RPC
protocol error, so the text is readable and says what to do: an unknown port
lists the pool, a missing lease names the holder, a refused speed names the modes
the port supports.

Return code 127 from a tool means its binary is not installed; 124 means it
timed out.
