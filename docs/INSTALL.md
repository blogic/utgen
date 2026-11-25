# Install

Written so a session with no knowledge of this codebase can bring the daemon up
on a host it has never seen. Everything here is host-independent; the specific
machine this was developed on is described in `../README.md`.

## 1. What the host must be

- Linux with network namespace support, which is any stock kernel. Verified on
  Debian 13 trixie, kernel 6.12.
- Root. The daemon creates namespaces, moves physical NICs between them and
  drives `ethtool`, so there is no useful unprivileged mode and the unit does
  not attempt one.
- At least **two** physical NICs that are free: not carrying the management
  address, not enslaved to a bridge or bond, and not being configured by
  anything else. One NIC is enough to inject and capture, but a flow needs a
  source and a destination.

A port is moved into its own namespace, so whatever manages the host's network
must be told to leave it alone, or it will keep reclaiming it. See step 4.

## 2. Packages

| Binary | Debian package | Needed for |
|---|---|---|
| `ip` | `iproute2` | namespaces, links, addresses, VLANs. Not optional |
| `ethtool` | `ethtool` | link modes, offloads, pause, `-S` counters. Not optional |
| `iperf3` | `iperf3` | `traffic_start` |
| `trafgen` | `netsniff-ng` | `pps_start` |
| `tcpdump` | `tcpdump` | `capture_start` |
| `ss` | `iproute2` | the daemon's own port checks |
| `ping` | `iputils-ping` | populating the neighbour table for `inject_frames` |

```
apt install iproute2 ethtool iperf3 netsniff-ng tcpdump iputils-ping
```

A missing binary is reported as return code 127 by the tool that needed it, and
only disables that tool. The daemon starts without any of the optional ones.

**These paths are compiled in**, as absolute paths: `/usr/sbin/ip`,
`/usr/sbin/ethtool`, `/usr/sbin/trafgen`, `/usr/bin/iperf3`, `/usr/bin/tcpdump`,
`/usr/bin/ss`, `/usr/bin/ping`, `/usr/bin/journalctl`. They are correct on
Debian and on any distribution with `usrmerge`, where `/usr/sbin` resolves. On a
distribution that puts `trafgen` in `/usr/bin`, symlink it or edit the constant
at the top of the module that names it.

## 3. Build

```
apt install cargo rustc        # or rustup, 2024 edition, so >= 1.85
cd rust
cargo test                     # 153 cases, no hardware and no root needed
cargo build --release
sudo ./tools/install.sh
```

`install.sh` copies `tgend` and `tgen` to `/opt/traffic-generator/bin`, symlinks
`tgen` into `/usr/local/bin`, installs the unit, and installs the config only if
none is already there. It **deliberately does not build**: cargo as root leaves a
root-owned `target/` that breaks every later developer build.

Run `cargo test` before trusting a build. It covers the config validator, the
lease store, the run store, every engine's argument construction and summary
parser, the checksum used by frame injection and the listen-port allocator, with
no hardware.

## 4. Stop the host's network manager touching the ports

Whatever manages the host's network will otherwise re-add addresses to a port,
or pull it back out of its namespace. Both of these are sufficient on their own.

NetworkManager:

```
# /etc/NetworkManager/conf.d/99-traffic-generator.conf
[keyfile]
unmanaged-devices=interface-name:enp1s0f0np0;interface-name:enp1s0f1np1
```

`systemctl reload NetworkManager`, then confirm with
`nmcli device status`: each port must read `unmanaged`.

systemd-networkd: make sure no `.network` file matches the ports. A
`Name=en*` wildcard does match them, which is the usual cause.

The management interface must **not** be in the pool. Putting it there moves it
into a namespace and takes the host off the network, including the session doing
it.

## 5. Write the config

`/etc/traffic-generator/config.json`, mode 600 because it holds the bearer
token. Full field reference in `CONFIG.md`. The minimum:

```json
{
  "ports": [
    {"label": "p0", "iface": "enp1s0f0np0", "description": "10G-T, to board WAN"},
    {"label": "p1", "iface": "enp1s0f1np1", "description": "10G-T, to board LAN"}
  ],
  "mcp": {
    "host": "0.0.0.0",
    "port": 9140,
    "path": "/mcp",
    "token": "PASTE_A_GENERATED_TOKEN_HERE",
    "allowed_hosts": ["10.0.0.5:9140", "127.0.0.1:9140"]
  },
  "web": {"host": "0.0.0.0", "port": 9150}
}
```

Generate the token with `head -c 32 /dev/urandom | base64 | tr -d '=+/'`. The
config refuses to load with a token under 16 characters on a non-loopback bind.

There is **no auto-discovery**: a port that is not listed does not exist to the
daemon. That is deliberate, so a stray NIC cannot be picked up and torn out of
the host's network.

`ip -br link` lists candidates; match on the PCI path with
`ls -l /sys/class/net/*/device` if several cards look alike.

## 6. Start

```
systemctl enable --now tgend
systemctl status tgend
journalctl -u tgend -f
tgen ports
```

`tgen ports` printing the pool with live link state means the daemon is up, the
config parsed and the NICs are visible. The status page is at
`http://<host>:9150/`.

## 7. Connect a remote session

```
claude mcp add --transport http tgen http://<host>:9140/mcp \
  --header "Authorization: Bearer <token>"
```

Then ask it to call `ports_list`. The 32 tools carry their own descriptions and
argument schemas, and the daemon serves `TOOLS.md` over the connection itself as
the resource `tgen://guide`, so a remote session needs nothing from this
repository. It is also at `http://<host>:9150/guide.md`.

Open port 9140 to the machine that will drive it, and 9150 to wherever the
status page is read from. Both listeners bind whatever `host` says, and
`0.0.0.0` means the whole network can reach them, with only the bearer token in
front of 9140 and nothing in front of 9150.

## 8. Verify end to end

With two ports cabled directly to each other, the correct answer is known, which
makes this a test of the tool rather than of a device:

```
tgen lease acquire p0 p1 --ttl 1800
tgen endpoint create p0 --ipv4 10.90.0.1/24
tgen endpoint create p1 --ipv4 10.90.0.2/24
tgen link-wait p0 --expect 10000
tgen traffic p0 p1 --duration 10 --streams 4
tgen probe p0 p1 --rate 2000
tgen lease release
```

Expect throughput near line rate and zero loss. Any loss on a direct cable is
this tool saturating, not a device.

A `veth` pair can stand in for cabled ports to exercise the plumbing, but it
tells you nothing about offloads, link negotiation or packet rate. Do not
baseline on it.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `no configuration; refusing to guess a port pool` | no file at the config path, and `$TGEN_CONFIG` unset or wrong |
| `unknown port "eth5"; pool is: ...` | not in `ports`. The daemon only ever touches what is listed |
| `rc 127` from a tool | that tool's binary is not installed, see step 2 |
| port keeps regaining an address | step 4 was skipped or did not take |
| `endpoint ... does not exist` | `endpoint_create` not called, or its lease expired and was swept |
| lease gone after minutes | TTL expired. Renew it, or ask for a longer `ttl_s` |
| endpoints torn down on their own | the same expiry. The sweeper runs every 15 s |
| `no free listen port in N..N+64` | that many runs are in flight to one destination |
| namespaces present but no lease | a previous daemon died. Startup reconcile returns them; `systemctl restart tgend` |
| unit restarting every 5 s | a listener could not bind. `journalctl -u tgend` ends in `Address already in use (os error 98)`; something else holds 9140 or 9150 |
| `namespaces named like ours but holding another device` | a second daemon is using the same `netns_prefix`. Give each one its own, or stop one |
