# tgend

The daemon and CLI. See `../README.md` for what the tool does and
`../docs/INSTALL.md` to bring it up.

## Build

```
cargo test                 # 159 cases, no hardware and no root
cargo build --release
sudo TGEN_CONFIG=../configs/example.json ./target/release/tgend
```

`tools/install.sh` installs a release build; it does not build, because cargo as
root leaves a root-owned `target/`.

## Layout

| Path | Role |
|---|---|
| `src/shell.rs` | subprocess runner; a missing binary is rc 127 and a timeout rc 124 |
| `src/config.rs` | config load and validation; refuses to run without a declared port pool |
| `src/leases.rs` | port ownership with TTL; `sweep` returns what it dropped so the caller reclaims |
| `src/runs.rs` | run registry, NDJSON samples, atomic metadata |
| `src/netns.rs` | namespace, link, address, VLAN and ethtool primitives |
| `src/capture.rs`, `src/echo.rs` | tcpdump and echo lifecycles, killed before their namespace goes |
| `src/engines/` | iperf3, trafgen, probe, flows: argv construction and summary parsing |
| `src/helpers/` | the namespace-side halves, run as subcommands of this binary |
| `src/core.rs` | the single orchestrator |
| `src/mcp.rs` | the 32-tool MCP surface over `Core` |
| `src/web.rs` | the status page, with `src/web/index.html` embedded, and `/guide.md` |
| `src/bin/tgen.rs` | the CLI, an MCP client |
| `src/main.rs` | bearer auth, axum, the lease sweeper, helper subcommands |

Every face calls `Core` and only `Core`, so the daemon is the single owner of
leases, namespaces and running processes.

## The helper contract

Entering a namespace means `setns`, which would move the whole daemon, so
anything that must run inside one is a subprocess. Helpers are this same binary
re-invoked under `ip netns exec` as a hidden subcommand, taking JSON on stdin and
emitting JSON on stdout.

`own_binary()` resolves `/proc/self/exe` once and strips a trailing
` (deleted)`, which the kernel appends after the binary is replaced. Without
that, spawning the literal path fails and the only symptom is "helper exited
before binding".

## The guide travels with the binary

`../docs/TOOLS.md` is `include_str!`d into `src/mcp.rs` and served as the MCP
resource `tgen://guide`, plus `/guide.md` on the web listener. A session driving
this usually runs on another machine and cannot read the repository, so the
document has to go over the connection, and embedding it means it can never
describe a different build. `instructions` stays short and points at it.

A test fails if the tool router serves a tool the guide never names, and the tool
count is pinned so that test cannot go vacuous.

## Two rmcp specifics

`rmcp` turns an `ErrorData` error branch into a JSON-RPC protocol error, which a
client surfaces as a broken call rather than something the model can read. A
`String` error branch becomes a text block with `is_error=true`, which is what a
tool failure should be, so `fault()` returns `String`.

`#[tool_handler]`'s `instructions` field takes a string literal, so it cannot
reference a constant. `get_info()` is written out instead.

## Testing

`cargo test` needs no hardware and no root: it covers config validation, the
lease and run stores, every engine's argv and summary parsing, the listen-port
allocator, and the internet checksum against the RFC 1071 vector.

A test that builds a `Core` must give it its own `netns_prefix`, or it reads the
namespaces of a daemon running on the same machine.

What cannot be unit tested is everything that needs a NIC: link negotiation,
offloads, packet rate, and whether a frame reached the wire. Verify those on a
loop between two cabled ports, where the correct answer is known and any loss is
the generator saturating rather than a device.
