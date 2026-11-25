# Configuration

One JSON file. `/etc/traffic-generator/config.json` by default, overridden by
`$TGEN_CONFIG` or `--config`. Mode 600, because it holds the bearer token.

There is no default pool and no auto-discovery. With no file the daemon refuses
to start rather than guess which NICs it may take, since taking the wrong one
removes the host from the network.

## Top level

| Field | Required | Default | Meaning |
|---|---|---|---|
| `ports` | yes | | the pool. Nothing outside it can be touched |
| `mcp` | yes | | the authenticated control listener |
| `web` | no | absent | the read-only status page. Omit it and no second listener is started |
| `netns_prefix` | no | `tgen-` | namespace for a port is this plus its label |
| `state_dir` | no | `/run/traffic-generator` | leases, endpoints, pid and helper state |
| `runs_dir` | no | `/var/lib/traffic-generator/runs` | run metadata, samples, stderr |
| `captures_dir` | no | `/var/lib/traffic-generator/captures` | pcap files |

`state_dir` on tmpfs is correct: it describes namespaces, which do not survive a
reboot either. It must survive a daemon **restart**, though, or startup
reconciliation sees live endpoints as orphans and tears them down. The unit does
this with `RuntimeDirectory=` plus `RuntimeDirectoryPreserve=restart`.

`netns_prefix` must be unique per daemon on a host. Two daemons sharing it see
each other's namespaces; the second now detects this and reports them as
`foreign` instead of tearing them down, but nothing good follows from it.

## ports[]

| Field | Required | Meaning |
|---|---|---|
| `label` | yes | the short name every tool uses. 1 to 16 characters, lowercase, digits, `-` |
| `iface` | yes | the kernel interface name. 1 to 15 characters, the `IFNAMSIZ` limit |
| `description` | no | free text, shown by `ports_list` and on the status page. Say what it is cabled to |

Labels and interfaces must both be unique. Tools accept either form, so
`ports_list` and `p0` and `enp1s0f0np0` all work, but labels keep a suite
readable and survive a NIC being replaced.

Use `description` for the wiring. It is the only place the physical layout is
recorded, and a remote session reads it to decide which port is which.

Never list the management interface. It would be moved into a namespace, taking
the host off the network.

## mcp

| Field | Required | Default | Meaning |
|---|---|---|---|
| `host` | yes | | bind address. `0.0.0.0` for a remote session, `127.0.0.1` for local only |
| `port` | yes | | TCP port |
| `path` | yes | | URL path, must start with `/`. `/mcp` by convention |
| `token` | yes | | bearer token. At least 16 characters unless bound to loopback |
| `allowed_hosts` | no | `[]` | permitted `Host` headers. Empty means any |
| `allowed_origins` | no | `[]` | permitted `Origin` headers. Empty means any |

The token is compared in constant time. A request without it gets 401.

`allowed_hosts` is the MCP specification's defence against DNS rebinding, and it
is exact string matching on `Host` **including the port**. A client reaching the
daemon by a name or address not in the list gets **403**, with a correct token.
List every form a client will use:

```json
"allowed_hosts": ["10.0.0.5:9140", "lab-host:9140", "127.0.0.1:9140"]
```

Leaving it empty accepts any `Host`, which is what the CLI and curl want if the
list is ever wrong.

## web

| Field | Required | Meaning |
|---|---|---|
| `host` | yes | bind address |
| `port` | yes | TCP port. Must differ from `mcp.port`, and the config refuses otherwise |

Unauthenticated and read-only, deliberately, so a browser can just open it. It
serves no mutating route. Keeping it off `mcp.port` is what stops an
unauthenticated route sharing the listener that requires the token; omit the
block entirely to not serve it at all.

## Rejected at load

The daemon exits with the reason rather than starting half-configured:

- `ports` empty, a duplicate `label` or `iface`, a label with illegal
  characters, a label over 16 or an interface over 15 characters
- `mcp.path` without a leading `/`
- a token under 16 characters while `mcp.host` is not loopback
- a token still containing the shipped `REPLACE_ME` placeholder, which is long
  enough to pass every other check
- `web.port` equal to `mcp.port`
- an empty `netns_prefix`
- malformed JSON, or a missing `mcp` block, naming the path

A bind failure is not a config error and happens later: the process exits with
`Address already in use`, and the unit restarts it every 5 s until the port is
free.
