# netwatch

A live dashboard of the **apps you choose to monitor** — not a wall of every port.
Every 60 s it probes each monitor (TCP connect or HTTP GET), keeps latency history,
and shows up/down with an icon and a chart. Hosts are still scanned, but only as the
place you pick services from.

```
./run.sh   ->   http://127.0.0.1:8099
```

## The model

| | what it is |
|---|---|
| **App / monitor** | one card on the dashboard: `host:port` or a URL. Up/down, latency, uptime. |
| **Host** | an inventory entry produced by a scan: ports, banners, containers, identity. |

Add apps three ways:

1. **From a scan** — `Hosts` → click a host → `+` next to any port in the service table.
2. **A URL** — `Add URL` in the header; any HTTP(S) endpoint (ingress, k8s service, healthcheck).
3. **This machine** — add it as a host, then pick the containers you care about.

Only the apps you pick are probed every cycle; everything else is inventory.

## Add a host (and let it discover)

`Add host` → address (`192.168.2.237`, `nas.local`, or `http://x:8080/` — scheme stripped).

SSH is optional and only used to read `docker ps` (container names, images, real ports):

| auth | how |
|---|---|
| **Agent / ~/.ssh** | uses `~/.ssh/id_ed25519` (or ecdsa/rsa); no config needed |
| **Key file** | path to a private key, e.g. `~/.ssh/id_ed25519` |
| **Password** | stored in `netwatch.db` (mode 0600) — a key is safer |

SSH target may include a port: `user@host:2222`. Without SSH you still get ports,
banners and HTTP fingerprints — just no container names.

## Identification

Strongest signal wins, and the source is shown per row:

```
docker image  ->  HTTP fingerprint (title / Server / favicon / login text)
              ->  banner (SSH-2.0-OpenSSH_9.6, -ERR, +OK, RTSP)
              ->  port table
              ->  LLM (optional, cached by fingerprint hash)
```

Unidentified high ports are stored but hidden behind “show N hidden ports”.

## Run

```bash
cd ~/Desktop/net-monitor/netwatch
./run.sh                     # creates .venv, installs deps, serves :8099
```

| var | default | meaning |
|---|---|---|
| `NETWATCH_INTERVAL` | `60` | seconds between probe cycles |
| `NETWATCH_HOST` | `127.0.0.1` | bind address — keep it loopback |
| `NETWATCH_PORT` | `8099` | HTTP port |
| `NETWATCH_LLM_URL` / `_KEY` / `_MODEL` | — | OpenAI-compatible endpoint; LLM off until URL+model set |
| `NETWATCH_DB` | `./netwatch.db` | SQLite file |

## API

```
GET    /api/state                      hosts + monitors + history
GET    /api/stream                     SSE: tick | scan | monitors
POST   /api/monitors                   {host_id, port} or {url, name?}
DELETE /api/monitors/{id}
POST   /api/hosts                      {kind: local|ssh|url, address, name?, ssh?, auth?, ssh_key?, ssh_password?}
PATCH  /api/hosts/{id}                 name / ssh / auth / ssh_key / ssh_password
DELETE /api/hosts/{id}
POST   /api/hosts/{id}/scan?deep=true  all 65535 ports, ~1 min
POST   /api/cycle                      probe everything now
GET    /api/health
```

## Limits

- A URL monitor is “up” when it answers with HTTP < 500; 401/404 still count as alive.
- A TCP monitor is “up” when the port accepts a connection. No payload is sent.
- Deep scan is ~65k connects: one host at a time, never on a timer.
- SSH passwords are stored in plaintext in SQLite (0600). Prefer keys.
- Bound to loopback because `POST /api/hosts` can reach any internal address.
