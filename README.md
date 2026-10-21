# netwatch

Live LAN dashboard: every 60 s it probes each host, knows what the services *are*,
and draws the latency. One process, one SQLite file, no build step.

```
run.sh  ->  http://127.0.0.1:8099
```

## What it does

- **Add a host** from the UI (`+ Add host`): an IP/hostname, or `user@host` for SSH,
  or "this machine". Discovery starts immediately.
- **Discovers** by TCP-connecting the 300 most common ports (or all 65535 on
  *Deep scan*), grabbing banners, and pulling HTTP metadata.
- **Identifies** in this order: docker image name (local or over SSH) → HTTP
  fingerprint (title, `Server`, favicon hash, login page) → TCP banner → port table
  → optional LLM for the leftovers, cached by fingerprint hash.
- **Monitors** every meaningful port once a minute, records `up` + latency, keeps
  90 points per host, 7 days of history.
- **Shows only meaningful ports**: unidentified high ports are stored but hidden
  behind "show all N ports".
- Live via SSE; degrades to the state endpoint if the stream drops.

## Run

```bash
cd ~/Desktop/net-monitor/netwatch
./run.sh                     # creates .venv, installs 4 deps, serves :8099
```

Environment:

| var | default | meaning |
|---|---|---|
| `NETWATCH_INTERVAL` | `60` | seconds between probe cycles |
| `NETWATCH_HOST` | `127.0.0.1` | bind address — keep it loopback |
| `NETWATCH_PORT` | `8099` | HTTP port |
| `NETWATCH_LLM_URL` | — | OpenAI-compatible base, e.g. `http://llm-host:4000/v1` |
| `NETWATCH_LLM_KEY` | — | bearer token |
| `NETWATCH_LLM_MODEL` | — | model name; LLM stays off until URL+model are set |
| `NETWATCH_DB` | `./netwatch.db` | SQLite path |

## API

```
GET    /api/state                 full snapshot (hosts, services, containers, history)
GET    /api/stream                SSE: tick | scan events
POST   /api/hosts                 {kind: url|ssh|local, address, name?, ssh?}
DELETE /api/hosts/{id}
POST   /api/hosts/{id}/scan?deep=true
POST   /api/cycle                 probe every host now
GET    /api/health
```

## Known limits

- No ICMP privileges needed: hosts with no open TCP port are probed with `ping`;
  hosts that drop both are simply "down". Full port scan takes ~60 s per host.
- SSH hosts need key auth (`ssh-copy-id`) and the user in the `docker` group;
  without it you get ports + HTTP, just no container names.
- The LLM only ever *labels* a host; it never decides whether a port is open.
- Scanning a subnet you do not own is your problem. Defaults bind to loopback
  because `POST /api/hosts` can reach internal addresses.
