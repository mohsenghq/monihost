"""netwatch — live LAN dashboard. Run: uvicorn app:app --port 8099"""
import asyncio
import json
import os
import re
import sys
import time
from collections import deque
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import scanner
from store import Store

HERE = os.path.dirname(os.path.abspath(__file__))
INTERVAL = int(os.environ.get("NETWATCH_INTERVAL", "60"))   # seconds between cycles
HISTORY = int(os.environ.get("NETWATCH_HISTORY", "90"))     # points kept per host
LLM = {
    "url": os.environ.get("NETWATCH_LLM_URL", ""),          # e.g. http://10.50.90.90:4000/v1
    "key": os.environ.get("NETWATCH_LLM_KEY", ""),
    "model": os.environ.get("NETWATCH_LLM_MODEL", ""),
}

store = Store()
RT: dict[int, dict] = {}          # host_id -> {hist, svc, up, checks, good}
RM: dict[int, dict] = {}          # monitor_id -> {hist, up, lat, status, checks, good}
SUBS: list[asyncio.Queue] = []
SCANS: dict[int, str] = {}
TASKS: set[asyncio.Task] = set()
CYCLE = 0
PROBES = 0
COST_MS = 0
LOCK = asyncio.Lock()

ADDR_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,250})$")
SSH_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]{0,31}@)?([A-Za-z0-9]([A-Za-z0-9._-]{0,250}))(:\d{1,5})?$")


def rt(hid):
    if hid not in RT:
        up = store.uptime(hid)
        RT[hid] = {"hist": deque(([t, l] for t, l in store.history(hid, HISTORY)), maxlen=HISTORY),
                   "svc": {}, "up": True,
                   "checks": up["checks"], "good": up["good"]}
    return RT[hid]


def rmon(mid):
    if mid not in RM:
        up = store.muptime(mid)
        RM[mid] = {"hist": deque(([t, l] for t, l in store.mhistory(mid, HISTORY)), maxlen=HISTORY),
                   "up": up["checks"] > 0, "lat": None, "status": None,
                   "checks": up["checks"], "good": up["good"]}
    return RM[mid]


async def broadcast(msg):
    dead = []
    for q in SUBS:
        try:
            q.put_nowait(msg)
        except asyncio.QueueFull:
            dead.append(q)
    for q in dead:
        SUBS.remove(q)


# ---------------------------------------------------------------- cycles
async def run_cycle():
    global CYCLE, PROBES, COST_MS
    if LOCK.locked():
        return
    async with LOCK:
        t0 = time.perf_counter()
        hosts = store.hosts()
        services = store.all_services()
        mons = store.monitors()
        mon_ports = {}
        for m in mons:
            if m["kind"] != "http" and m.get("host_id"):
                mon_ports.setdefault(m["host_id"], set()).add(m["port"])
        PROBES = 0
        updates = []
        by_host = {}
        for h in hosts:
            svcs = [s for s in services.get(h["id"], []) if not s["noise"]]
            have = {s["port"] for s in svcs}
            svcs += [{"port": p} for p in mon_ports.get(h["id"], set()) if p not in have]
            try:
                up, lat, per = await scanner.probe_host(h["address"], h["id"], svcs,
                                                        local=h["kind"] == "local")
            except Exception:
                up, lat, per = False, None, {}
            PROBES += max(1, len(svcs))
            by_host[h["id"]] = per
            r = rt(h["id"])
            r["up"] = up
            r["svc"] = {p: {"up": ok, "lat": l} for p, (ok, l) in per.items()}
            r["checks"] += 1
            r["good"] += 1 if up else 0
            now = time.time()
            r["hist"].append([now, lat])
            store.log_checks([(h["id"], now, 1 if up else 0, lat)])
            updates.append({"id": h["id"], "up": up, "lat": lat,
                            "checks": r["checks"], "good": r["good"],
                            "services": [{"p": p, "up": v["up"], "lat": v["lat"]}
                                         for p, v in r["svc"].items()]})
        # monitors: one result each, from the host probe or an HTTP request
        now = time.time()
        async def check_monitor(m):
            if m["kind"] == "http":
                return await scanner.http_check(m["url"])
            up, lat = by_host.get(m.get("host_id"), {}).get(m.get("port"), (False, None))
            return up, lat, None

        results = await asyncio.gather(*(check_monitor(m) for m in mons)) if mons else []
        mupdates, mrows = [], []
        for m, (up, lat, status) in zip(mons, results):
            r = rmon(m["id"])
            r.update(up=up, lat=lat, status=status)
            r["checks"] += 1
            r["good"] += 1 if up else 0
            r["hist"].append([now, lat])
            mrows.append((m["id"], now, 1 if up else 0, lat, status))
            mupdates.append({"id": m["id"], "up": up, "lat": lat, "status": status,
                             "checks": r["checks"], "good": r["good"]})
        if mrows:
            store.log_mchecks(mrows)

        CYCLE += 1
        COST_MS = round((time.perf_counter() - t0) * 1000)
        if CYCLE % 60 == 0:
            store.prune()
        await broadcast({"type": "tick", "cycle": CYCLE, "probes": PROBES,
                         "cost_ms": COST_MS, "hosts": updates, "monitors": mupdates})


async def cycle_loop():
    while True:
        t0 = time.perf_counter()
        try:
            await run_cycle()
        except Exception as e:
            print("cycle error:", e, file=sys.stderr)
        elapsed = time.perf_counter() - t0
        await asyncio.sleep(max(2, INTERVAL - elapsed))


async def scan_job(hid, deep=False):
    if hid in SCANS:
        return
    SCANS[hid] = "deep" if deep else "quick"
    await broadcast({"type": "scan", "host_id": hid, "state": "start", "deep": deep})
    try:
        host = store.host(hid)
        if not host:
            return
        data = await scanner.discover(host, deep=deep, llm_cfg=LLM, identity_lookup=store.identity)
        store.replace_services(hid, data["services"])
        store.replace_containers(hid, data["containers"])
        store.update_host(hid, name=data["name"], icon=data["icon"], os=data["os"],
                          by=data["by"], conf=data["conf"], descr=data["descr"],
                          scanned=time.time())
        if data.get("llm"):
            lm = data["llm"]
            store.save_identity(lm["fhash"], lm["name"], lm["slug"],
                                lm.get("category", ""), lm.get("descr", ""))
        await broadcast({"type": "scan", "host_id": hid, "state": "done", "deep": deep,
                         "services": len(data["services"])})
    except Exception as e:
        print("scan error:", e, file=sys.stderr)
        await broadcast({"type": "scan", "host_id": hid, "state": "error", "error": str(e)[:120]})
    finally:
        SCANS.pop(hid, None)
        await run_cycle()


def spawn(coro):
    t = asyncio.create_task(coro)
    TASKS.add(t)
    t.add_done_callback(TASKS.discard)


# ---------------------------------------------------------------- state
def build_state():
    hosts = store.hosts()
    services = store.all_services()
    out = []
    for h in hosts:
        r = rt(h["id"])
        svcs = []
        for s in services.get(h["id"], []):
            st = r["svc"].get(s["port"], {})
            svcs.append({"p": s["port"], "n": s["name"], "prod": s["product"],
                         "ver": s["version"], "src": s["src"], "conf": s["conf"],
                         "noise": bool(s["noise"]), "ev": s["evidence"],
                         "up": st.get("up", r["up"]), "lat": st.get("lat")})
        out.append({
            "id": h["id"], "name": h["name"] or h["address"], "address": h["address"], "kind": h["kind"],
            "ssh": h["ssh"] or "", "auth": h.get("ssh_auth") or "agent",
            "ssh_key": h.get("ssh_key") or "",
            "icon": h["icon"] or "server", "os": h["os"] or "",
            "by": h["by"] or "banner", "conf": h["conf"] or 0, "descr": h["descr"] or "",
            "up": r["up"], "lat": (svcs and next((s["lat"] for s in svcs if s["up"] and not s["noise"]), None))
                   or (r["hist"][-1][1] if r["hist"] else None),
            "checks": r["checks"], "good": r["good"],
            "services": svcs, "containers": store.containers(h["id"]),
            "history": [[t, l] for t, l in r["hist"]],
            "scanning": SCANS.get(h["id"]),
            "scanned": h["scanned"] or 0,
        })
    hmap = {h["id"]: h for h in hosts}
    slug_of = {(h["id"], s["port"]): s.get("slug") for h in hosts for s in services.get(h["id"], [])}
    monitors = []
    for m in store.monitors():
        r = rmon(m["id"])
        host = hmap.get(m.get("host_id")) if m.get("host_id") else None
        target = m["url"] if m["kind"] == "http" else (
            f"{host['address']}:{m['port']}" if host else f":{m['port']}")
        monitors.append({
            "id": m["id"], "name": m["name"] or target,
            "icon": (m["icon"] if m["icon"] not in ("", "server")
                     else (slug_of.get((m.get("host_id"), m.get("port"))) or "server")),
            "kind": m["kind"], "url": m["url"], "port": m["port"],
            "host_id": m["host_id"], "host": (host["name"] or host["address"]) if host else "",
            "address": host["address"] if host else "", "target": target,
            "up": r["up"], "lat": r["lat"], "status": r["status"],
            "checks": r["checks"], "good": r["good"],
            "history": [[t, l] for t, l in r["hist"]],
        })
    return {"interval": INTERVAL, "cycle": CYCLE, "probes": PROBES, "cost_ms": COST_MS,
            "llm": bool(LLM["url"] and LLM["model"]), "hosts": out, "monitors": monitors}


@asynccontextmanager
async def lifespan(app):
    # seed this machine on first run
    if not store.hosts():
        ip = "127.0.0.1"
        try:  # primary LAN address, no traffic is sent
            import socket as _s
            u = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
            u.connect(("8.8.8.8", 80))
            ip = u.getsockname()[0]
            u.close()
        except Exception:
            pass
        hid = store.add_host("this-host", ip, "local")
        spawn(scan_job(hid))
    else:  # refresh stale inventories in the background
        for h in store.hosts():
            if not h["scanned"] or time.time() - h["scanned"] > 6 * 3600:
                spawn(scan_job(h["id"]))
    task = asyncio.create_task(cycle_loop())
    yield
    task.cancel()


app = FastAPI(title="netwatch", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=os.path.join(HERE, "static")), name="static")


@app.get("/")
async def index():
    return FileResponse(os.path.join(HERE, "static", "index.html"),
                        headers={"Cache-Control": "no-cache"})


@app.get("/api/state")
async def state():
    return build_state()


@app.get("/api/stream")
async def stream():
    q = asyncio.Queue(maxsize=32)
    SUBS.append(q)

    async def gen():
        try:
            yield "retry: 3000\n\n"
            yield f"data: {json.dumps({'type': 'hello', 'interval': INTERVAL})}\n\n"
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), 15)
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
                    continue
                yield f"data: {json.dumps(msg)}\n\n"
        finally:
            if q in SUBS:
                SUBS.remove(q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


class MonitorIn(BaseModel):
    host_id: int | None = None
    port: int | None = None
    url: str = ""
    name: str = ""


async def probe_monitor_now(mid):
    """First data point for a monitor the user just added."""
    m = store.monitor(mid)
    if not m:
        return
    if m["kind"] == "http":
        up, lat, status = await scanner.http_check(m["url"])
    else:
        host = store.host(m["host_id"]) if m.get("host_id") else None
        if not host:
            return
        addr = "127.0.0.1" if host["kind"] == "local" else host["address"]
        ok, lat = await scanner.tcp_probe(addr, m["port"])
        up, status = ok, None
    r = rmon(mid)
    r.update(up=up, lat=lat, status=status)
    r["checks"] += 1
    r["good"] += 1 if up else 0
    now = time.time()
    r["hist"].append([now, lat])
    store.log_mchecks([(mid, now, 1 if up else 0, lat, status)])
    await broadcast({"type": "monitors"})


async def identify_monitor(mid):
    """After a URL monitor is added, name it from its page/headers."""
    m = store.monitor(mid)
    if not m or m["kind"] != "http":
        return
    from urllib.parse import urlsplit
    u = urlsplit(m["url"])
    port = u.port or (443 if u.scheme == "https" else 80)
    info = await scanner.http_probe(u.hostname, port, scheme=u.scheme)
    text = " ".join([info.get("server", ""), info.get("title", ""), (info.get("body") or "")[:1500]])
    hit = scanner._match(text) if text.strip() else None
    name = m["name"]
    if not name or name == u.hostname:
        name = (info.get("title") or name or u.hostname)[:60]
    store.update_monitor(mid, name=name, icon=(hit[1] if hit else m["icon"]))
    await broadcast({"type": "monitor", "id": mid})


@app.post("/api/monitors")
async def add_monitor(body: MonitorIn):
    url = body.url.strip()
    if url:
        if not re.match(r"^https?://[^\s]+$", url, re.I):
            raise HTTPException(400, "url must start with http:// or https://")
        if store.find_monitor(url=url):
            raise HTTPException(409, "already monitored")
        hostname = url.split("//", 1)[1].split("/")[0][:60]
        mid = store.add_monitor(None, None, url, "http", body.name.strip()[:60] or hostname, "server")
        rmon(mid)
        spawn(identify_monitor(mid))
        spawn(probe_monitor_now(mid))
        return {"id": mid}
    if not body.host_id or not body.port:
        raise HTTPException(400, "host_id + port, or a url")
    host = store.host(body.host_id)
    if not host:
        raise HTTPException(404, "no such host")
    svc = next((s for s in store.services(body.host_id) if s["port"] == body.port), None)
    if not svc:
        raise HTTPException(404, "port not discovered on that host")
    if store.find_monitor(body.host_id, body.port):
        raise HTTPException(409, "already monitored")
    mid = store.add_monitor(body.host_id, body.port, "", "tcp",
                            body.name.strip()[:60] or svc["name"],
                            svc.get("slug") or "server")
    rmon(mid)
    spawn(probe_monitor_now(mid))
    return {"id": mid}


@app.delete("/api/monitors/{mid}")
async def del_monitor(mid: int):
    if not store.monitor(mid):
        raise HTTPException(404, "no such monitor")
    store.delete_monitor(mid)
    RM.pop(mid, None)
    await broadcast({"type": "monitors"})
    return {"ok": True}


class HostIn(BaseModel):
    kind: Literal["local", "ssh", "url"] = "url"
    address: str
    name: str = ""
    ssh: str = ""
    auth: Literal["agent", "key", "password"] = "agent"
    ssh_key: str = ""
    ssh_password: str = ""


class HostPatch(BaseModel):
    name: str | None = None
    ssh: str | None = None
    auth: Literal["agent", "key", "password"] | None = None
    ssh_key: str | None = None
    ssh_password: str | None = None


def check_ssh(ssh, auth, key, password, require_password=False):
    """Validate SSH options, return the expanded key path."""
    if auth == "key":
        if not key:
            raise HTTPException(400, "key file path required")
        path = os.path.expanduser(key.strip())
        if not os.path.isfile(path):
            raise HTTPException(400, f"key file not found: {path}")
        key = path
    if auth == "password" and require_password and not password:
        raise HTTPException(400, "password required")
    if (auth in ("key", "password") or key or password) and not ssh:
        raise HTTPException(400, "ssh target required (user@host)")
    if ssh and not SSH_RE.match(ssh):
        raise HTTPException(400, "ssh must be user@host")
    return key.strip()


@app.post("/api/hosts")
async def add_host(body: HostIn):
    raw = body.address.strip()
    if "://" in raw:
        m = re.match(r"^[a-z]+://([^/:]+)", raw, re.I)
        raw = m.group(1) if m else raw
    raw = raw.split("/")[0].split(":")[0] if raw.count(":") <= 1 else raw
    if not ADDR_RE.match(raw):
        raise HTTPException(400, "address must be an IP or hostname")
    if store.find_host(raw):
        raise HTTPException(409, "host already added")
    ssh = body.ssh.strip()
    key = check_ssh(ssh, body.auth, body.ssh_key, body.ssh_password, require_password=True)
    name = body.name.strip()[:60]  # empty is fine: discovery fills in rDNS/address
    hid = store.add_host(name, raw, body.kind, ssh or None, key,
                         body.ssh_password if ssh else "", body.auth if ssh else "agent")
    rt(hid)
    spawn(scan_job(hid))
    return {"id": hid, "address": raw}


@app.patch("/api/hosts/{hid}")
async def patch_host(hid: int, body: HostPatch):
    h = store.host(hid)
    if not h:
        raise HTTPException(404, "no such host")
    ssh = (body.ssh.strip() if body.ssh is not None else (h["ssh"] or ""))
    auth = body.auth or (h["ssh_auth"] or "agent")
    key = (body.ssh_key.strip() if body.ssh_key is not None else (h["ssh_key"] or ""))
    pw = h["ssh_pass"] or ""
    if body.ssh_password:          # blank means "keep the current one"
        pw = body.ssh_password
    key = check_ssh(ssh, auth, key, pw, require_password=(body.auth == "password" and not pw))
    kw = {"ssh": ssh or None, "ssh_auth": auth, "ssh_key": key}
    if body.ssh_password:
        kw["ssh_pass"] = body.ssh_password
    if body.name is not None:
        kw["name"] = body.name.strip()[:60]
    store.update_host(hid, **kw)
    spawn(scan_job(hid))
    return {"ok": True}


@app.delete("/api/hosts/{hid}")
async def del_host(hid: int):
    if not store.host(hid):
        raise HTTPException(404, "no such host")
    store.delete_host(hid)
    RT.pop(hid, None)
    SCANS.pop(hid, None)
    await broadcast({"type": "removed", "host_id": hid})
    return {"ok": True}


@app.post("/api/hosts/{hid}/scan")
async def scan(hid: int, deep: bool = False):
    if not store.host(hid):
        raise HTTPException(404, "no such host")
    if hid in SCANS:
        return {"ok": False, "reason": "already scanning"}
    spawn(scan_job(hid, deep=deep))
    return {"ok": True, "deep": deep}


@app.post("/api/cycle")
async def probe_now():
    spawn(run_cycle())
    return {"ok": True}


@app.get("/api/health")
async def health():
    return {"ok": True, "hosts": len(store.hosts()), "monitors": len(store.monitors()),
            "cycle": CYCLE, "interval": INTERVAL}
