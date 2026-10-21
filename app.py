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
SUBS: list[asyncio.Queue] = []
SCANS: dict[int, str] = {}
TASKS: set[asyncio.Task] = set()
CYCLE = 0
PROBES = 0
COST_MS = 0
LOCK = asyncio.Lock()

ADDR_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,250})$")
SSH_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]{0,31}@)?([A-Za-z0-9]([A-Za-z0-9._-]{0,250}))$")


def rt(hid):
    if hid not in RT:
        up = store.uptime(hid)
        RT[hid] = {"hist": deque(([t, l] for t, l in store.history(hid, HISTORY)), maxlen=HISTORY),
                   "svc": {}, "up": True,
                   "checks": up["checks"], "good": up["good"]}
    return RT[hid]


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
        PROBES = 0
        updates = []
        for h in hosts:
            svcs = [s for s in services.get(h["id"], []) if not s["noise"]]
            try:
                up, lat, per = await scanner.probe_host(h["address"], h["id"], svcs,
                                                        local=h["kind"] == "local")
            except Exception:
                up, lat, per = False, None, {}
            PROBES += max(1, len(svcs))
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
        CYCLE += 1
        COST_MS = round((time.perf_counter() - t0) * 1000)
        if CYCLE % 60 == 0:
            store.prune()
        await broadcast({"type": "tick", "cycle": CYCLE, "probes": PROBES,
                         "cost_ms": COST_MS, "hosts": updates})


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
            "ssh": h["ssh"] or "", "icon": h["icon"] or "server", "os": h["os"] or "",
            "by": h["by"] or "banner", "conf": h["conf"] or 0, "descr": h["descr"] or "",
            "up": r["up"], "lat": (svcs and next((s["lat"] for s in svcs if s["up"] and not s["noise"]), None))
                   or (r["hist"][-1][1] if r["hist"] else None),
            "checks": r["checks"], "good": r["good"],
            "services": svcs, "containers": store.containers(h["id"]),
            "history": [[t, l] for t, l in r["hist"]],
            "scanning": SCANS.get(h["id"]),
            "scanned": h["scanned"] or 0,
        })
    return {"interval": INTERVAL, "cycle": CYCLE, "probes": PROBES, "cost_ms": COST_MS,
            "llm": bool(LLM["url"] and LLM["model"]), "hosts": out}


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


class HostIn(BaseModel):
    kind: Literal["local", "ssh", "url"] = "url"
    address: str
    name: str = ""
    ssh: str = ""


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
    ssh = body.ssh.strip() or None
    if ssh and not SSH_RE.match(ssh):
        raise HTTPException(400, "ssh must be user@host")
    name = body.name.strip()[:60]  # empty is fine: discovery fills in rDNS/address
    hid = store.add_host(name, raw, body.kind, ssh)
    rt(hid)
    spawn(scan_job(hid))
    return {"id": hid, "address": raw}


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
    return {"ok": True, "hosts": len(store.hosts()), "cycle": CYCLE, "interval": INTERVAL}
