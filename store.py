"""SQLite persistence for netwatch. One process, one connection, a lock."""
import json
import os
import sqlite3
import threading
import time

DB_PATH = os.environ.get(
    "NETWATCH_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "netwatch.db")
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  address TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'url',
  ssh TEXT,
  icon TEXT DEFAULT 'server',
  os TEXT DEFAULT '',
  by TEXT DEFAULT 'banner',
  conf REAL DEFAULT 0,
  descr TEXT DEFAULT '',
  created REAL,
  scanned REAL
);
CREATE TABLE IF NOT EXISTS services(
  host_id INTEGER NOT NULL,
  port INTEGER NOT NULL,
  proto TEXT NOT NULL DEFAULT 'tcp',
  name TEXT DEFAULT 'unknown',
  product TEXT DEFAULT '',
  version TEXT DEFAULT '',
  src TEXT DEFAULT 'port',
  conf REAL DEFAULT 0,
  noise INTEGER DEFAULT 0,
  evidence TEXT DEFAULT '[]',
  banner TEXT DEFAULT '',
  PRIMARY KEY(host_id, port, proto)
);
CREATE TABLE IF NOT EXISTS containers(
  host_id INTEGER, name TEXT, image TEXT, status TEXT, ports TEXT
);
CREATE TABLE IF NOT EXISTS checks(host_id INTEGER, ts REAL, up INTEGER, lat REAL);
CREATE INDEX IF NOT EXISTS checks_host_ts ON checks(host_id, ts);
CREATE TABLE IF NOT EXISTS identities(
  fhash TEXT PRIMARY KEY, name TEXT, slug TEXT, category TEXT, descr TEXT, created REAL
);
"""


class Store:
    def __init__(self, path=DB_PATH):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        with self.lock:
            self.db.executescript(SCHEMA)
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.commit()

    # ---------- hosts ----------
    def hosts(self):
        with self.lock:
            return [dict(r) for r in self.db.execute("SELECT * FROM hosts ORDER BY id")]

    def host(self, hid):
        with self.lock:
            r = self.db.execute("SELECT * FROM hosts WHERE id=?", (hid,)).fetchone()
            return dict(r) if r else None

    def find_host(self, address):
        with self.lock:
            r = self.db.execute("SELECT * FROM hosts WHERE address=?", (address,)).fetchone()
            return dict(r) if r else None

    def add_host(self, name, address, kind, ssh=None):
        with self.lock:
            cur = self.db.execute(
                "INSERT INTO hosts(name,address,kind,ssh,created) VALUES(?,?,?,?,?)",
                (name, address, kind, ssh, time.time()),
            )
            self.db.commit()
            return cur.lastrowid

    def update_host(self, hid, **kw):
        if not kw:
            return
        cols = ", ".join(f"{k}=?" for k in kw)
        with self.lock:
            self.db.execute(f"UPDATE hosts SET {cols} WHERE id=?", (*kw.values(), hid))
            self.db.commit()

    def delete_host(self, hid):
        with self.lock:
            for t in ("services", "containers", "checks"):
                self.db.execute(f"DELETE FROM {t} WHERE host_id=?", (hid,))
            self.db.execute("DELETE FROM hosts WHERE id=?", (hid,))
            self.db.commit()

    # ---------- services / containers ----------
    def services(self, hid):
        with self.lock:
            rows = [dict(r) for r in self.db.execute(
                "SELECT * FROM services WHERE host_id=? ORDER BY noise, port", (hid,))]
        for r in rows:
            r["evidence"] = json.loads(r["evidence"] or "[]")
        return rows

    def all_services(self):
        out = {}
        with self.lock:
            for r in self.db.execute("SELECT * FROM services ORDER BY host_id, noise, port"):
                d = dict(r)
                d["evidence"] = json.loads(d["evidence"] or "[]")
                out.setdefault(d["host_id"], []).append(d)
        return out

    def replace_services(self, hid, services):
        with self.lock:
            self.db.execute("DELETE FROM services WHERE host_id=?", (hid,))
            self.db.executemany(
                """INSERT INTO services(host_id,port,proto,name,product,version,src,conf,noise,evidence,banner)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                [
                    (hid, s["port"], s.get("proto", "tcp"), s["name"], s.get("product", ""),
                     s.get("version", ""), s.get("src", "port"), s.get("conf", 0),
                     1 if s.get("noise") else 0, json.dumps(s.get("evidence", [])),
                     (s.get("banner") or "")[:300])
                    for s in services
                ],
            )
            self.db.commit()

    def containers(self, hid):
        with self.lock:
            return [dict(r) for r in self.db.execute(
                "SELECT name,image,status,ports FROM containers WHERE host_id=? ORDER BY name", (hid,))]

    def replace_containers(self, hid, rows):
        with self.lock:
            self.db.execute("DELETE FROM containers WHERE host_id=?", (hid,))
            self.db.executemany(
                "INSERT INTO containers(host_id,name,image,status,ports) VALUES(?,?,?,?,?)",
                [(hid, c["name"], c["image"], c["status"], c["ports"]) for c in rows],
            )
            self.db.commit()

    # ---------- checks ----------
    def log_checks(self, rows):
        """rows: [(host_id, ts, up, lat)]"""
        with self.lock:
            self.db.executemany("INSERT INTO checks(host_id,ts,up,lat) VALUES(?,?,?,?)", rows)
            self.db.commit()

    def history(self, hid, limit=90):
        with self.lock:
            rows = list(self.db.execute(
                "SELECT ts,lat FROM checks WHERE host_id=? ORDER BY ts DESC LIMIT ?", (hid, limit)))
        return [[r[0], r[1]] for r in reversed(rows)]

    def uptime(self, hid, days=7):
        with self.lock:
            r = self.db.execute(
                "SELECT COUNT(*), COALESCE(SUM(up),0) FROM checks WHERE host_id=? AND ts>?",
                (hid, time.time() - days * 86400)).fetchone()
        return {"checks": r[0], "good": r[1]}

    def prune(self, days=7):
        with self.lock:
            self.db.execute("DELETE FROM checks WHERE ts<?", (time.time() - days * 86400,))
            self.db.commit()

    # ---------- identity cache ----------
    def identity(self, fhash):
        with self.lock:
            r = self.db.execute("SELECT * FROM identities WHERE fhash=?", (fhash,)).fetchone()
            return dict(r) if r else None

    def save_identity(self, fhash, name, slug, category, descr):
        with self.lock:
            self.db.execute(
                "INSERT OR REPLACE INTO identities VALUES(?,?,?,?,?,?)",
                (fhash, name, slug, category, descr, time.time()))
            self.db.commit()
