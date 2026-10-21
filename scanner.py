"""Discovery + probing. Pure Python: no nmap, no root, no extra daemons.

Sources of truth, strongest first:
  docker ps        -> image name is the app, published ports map to it
  HTTP fingerprint -> title / Server / favicon / login page / TLS
  banner grab      -> SSH-2.0-OpenSSH_9.6, +OK, -ERR, MySQL handshake
  port table       -> last resort
  LLM              -> only for what is still unknown, cached by fingerprint hash
"""
import asyncio
import hashlib
import json
import os
import re
import socket
import ssl
import time

import asyncssh
import httpx

# ---------------------------------------------------------------- tables
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    514: "syslog", 587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync",
    902: "vmware-auth", 993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql",
    1521: "oracle", 1723: "pptp", 1883: "mqtt", 1900: "upnp", 2049: "nfs",
    2181: "zookeeper", 2375: "docker", 2376: "docker-tls", 2379: "etcd",
    3000: "http-alt", 3128: "proxy", 3260: "iscsi", 3306: "mysql",
    3389: "rdp", 4369: "epmd", 5000: "http-alt", 5432: "postgresql",
    5601: "kibana", 5672: "amqp", 5900: "vnc", 5985: "winrm", 5986: "winrm-tls",
    6379: "redis", 6443: "kube-api", 7001: "weblogic", 7474: "neo4j",
    7687: "neo4j-bolt", 8000: "http-alt", 8008: "http-alt", 8080: "http-alt",
    8081: "http-alt", 8088: "http-alt", 8090: "http-alt", 8123: "home-assistant",
    8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9090: "prometheus",
    9093: "alertmanager", 9100: "node-exporter", 9167: "http-alt",
    9187: "pg-exporter", 9200: "elasticsearch", 9300: "elasticsearch",
    9400: "dcgm", 9443: "https-alt", 10000: "webmin", 10250: "kubelet",
    10443: "https-alt", 11211: "memcached", 15672: "rabbitmq", 27017: "mongodb",
    32400: "plex", 3001: "http-alt", 4000: "http-alt", 4001: "http-alt",
    5555: "http-alt", 7000: "http-alt",
}
WEB_PORTS = {80, 443, 3000, 3001, 4000, 4001, 5000, 5555, 5601, 7000, 7474, 8000,
             8002, 8008, 8009, 8010, 8080, 8081, 8088, 8090, 8123, 8443, 8888,
             9000, 9090, 9093, 9100, 9167, 9187, 9200, 9400, 9443, 10000, 10250,
             10443, 15672, 2375, 2376, 30000, 32400}
TLS_PORTS = {443, 465, 636, 993, 995, 2376, 5986, 6443, 8443, 9443, 10443}

# (needle, display name, icon slug, product, category)
SIGNATURES = [
    ("splunkd", "Splunk", "splunk", "Splunkd", "observability"),
    ("splunk", "Splunk", "splunk", "Splunk", "observability"),
    ("neo4j", "Neo4j", "neo4j", "Neo4j", "database"),
    ("studio 3t", "Neo4j", "neo4j", "Neo4j", "database"),
    ("postgresql", "PostgreSQL", "postgresql", "PostgreSQL", "database"),
    ("pgvector", "pgvector", "postgresql", "pgvector", "database"),
    ("mariadb", "MariaDB", "mariadb", "MariaDB", "database"),
    ("mysql", "MySQL", "mysql", "MySQL", "database"),
    ("mongodb", "MongoDB", "mongodb", "MongoDB", "database"),
    ("redis", "Redis", "redis", "Redis", "cache"),
    ("grafana", "Grafana", "grafana", "Grafana", "observability"),
    ("prometheus", "Prometheus", "prometheus", "Prometheus", "observability"),
    ("loki", "Loki", "loki", "Loki", "observability"),
    ("kibana", "Kibana", "kibana", "Kibana", "observability"),
    ("elasticsearch", "Elasticsearch", "elasticsearch", "Elasticsearch", "search"),
    ("uptime kuma", "Uptime Kuma", "uptime-kuma", "Uptime Kuma", "monitoring"),
    ("netalertx", "NetAlertX", "netalertx", "NetAlertX", "monitoring"),
    ("portainer", "Portainer", "portainer", "Portainer", "containers"),
    ("docker registry", "Docker Registry", "docker", "Distribution", "containers"),
    ("gitea", "Gitea", "gitea", "Gitea", "git"),
    ("gitlab", "GitLab", "gitlab", "GitLab", "git"),
    ("jenkins", "Jenkins", "jenkins", "Jenkins", "ci"),
    ("nextcloud", "Nextcloud", "nextcloud", "Nextcloud", "files"),
    ("jellyfin", "Jellyfin", "jellyfin", "Jellyfin", "media"),
    ("plex", "Plex", "plex", "Plex Media Server", "media"),
    ("home assistant", "Home Assistant", "home-assistant", "Home Assistant", "automation"),
    ("homeassistant", "Home Assistant", "home-assistant", "Home Assistant", "automation"),
    ("synology", "Synology DSM", "synology", "DSM", "storage"),
    ("openwrt", "OpenWrt", "openwrt", "LuCI", "network"),
    ("luci", "OpenWrt", "openwrt", "LuCI", "network"),
    ("proxmox", "Proxmox", "proxmox", "Proxmox VE", "virtualization"),
    ("vmware", "VMware", "vmware", "VMware", "virtualization"),
    ("esxi", "VMware ESXi", "vmware", "ESXi", "virtualization"),
    ("kubernetes", "Kubernetes", "kubernetes", "Kubernetes", "orchestration"),
    ("kubelet", "kubelet", "kubernetes", "kubelet", "orchestration"),
    ("rabbitmq", "RabbitMQ", "rabbitmq", "RabbitMQ", "messaging"),
    ("keycloak", "Keycloak", "keycloak", "Keycloak", "auth"),
    ("minio", "MinIO", "minio", "MinIO", "storage"),
    ("traefik", "Traefik", "traefik", "Traefik", "proxy"),
    ("caddy", "Caddy", "caddy", "Caddy", "proxy"),
    ("haproxy", "HAProxy", "haproxy", "HAProxy", "proxy"),
    ("tornado", "Tornado app", "tornado", "Tornado", "web"),
    ("uvicorn", "Uvicorn app", "fastapi", "Uvicorn", "web"),
    ("gunicorn", "Gunicorn app", "gunicorn", "Gunicorn", "web"),
    ("wsgiserver", "Python WSGI app", "python", "WSGIServer", "web"),
    ("werkzeug", "Flask app", "flask", "Werkzeug", "web"),
    ("express", "Node/Express app", "nodejs", "Express", "web"),
    ("golang net/http", "Go web service", "go", "Go net/http", "web"),
    ("go-http", "Go web service", "go", "Go net/http", "web"),
    ("tomcat", "Apache Tomcat", "tomcat", "Apache Tomcat", "java"),
    ("jetty", "Jetty", "jetty", "Jetty", "java"),
    ("apache", "Apache httpd", "apache", "Apache httpd", "web"),
    ("openresty", "OpenResty", "openresty", "OpenResty", "web"),
    ("nginx", "nginx", "nginx", "nginx", "web"),
    ("microsoft-iis", "IIS", "microsoft-iis", "Microsoft IIS", "web"),
    ("microsoft httpapi", "Windows HTTPAPI", "windows-11", "HTTPAPI", "web"),
    ("sabnzbd", "SABnzbd", "sabnzbd", "SABnzbd", "downloads"),
    ("sonarr", "Sonarr", "sonarr", "Sonarr", "media"),
    ("radarr", "Radarr", "radarr", "Radarr", "media"),
    ("pihole", "Pi-hole", "pi-hole", "Pi-hole", "network"),
    ("adguard", "AdGuard Home", "adguard-home", "AdGuard Home", "network"),
    ("n8n", "n8n", "n8n", "n8n", "automation"),
    ("ollama", "Ollama", "ollama", "Ollama", "ai"),
    ("vllm", "vLLM", "vllm", "vLLM", "ai"),
    ("litellm", "LiteLLM", "litellm", "LiteLLM", "ai"),
]

APP_NAMES = {
    "redis": "Redis", "postgres": "PostgreSQL", "postgresql": "PostgreSQL",
    "neo4j": "Neo4j", "splunk": "Splunk", "nginx": "nginx", "pgvector": "pgvector",
    "scraper": "vxcontrol scraper", "pgexporter": "Postgres Exporter",
    "postgres-exporter": "Postgres Exporter", "gitea": "Gitea", "grafana": "Grafana",
    "langfuse": "Langfuse", "keycloak": "Keycloak", "qdrant": "Qdrant", "flowise": "Flowise",
    "prometheus": "Prometheus", "nextcloud": "Nextcloud", "jellyfin": "Jellyfin",
    "ubuntu": "Ubuntu", "kube-state-metrics": "kube-state-metrics",
    "node-exporter": "node_exporter", "dcgm-exporter": "DCGM Exporter",
}
BASE_ICON = {"redis": "redis", "postgres": "postgresql", "postgresql": "postgresql",
             "keycloak": "keycloak", "qdrant": "qdrant", "flowise": "flowise",
             "mongo": "mongodb", "mongodb": "mongodb", "minio": "minio",
             "openldap": "openldap", "langfuse": "server", "flower": "server",
             "neo4j": "neo4j", "splunk": "splunk", "nginx": "nginx", "grafana": "grafana",
             "prometheus": "prometheus", "gitea": "gitea", "jellyfin": "jellyfin",
             "nextcloud": "nextcloud", "mongo": "mongodb", "mysql": "mysql",
             "mariadb": "mariadb", "rabbitmq": "rabbitmq", "traefik": "traefik",
             "portainer": "portainer", "minio": "minio", "postgres-exporter": "postgresql",
             "pgexporter": "postgresql", "pgvector": "postgresql"}


# ---------------------------------------------------------------- tcp
async def tcp_probe(address, port, timeout=1.2):
    t0 = time.perf_counter()
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(address, port), timeout)
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return True, round((time.perf_counter() - t0) * 1000, 2)
    except Exception:
        return False, None


async def scan_ports(address, ports, timeout=0.7, conc=400):
    sem = asyncio.Semaphore(conc)

    async def one(p):
        async with sem:
            ok, _ = await tcp_probe(address, p, timeout)
            return p if ok else None

    found = await asyncio.gather(*(one(p) for p in ports))
    return sorted(p for p in found if p)


async def banner_grab(address, port, timeout=0.9):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(address, port), timeout)
        try:
            data = await asyncio.wait_for(r.read(256), timeout)
        except Exception:
            data = b""
        if not data and port in (25, 110, 143, 21):
            w.write(b"\r\n")
            await w.drain()
            try:
                data = await asyncio.wait_for(r.read(256), timeout)
            except Exception:
                data = b""
        w.close()
        return data.decode("utf-8", "replace").strip()[:200]
    except Exception:
        return ""


# ---------------------------------------------------------------- http
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
TAG_RE = re.compile(r"<[^>]+>")


async def http_probe(address, port, timeout=4.0, scheme=None):
    scheme = scheme or ("https" if port in TLS_PORTS else "http")
    url = f"{scheme}://{address}:{port}/"
    out = {"url": url, "status": None, "title": "", "server": "", "powered": "",
           "tls": "", "favicon": "", "body": "", "evidence": []}
    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout,
                                     follow_redirects=True, headers={"User-Agent": "netwatch/1.0"}) as c:
            r = await c.get(url)
            out["status"] = r.status_code
            body = r.text[:6000] if r.text else ""
            out["body"] = body
            m = TITLE_RE.search(body)
            if m:
                out["title"] = TAG_RE.sub("", m.group(1)).strip()[:90]
            h = r.headers
            out["server"] = h.get("server", "")[:90]
            out["powered"] = h.get("x-powered-by", "")[:90]
            out["evidence"] += [f"HTTP {r.status_code}", f"final URL {str(r.url)[:70]}"]
            if out["server"]:
                out["evidence"].append(f"Server: {out['server']}")
            if out["powered"]:
                out["evidence"].append(f"X-Powered-By: {out['powered']}")
            if out["title"]:
                out["evidence"].append(f'title "{out["title"]}"')
            if scheme == "https":
                obj = None
                try:
                    obj = r.extensions["network_stream"].get_extra_info("ssl_object")
                except Exception:
                    pass
                out["tls"] = "TLS ok" if obj else "TLS"
                out["evidence"].append(f"{out['tls']} · {address}:{port}")
            try:
                f = await c.get(f"{scheme}://{address}:{port}/favicon.ico")
                if f.status_code == 200 and f.content:
                    fp = hashlib.sha1(f.content).hexdigest()[:10]
                    out["favicon"] = fp
                    out["evidence"].append(f"favicon sha1:{fp}")
            except Exception:
                pass
    except Exception as e:
        out["evidence"].append(f"probe failed: {type(e).__name__}")
    return out


async def http_check(url, timeout=6.0):
    """Probe one URL for a monitor. Returns (up, latency_ms, status)."""
    t0 = time.perf_counter()
    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=True,
                                     headers={"User-Agent": "netwatch/1.0"}) as c:
            r = await c.get(url)
        ms = round((time.perf_counter() - t0) * 1000, 2)
        return r.status_code < 500, ms, r.status_code
    except Exception:
        return False, None, None


def _match(text):
    low = text.lower()
    for needle, name, slug, product, cat in SIGNATURES:
        if needle in low:
            return name, slug, product, cat
    return None


# ---------------------------------------------------------------- identify
def identify(port, banner="", http=None, image=None, cname=""):
    """Return a service dict for one port."""
    ev = []
    src = "port"
    name = COMMON_PORTS.get(port, f"port {port}")
    product, version, conf, cat = "", "", 0.3, "other"
    slug = "server"
    noise = port not in COMMON_PORTS

    if image:
        base = image.split("/")[-1].split(":")[0].lower()
        if re.fullmatch(r"[0-9a-f]{12,64}", base) and cname:
            # image is an untagged build id (docker run <sha>): the container name is all we have
            name = cname.replace("-", " ").replace("_", " ")[:40]
            slug, product, conf, src, noise = "docker", image[:40], 0.9, "docker", False
        else:
            name = APP_NAMES.get(base, base.replace("-", " ").replace("_", " "))
            slug = BASE_ICON.get(base, "docker")
            product, conf, src, noise = image, 0.95, "docker", False
        ev.append(f"docker image: {image}")

    text = " ".join(x for x in [
        banner, (http or {}).get("server", ""), (http or {}).get("powered", ""),
        (http or {}).get("title", ""), (http or {}).get("body", "")[:2500]] if x)
    hit = _match(text) if text else None

    if hit and (not image or conf < 0.95):
        name, slug, product, cat = hit
        conf = max(conf, 0.9 if http else 0.72)
        src, noise = ("fp" if http else "banner"), False
        ev.append(f"matched signature: {product}")

    if http and http.get("status"):
        ev += http.get("evidence", [])
        if not hit:
            if http.get("title"):
                name = http["title"][:40]
                conf, src, noise = 0.55, "fp", False
                ev.append("named from page title")
            elif http.get("server"):
                name = http["server"].split("/")[0] or name
                conf, src, noise = 0.5, "fp", False

    if banner and not http:
        ev.append("banner: " + banner[:80])
        b = banner
        if b.startswith("SSH-"):
            m = re.search(r"SSH-2\.0-(\S+)", b)
            name = "OpenSSH" if "OpenSSH" in b else "SSH"
            product = m.group(1) if m else "SSH"
            slug, conf, src, noise = "openssh", 0.85, "banner", False
        elif b.startswith("+OK"):
            name, slug, product, conf, src, noise = "POP3", "server", "POP3", 0.7, "banner", False
        elif b.startswith("-ERR"):
            name, slug, product, conf, src, noise = "Redis", "redis", "Redis", 0.8, "banner", False
        elif "mysql" in b.lower() or "mariadb" in b.lower():
            name, slug, product, conf, src, noise = "MySQL", "mysql", "MySQL", 0.8, "banner", False
        elif b.startswith("220") and "ftp" in b.lower():
            name, slug, product, conf, src, noise = "FTP", "server", "FTP", 0.7, "banner", False
        elif b.startswith("220") and "smtp" in b.lower():
            name, slug, product, conf, src, noise = "SMTP", "server", "SMTP", 0.7, "banner", False
        elif "rtsp" in b.lower():
            name, slug, product, conf, src, noise = "RTSP camera", "hikvision", "RTSP", 0.7, "banner", False

    if http and not http.get("status") and not banner and not image:
        name, noise = "http (filtered)", True

    return {"port": port, "proto": "tcp", "name": name, "product": product,
            "version": version, "src": src, "conf": round(conf, 2), "noise": noise,
            "evidence": ev[:8], "banner": banner, "slug": slug, "category": cat}


# ---------------------------------------------------------------- docker
PORT_MAP_RE = re.compile(r"(?:0\.0\.0\.0|\[::\]|127\.0\.0\.1):(\d+)->(\d+)/(?:tcp|udp)")
RANGE_RE = re.compile(r"(?:0\.0\.0\.0|\[::\]|127\.0\.0\.1):(\d+)-(\d+)->(\d+)-(\d+)/(?:tcp|udp)")


async def _run(cmd, timeout=10):
    try:
        p = await asyncio.wait_for(
            asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE,
                                           stderr=asyncio.subprocess.DEVNULL), timeout)
        out, _ = await asyncio.wait_for(p.communicate(), timeout)
        return out.decode("utf-8", "replace")
    except Exception:
        return ""


def _parse_docker(raw):
    out = []
    for line in raw.splitlines():
        line = line.strip().strip("'")
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        out.append({"name": d.get("Names") or d.get("Name", "?"),
                    "image": d.get("Image", ""),
                    "status": d.get("Status", "") + (f" · {d['State']}" if d.get("State") and d["State"] != "running" else ""),
                    "ports": d.get("Ports", "") or "—"})
    return out


async def docker_local():
    return _parse_docker(await _run(["docker", "ps", "--format", "'{{json .}}'"]))


async def ssh_inventory(target, password="", key_path="", timeout=12):
    """One SSH connection: docker containers + OS. Returns (containers, os, error).

    Auth: password if given, else key_path, else the SSH agent / default keys.
    """
    user, _, host = target.partition("@")
    if not host:
        host, user = user, ""
    port = 22
    if ":" in host and host.rsplit(":", 1)[1].isdigit():
        host, p = host.rsplit(":", 1)
        port = int(p)
    opts = {"known_hosts": None, "login_timeout": 8, "port": port}
    if user:
        opts["username"] = user
    if password:
        opts["password"] = password
    elif key_path:
        opts["client_keys"] = [os.path.expanduser(key_path)]
    else:
        # one default key beats "try every key in ~/.ssh" (sshds drop you at MaxAuthTries)
        for cand in ("id_ed25519", "id_ecdsa", "id_rsa"):
            p = os.path.expanduser(f"~/.ssh/{cand}")
            if os.path.isfile(p):
                opts["client_keys"] = [p]
                break
    try:
        async with asyncssh.connect(host, **opts) as conn:
            r = await conn.run("docker ps --format '{{json .}}'", check=False, timeout=timeout)
            text = (r.stdout or "").strip()
            containers = _parse_docker(text)
            o = await conn.run("grep -m1 ^PRETTY_NAME /etc/os-release 2>/dev/null || uname -s",
                               check=False, timeout=5)
            osname = re.sub(r"^PRETTY_NAME=", "", (o.stdout or "").strip()).strip('"')[:60]
            err = ""
            if r.exit_status not in (0, None) and not text:
                err = (r.stderr or "docker unavailable").strip().splitlines()[-1][:80]
            return containers, osname, err
    except asyncio.TimeoutError:
        return [], "", "ssh timeout"
    except Exception as e:
        msg = str(e) or "failed"
        return [], "", f"ssh: {type(e).__name__}: {msg[:60]}"


def container_ports(containers, include_loopback=True):
    """host port -> image, from `docker ps` Ports column.

    Loopback-only bindings (127.0.0.1:9187->9187) are not reachable from
    another machine, so they are skipped for remote hosts.
    """
    m = {}
    for c in containers:
        for entry in c.get("ports", "").split(","):
            entry = entry.strip()
            if not include_loopback and entry.startswith(("127.", "[::1]")):
                continue
            rng = RANGE_RE.search(entry)
            if rng:
                a, b = int(rng.group(1)), int(rng.group(2))
                for p in range(a, min(b, a + 99) + 1):
                    m[p] = {"image": c.get("image", ""), "name": c.get("name", "")}
                continue
            for hp, _cp in PORT_MAP_RE.findall(entry):
                m[int(hp)] = {"image": c.get("image", ""), "name": c.get("name", "")}
    return m


# ---------------------------------------------------------------- LLM
async def llm_identify(host, services, cfg):
    """One call per unknown fingerprint, cached by the caller."""
    if not cfg.get("url") or not cfg.get("model"):
        return None
    evidence = {
        "host": host.get("address"),
        "hostname": host.get("name"),
        "ports": [{"port": s["port"], "service": s["name"], "product": s.get("product"),
                   "banner": (s.get("banner") or "")[:120]} for s in services[:12]],
    }
    prompt = (
        "Identify this network host/service for an infrastructure dashboard. "
        "Use the evidence only; do not invent versions. Reply with strict JSON: "
        '{"name":"short display name","slug":"selfh.st icon slug (lowercase, e.g. grafana) or \\"server\\"",'
        '"category":"one word","description":"one sentence, max 140 chars","confidence":0.0}'
        f"\n\nEvidence:\n{json.dumps(evidence, indent=1)[:3000]}"
    )
    try:
        async with httpx.AsyncClient(timeout=25) as c:
            r = await c.post(
                cfg["url"].rstrip("/") + "/chat/completions",
                headers={"Authorization": f"Bearer {cfg.get('key', '')}"},
                json={"model": cfg["model"], "temperature": 0.1,
                      "messages": [{"role": "system", "content": "You output only JSON."},
                                   {"role": "user", "content": prompt}]},
            )
            r.raise_for_status()
            text = r.json()["choices"][0]["message"]["content"].strip()
        text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.M).strip()
        d = json.loads(text)
        if not d.get("name"):
            return None
        return {"name": str(d["name"])[:40], "slug": str(d.get("slug") or "server")[:40],
                "category": str(d.get("category") or "other")[:20],
                "descr": str(d.get("description") or "")[:200],
                "conf": min(0.9, max(0.1, float(d.get("confidence") or 0.4)))}
    except Exception:
        return None


# ---------------------------------------------------------------- discovery
def _rdns(address):
    try:
        return socket.gethostbyaddr(address)[0].split(".")[0][:40]
    except Exception:
        return ""


def _guess_os(text):
    low = text.lower()
    for k, v in (("ubuntu", "Ubuntu"), ("debian", "Debian"), ("freebsd", "FreeBSD"),
                 ("windows", "Windows"), ("centos", "CentOS"), ("alpine", "Alpine"),
                 ("raspbian", "Raspberry Pi OS"), ("synology", "Synology DSM")):
        if k in low:
            return v
    return ""


async def discover(host, deep=False, llm_cfg=None, identity_lookup=None):
    address = host["address"]
    local = host.get("kind") == "local"
    probe_addr = "127.0.0.1" if local else address
    # docker is only meaningful for this machine or over SSH; otherwise skip it
    containers, remote_os, ssh_err = [], "", ""
    if local:
        containers = await docker_local()
    elif host.get("ssh"):
        containers, remote_os, ssh_err = await ssh_inventory(
            host["ssh"], host.get("ssh_pass") or "", host.get("ssh_key") or "")
    published = container_ports(containers, include_loopback=local)

    ports = list(range(1, 65536)) if deep else sorted(COMMON_PORTS)
    open_ports = await scan_ports(probe_addr, ports, timeout=0.45 if deep else 0.8,
                                  conc=500 if deep else 300)
    # a container publishing a port on this host is open by definition
    for p in published:
        if p not in open_ports:
            open_ports.append(p)

    sem = asyncio.Semaphore(8)
    services = []

    async def classify(p):
        async with sem:
            http = None
            banner = ""
            if p in WEB_PORTS:
                http = await http_probe(probe_addr, p)
                if not http.get("status"):
                    banner = await banner_grab(probe_addr, p)
            else:
                banner = await banner_grab(probe_addr, p)
                if banner.startswith("HTTP/"):
                    http = await http_probe(probe_addr, p)
            pub = published.get(p) or {}
            s = identify(p, banner, http, pub.get("image"), pub.get("name", ""))
            if http and http.get("title") and not s.get("product"):
                s["name"] = s["name"] or http["title"]
            if http:
                s["evidence"] = (s.get("evidence") or []) + [f"http {p}"]
                s["status"] = http.get("status")
            return s

    services = [s for s in await asyncio.gather(*(classify(p) for p in open_ports)) if s]
    services.sort(key=lambda s: (s["noise"], s["port"]))

    # host-level identity
    rank = {"docker": 0, "fp": 1, "banner": 2, "port": 3}
    infra = ("postgres", "redis", "mysql", "mariadb", "mongo", "memcached",
             "exporter", "pgvector", "proxy", "redis-stack")
    def interesting(s):
        img = (s.get("product") or "").lower()
        return (any(k in img for k in infra), rank.get(s["src"], 9), s["port"])
    cand = [s for s in services if s["slug"] != "server"]
    primary = sorted(cand, key=interesting)[0] if cand else None
    icon = primary["slug"] if primary else "server"
    by = "docker" if published else ("fp" if any(s["src"] == "fp" for s in services) else "banner")
    conf = max([s["conf"] for s in services], default=0.3)

    name = host.get("name") or address
    if not host.get("name"):  # no label yet: try reverse DNS, else keep the address
        name = await asyncio.to_thread(_rdns, address) or address

    text = " ".join((s.get("banner") or "") + " " + (s.get("product") or "") for s in services)
    os_guess = _guess_os(text) or remote_os

    # LLM only for hosts we could not name from strong signals
    unknown = [s for s in services if s["name"].startswith("http") or s["name"].startswith("port ")]
    llm_meta = None
    if llm_cfg and llm_cfg.get("url") and not published and unknown:
        fhash = hashlib.sha1(json.dumps(
            sorted((s["port"], s["name"], s.get("product", "")) for s in services)).encode()).hexdigest()[:16]
        cached = identity_lookup(fhash) if identity_lookup else None
        if cached:
            llm_meta = {"name": cached["name"], "slug": cached["slug"],
                        "descr": cached["descr"], "conf": 0.6, "cat": cached["category"]}
        else:
            llm_meta = await llm_identify(host, services, llm_cfg)
            llm_meta = dict(llm_meta, fhash=fhash) if llm_meta else None
        if llm_meta:
            by = "llm"
            icon = llm_meta.get("slug") or icon
            conf = llm_meta.get("conf", conf)

    apps = [s["name"] for s in sorted(services, key=lambda s: (s["noise"],) + interesting(s))][:4]
    descr = f"{len([s for s in services if not s['noise']])} open ports"
    descr += (": " + ", ".join(dict.fromkeys(apps))) if apps else " (no TCP services)"
    if containers:
        descr += f" · {len(containers)} docker containers"
    if ssh_err:
        descr += " · " + ssh_err
    if llm_meta and llm_meta.get("descr"):
        descr += " — " + llm_meta["descr"]

    return {"name": name, "icon": icon, "os": os_guess, "by": by, "conf": conf,
            "descr": descr, "services": services, "containers": containers,
            "llm": llm_meta}


# ---------------------------------------------------------------- live probe
async def probe_host(address, host_id, services, timeout=1.6, local=False):
    """One 60s cycle for one host. Returns (up, avg_lat, {port: (up, lat)})."""
    probe_addr = "127.0.0.1" if local else address
    if not services:
        t0 = time.perf_counter()
        try:
            p = await asyncio.wait_for(
                asyncio.create_subprocess_exec("ping", "-c", "1", "-W", "1", "-n", probe_addr,
                                               stdout=asyncio.subprocess.DEVNULL,
                                               stderr=asyncio.subprocess.DEVNULL), 3)
            ok = await asyncio.wait_for(p.wait(), 3) == 0
        except Exception:
            ok = False
        lat = round((time.perf_counter() - t0) * 1000, 2) if ok else None
        return ok, lat, {}

    sem = asyncio.Semaphore(24)

    async def one(s):
        async with sem:
            ok, lat = await tcp_probe(probe_addr, s["port"], timeout)
            return s["port"], ok, lat

    res = await asyncio.gather(*(one(s) for s in services))
    per = {p: (ok, lat) for p, ok, lat in res}
    ups = [lat for _, ok, lat in res if ok and lat is not None]
    return bool(ups), (round(sum(ups) / len(ups), 2) if ups else None), per
