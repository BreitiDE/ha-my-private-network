#!/usr/bin/env python3
"""
My Private Network - a small, self-contained IP address manager.

* Pure Python standard library (3.9+), no pip packages needed
* Data is stored in a JSON file (atomic writes + .bak backup)
* Web UI over HTTPS (or HTTP) with login
* Multiple networks, ping status, CSV import/export

Quick start (standalone):
    python3 mpn.py --set-password admin     # creates config.json + first user
    python3 mpn.py --gen-cert               # self-signed TLS certificate
    python3 mpn.py                          # start the server

Home Assistant app:
    python3 mpn.py --addon                  # reads /data/options.json, ingress on 8099
"""

import argparse
import base64
import csv
import getpass
import hashlib
import hmac
import html
import io
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

APP_NAME = "My Private Network"
VERSION = "1.1.0"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MAX_BODY = 5 * 1024 * 1024
COOKIE_NAME = "mpn_session"
PBKDF2_ITERATIONS = 310000

log = logging.getLogger("mpn")

DEFAULT_CONFIG = {
    "listen_address": "0.0.0.0",
    "port": 8443,
    "data_file": "data.json",
    "log_file": "mpn.log",
    "default_network": {
        "name": "Home",
        "cidr": "192.168.0.0/24",
        "description": "Home LAN",
    },
    "tls": {"enabled": True, "cert_file": "cert.pem", "key_file": "key.pem"},
    "session_timeout_minutes": 60,
    "ping": {"enabled": True, "timeout_seconds": 1, "cache_seconds": 30, "workers": 64,
             "refresh_seconds": 60},
    "types": [
        "Router", "Switch", "Access Point", "Firewall", "Server", "NAS", "VM",
        "Container", "Client", "Laptop", "Phone", "Tablet", "Printer", "Camera",
        "IoT", "Media", "Other",
    ],
    "users": {},
}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def e(value):
    """HTML-escape any value."""
    return html.escape("" if value is None else str(value), quote=True)


def now_iso():
    return datetime.now().replace(microsecond=0).isoformat()


def fmt_dt(value):
    try:
        return datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError):
        return value or ""


def parse_dt(value):
    value = (value or "").strip()
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).replace(microsecond=0).isoformat()
    except ValueError:
        return None


def new_id():
    return secrets.token_hex(6)


def rel_path(base_dir, path):
    return path if os.path.isabs(path) else os.path.join(base_dir, path)


def b64(data):
    return base64.b64encode(data).decode("ascii")


def save_json_atomic(path, obj, backup=False, mode=None):
    directory = os.path.dirname(os.path.abspath(path))
    if backup and os.path.exists(path):
        shutil.copy2(path, path + ".bak")
    tmp = os.path.join(directory, ".%s.%s.tmp" % (os.path.basename(path), secrets.token_hex(4)))
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    if mode is not None:
        os.chmod(tmp, mode)
    os.replace(tmp, path)


def normalize_mac(value):
    value = (value or "").strip()
    if not value:
        return ""
    if re.search(r"[^0-9A-Fa-f:\-.\s]", value):
        raise ValueError("invalid characters")
    digits = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(digits) != 12:
        raise ValueError("wrong length")
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2)).upper()


def usable(net, ip):
    """True if ip may be assigned to a host inside net."""
    if ip not in net:
        return False
    if net.prefixlen >= 31:
        return True
    return ip != net.network_address and ip != net.broadcast_address


def capacity(net):
    return net.num_addresses - (0 if net.prefixlen >= 31 else 2)


def csv_guard(value):
    """Protect exported cells against spreadsheet formula injection."""
    value = "" if value is None else str(value)
    if value and value[0] in "=+-@\t\r":
        return "'" + value
    return value


def csv_unguard(value):
    value = (value or "").strip()
    if len(value) > 1 and value[0] == "'" and value[1] in "=+-@":
        return value[1:]
    return value


# --------------------------------------------------------------------------
# Passwords, sessions, login throttling
# --------------------------------------------------------------------------

def hash_password(password):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return "pbkdf2_sha256$%d$%s$%s" % (PBKDF2_ITERATIONS, b64(salt), b64(dk))


_DUMMY_HASH = hash_password(secrets.token_hex(8))


def verify_password(password, stored):
    try:
        algo, iterations, salt, expected = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 base64.b64decode(salt), int(iterations))
        return hmac.compare_digest(b64(dk), expected)
    except (ValueError, AttributeError):
        return False


class Sessions:
    def __init__(self, timeout_minutes):
        self.timeout = max(1, int(timeout_minutes)) * 60
        self.items = {}
        self.lock = threading.Lock()

    def create(self, user):
        token = secrets.token_urlsafe(32)
        with self.lock:
            self.items[token] = {
                "user": user,
                "csrf": secrets.token_urlsafe(24),
                "expires": time.time() + self.timeout,
                "flash": [],
            }
        return token

    def get(self, token):
        if not token:
            return None
        now = time.time()
        with self.lock:
            for key in [k for k, s in self.items.items() if s["expires"] < now]:
                del self.items[key]
            sess = self.items.get(token)
            if sess:
                sess["expires"] = now + self.timeout
            return sess

    def destroy(self, token):
        with self.lock:
            self.items.pop(token, None)


class LoginThrottle:
    """Block a client IP for a while after too many failed logins."""

    def __init__(self, max_failures=5, window=300):
        self.max_failures = max_failures
        self.window = window
        self.failures = {}
        self.lock = threading.Lock()

    def _recent(self, ip):
        cutoff = time.time() - self.window
        items = [t for t in self.failures.get(ip, []) if t > cutoff]
        self.failures[ip] = items
        return items

    def blocked(self, ip):
        with self.lock:
            return len(self._recent(ip)) >= self.max_failures

    def fail(self, ip):
        with self.lock:
            self._recent(ip).append(time.time())

    def reset(self, ip):
        with self.lock:
            self.failures.pop(ip, None)


# --------------------------------------------------------------------------
# Data store
# --------------------------------------------------------------------------

HOST_FIELDS = ("ip", "mac", "name", "type", "description")

HEADER_ALIASES = {
    "ip": "ip", "ip address": "ip", "ipaddress": "ip", "address": "ip",
    "mac": "mac", "mac address": "mac", "macaddress": "mac",
    "name": "name", "hostname": "name", "host": "name",
    "type": "type",
    "description": "description", "desc": "description", "comment": "description",
    "modified": "modified", "last modified": "modified", "changed": "modified",
}


def clean_host_fields(net, form):
    """Validate the per-host fields. Uniqueness is checked by the caller."""
    errors = []
    clean = {}
    ip_text = (form.get("ip") or "").strip()
    if not ip_text:
        errors.append("IP address is required.")
    else:
        try:
            ip = ipaddress.IPv4Address(ip_text)
            if not usable(net, ip):
                errors.append("%s is not a usable address in %s." % (ip, net))
            clean["ip"] = str(ip)
        except ValueError:
            errors.append("'%s' is not a valid IPv4 address." % ip_text)
    try:
        clean["mac"] = normalize_mac(form.get("mac"))
    except ValueError:
        errors.append("MAC address must contain 12 hex digits, e.g. AA:BB:CC:DD:EE:FF.")
    name = (form.get("name") or "").strip()
    if not name:
        errors.append("Name is required.")
    elif len(name) > 64:
        errors.append("Name must be 64 characters or less.")
    clean["name"] = name
    htype = (form.get("type") or "").strip()
    if len(htype) > 32:
        errors.append("Type must be 32 characters or less.")
    clean["type"] = htype
    description = (form.get("description") or "").strip()
    if len(description) > 1000:
        errors.append("Description must be 1000 characters or less.")
    clean["description"] = description
    return clean, errors


def parse_csv(text):
    """Return a list of (line_number, record) from CSV text. Raises ValueError."""
    text = (text or "").lstrip("\ufeff")
    if not text.strip():
        raise ValueError("The CSV data is empty.")
    first_line = text.splitlines()[0]
    delimiter = max([",", ";", "\t"], key=first_line.count)
    reader = csv.reader(io.StringIO(text), delimiter=delimiter)
    try:
        header_row = next(reader)
    except StopIteration:
        raise ValueError("The CSV data is empty.")
    header = [HEADER_ALIASES.get(h.strip().lower()) for h in header_row]
    if "ip" not in header or "name" not in header:
        raise ValueError("The first row must be a header with at least the columns 'ip' and 'name'.")
    records = []
    try:
        for row in reader:
            if not any(cell.strip() for cell in row):
                continue
            record = {}
            for key, value in zip(header, row):
                if key:
                    record[key] = csv_unguard(value)
            records.append((reader.line_num, record))
    except csv.Error as ex:
        raise ValueError("CSV parse error near line %d: %s" % (reader.line_num, ex))
    return records


class Store:
    def __init__(self, path, default_network=None):
        self.path = path
        self.lock = threading.RLock()
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                self.data = json.load(f)
            self.data.setdefault("networks", [])
            self.data.setdefault("hosts", [])
        else:
            self.data = {"version": 1, "networks": [], "hosts": []}
            dn = default_network or {}
            if dn.get("cidr"):
                try:
                    net = ipaddress.IPv4Network(dn["cidr"], strict=False)
                    self.data["networks"].append({
                        "id": new_id(),
                        "name": dn.get("name") or str(net),
                        "cidr": str(net),
                        "description": dn.get("description", ""),
                        "created": now_iso(),
                    })
                except ValueError:
                    log.error("Default network '%s' is not a valid IPv4 network - skipped", dn["cidr"])
            self._save()
            log.info("Created data file %s", path)

    def _save(self):
        save_json_atomic(self.path, self.data, backup=True, mode=0o600)

    # -- networks --------------------------------------------------------

    def _net(self, nid):
        return next((n for n in self.data["networks"] if n["id"] == nid), None)

    def networks(self):
        with self.lock:
            nets = [dict(n) for n in self.data["networks"]]
            for n in nets:
                n["count"] = sum(1 for h in self.data["hosts"] if h["network_id"] == n["id"])
        return sorted(nets, key=lambda n: (ipaddress.IPv4Network(n["cidr"]), n["name"].lower()))

    def network(self, nid):
        with self.lock:
            n = self._net(nid)
            return dict(n) if n else None

    def save_network(self, nid, form):
        name = (form.get("name") or "").strip()
        description = (form.get("description") or "").strip()
        cidr_text = (form.get("cidr") or "").strip()
        errors, warnings = [], []
        net = None
        if not name:
            errors.append("Name is required.")
        elif len(name) > 64:
            errors.append("Name must be 64 characters or less.")
        try:
            net = ipaddress.IPv4Network(cidr_text, strict=False)
            if net.prefixlen < 16:
                errors.append("Networks larger than /16 are not supported.")
        except ValueError:
            errors.append("'%s' is not a valid IPv4 network (e.g. 192.168.10.0/24)." % cidr_text)
        with self.lock:
            existing = self._net(nid) if nid else None
            if nid and not existing:
                errors.append("Network not found.")
            if not errors:
                for other in self.data["networks"]:
                    if other["id"] == nid:
                        continue
                    onet = ipaddress.IPv4Network(other["cidr"])
                    if onet == net:
                        errors.append("%s already exists as '%s'." % (net, other["name"]))
                    elif onet.overlaps(net):
                        warnings.append("%s overlaps with %s (%s)." % (net, other["cidr"], other["name"]))
                if existing and str(net) != existing["cidr"]:
                    outside = [h["ip"] for h in self.data["hosts"]
                               if h["network_id"] == nid
                               and not usable(net, ipaddress.IPv4Address(h["ip"]))]
                    if outside:
                        errors.append("Cannot change the range: %d address(es) would fall outside %s (e.g. %s)."
                                      % (len(outside), net, outside[0]))
            if errors:
                return None, errors, []
            if existing:
                existing.update(name=name, cidr=str(net), description=description)
                result = existing
            else:
                result = {"id": new_id(), "name": name, "cidr": str(net),
                          "description": description, "created": now_iso()}
                self.data["networks"].append(result)
            self._save()
            return dict(result), [], warnings

    def delete_network(self, nid):
        with self.lock:
            net = self._net(nid)
            if not net:
                return None, 0
            count = sum(1 for h in self.data["hosts"] if h["network_id"] == nid)
            self.data["hosts"] = [h for h in self.data["hosts"] if h["network_id"] != nid]
            self.data["networks"].remove(net)
            self._save()
            return dict(net), count

    # -- hosts -----------------------------------------------------------

    def hosts(self, nid):
        with self.lock:
            items = [dict(h) for h in self.data["hosts"] if h["network_id"] == nid]
        return sorted(items, key=lambda h: int(ipaddress.IPv4Address(h["ip"])))

    def host(self, nid, hid):
        with self.lock:
            h = next((h for h in self.data["hosts"]
                      if h["id"] == hid and h["network_id"] == nid), None)
            return dict(h) if h else None

    def next_free(self, nid):
        with self.lock:
            net = self._net(nid)
            if not net:
                return None
            used = {h["ip"] for h in self.data["hosts"] if h["network_id"] == nid}
        n = ipaddress.IPv4Network(net["cidr"])
        candidates = n.hosts() if n.prefixlen < 31 else iter(n)
        for ip in candidates:
            if str(ip) not in used:
                return str(ip)
        return None

    def save_host(self, nid, hid, form):
        with self.lock:
            net = self._net(nid)
            if not net:
                return None, ["Network not found."], []
            clean, errors = clean_host_fields(ipaddress.IPv4Network(net["cidr"]), form)
            existing = None
            if hid:
                existing = next((h for h in self.data["hosts"]
                                 if h["id"] == hid and h["network_id"] == nid), None)
                if not existing:
                    errors.append("This address entry no longer exists.")
            warnings = []
            if not errors:
                for h in self.data["hosts"]:
                    if h["network_id"] != nid or h["id"] == hid:
                        continue
                    if h["ip"] == clean["ip"]:
                        errors.append("%s is already assigned to %s." % (clean["ip"], h["name"]))
                    elif clean["mac"] and h.get("mac") == clean["mac"]:
                        warnings.append("MAC %s is also used by %s (%s)." % (clean["mac"], h["ip"], h["name"]))
            if errors:
                return None, errors, []
            if existing:
                if any(existing.get(k) != clean[k] for k in HOST_FIELDS):
                    existing.update(clean)
                    existing["modified"] = now_iso()
                result = existing
            else:
                result = dict(id=new_id(), network_id=nid, modified=now_iso(), **clean)
                self.data["hosts"].append(result)
            self._save()
            return dict(result), [], warnings

    def delete_host(self, nid, hid):
        with self.lock:
            h = next((h for h in self.data["hosts"]
                      if h["id"] == hid and h["network_id"] == nid), None)
            if not h:
                return None
            self.data["hosts"].remove(h)
            self._save()
            return dict(h)

    def import_csv(self, nid, text, mode):
        """Validate everything first; change nothing if any row is invalid."""
        result = {"added": 0, "updated": 0, "unchanged": 0, "errors": []}
        try:
            records = parse_csv(text)
        except ValueError as ex:
            result["errors"].append(str(ex))
            return result
        with self.lock:
            net = self._net(nid)
            if not net:
                result["errors"].append("Network not found.")
                return result
            n = ipaddress.IPv4Network(net["cidr"])
            seen, plan = set(), []
            for line, record in records:
                clean, errs = clean_host_fields(n, record)
                if errs:
                    result["errors"].extend("Line %d: %s" % (line, err) for err in errs)
                    continue
                if clean["ip"] in seen:
                    result["errors"].append("Line %d: %s appears more than once." % (line, clean["ip"]))
                    continue
                seen.add(clean["ip"])
                plan.append((clean, parse_dt(record.get("modified"))))
            if not result["errors"] and not plan:
                result["errors"].append("No data rows found.")
            if result["errors"]:
                return result
            if mode == "replace":
                self.data["hosts"] = [h for h in self.data["hosts"] if h["network_id"] != nid]
            existing = {h["ip"]: h for h in self.data["hosts"] if h["network_id"] == nid}
            now = now_iso()
            for clean, modified in plan:
                h = existing.get(clean["ip"])
                if h:
                    if any(h.get(k) != clean[k] for k in HOST_FIELDS):
                        h.update(clean)
                        h["modified"] = modified or now
                        result["updated"] += 1
                    else:
                        result["unchanged"] += 1
                else:
                    self.data["hosts"].append(
                        dict(id=new_id(), network_id=nid, modified=modified or now, **clean))
                    result["added"] += 1
            self._save()
        return result


# --------------------------------------------------------------------------
# Ping
# --------------------------------------------------------------------------

class Pinger:
    def __init__(self, cfg):
        self.timeout = max(1, int(cfg.get("timeout_seconds", 1)))
        self.cache_seconds = int(cfg.get("cache_seconds", 30))
        self.binary = shutil.which("ping")
        self.available = bool(cfg.get("enabled", True)) and bool(self.binary)
        self.cache = {}
        self.lock = threading.Lock()
        self.pool = ThreadPoolExecutor(max_workers=max(1, int(cfg.get("workers", 64))))
        if cfg.get("enabled", True) and not self.binary:
            log.warning("'ping' not found - reachability check disabled (dnf install iputils)")

    def _ping(self, ip):
        try:
            proc = subprocess.run(
                [self.binary, "-c", "1", "-q", "-W", str(self.timeout), ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=self.timeout + 3)
            return proc.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def check(self, ips):
        now = time.time()
        results, todo = {}, []
        with self.lock:
            for ip in ips:
                cached = self.cache.get(ip)
                if cached and now - cached[0] < self.cache_seconds:
                    results[ip] = cached[1]
                else:
                    todo.append(ip)
        for ip, ok in zip(todo, self.pool.map(self._ping, todo)):
            results[ip] = ok
            with self.lock:
                self.cache[ip] = (time.time(), ok)
        return results


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------

_SVG = ('<svg class="i" viewBox="0 0 24 24" width="16" height="16" fill="none" '
        'stroke="currentColor" stroke-width="2" stroke-linecap="round" '
        'stroke-linejoin="round" aria-hidden="true">%s</svg>')
ICONS = {
    "logo": '<rect x="9" y="2" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/>'
            '<rect x="16" y="16" width="6" height="6" rx="1"/><path d="M12 8v6M5 16v-2h14v2"/>',
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "edit": '<path d="M4 20h4L18.5 9.5a2.1 2.1 0 0 0-3-3L5 17v3"/><path d="M13.5 6.5l3 3"/>',
    "trash": '<path d="M4 7h16M10 11v6M14 11v6M5 7l1 12a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2l1-12M9 7V4h6v3"/>',
    "download": '<path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2M7 11l5 5 5-5M12 4v12"/>',
    "upload": '<path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2M7 9l5-5 5 5M12 4v12"/>',
    "logout": '<path d="M14 8V6a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h7a2 2 0 0 0 2-2v-2"/>'
              '<path d="M9 12h12l-3-3M18 15l3-3"/>',
    "layers": '<path d="M12 4l8 4-8 4-8-4 8-4M4 12l8 4 8-4M4 16l8 4 8-4"/>',
    "search": '<circle cx="10" cy="10" r="7"/><path d="M21 21l-6-6"/>',
    "user": '<circle cx="12" cy="8" r="4"/><path d="M6 21v-2a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v2"/>',
}


def icon(name, size=16):
    svg = _SVG % ICONS[name]
    if size != 16:
        svg = svg.replace('width="16" height="16"', 'width="%d" height="%d"' % (size, size))
    return svg


FAVICON = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#2f6fed" '
           'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">%s</svg>' % ICONS["logo"])

CSS = """
:root{--bg:#f4f6fa;--card:#fff;--text:#1b2330;--muted:#687385;--border:#e2e7ef;--accent:#2f6fed;
--accent-bg:#eaf0ff;--danger:#cf3b3b;--danger-bg:#fdecec;--ok:#1d9a52;--ok-bg:#e3f5ea;--warn:#a86a0c;
--warn-bg:#fdf3e1;--radius:12px;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
@media (prefers-color-scheme:dark){:root{--bg:#0f141b;--card:#171e28;--text:#e5eaf1;--muted:#8d99aa;
--border:#273142;--accent:#6c9cff;--accent-bg:#1c2944;--danger:#ff7a7a;--danger-bg:#3a1d20;--ok:#4fd083;
--ok-bg:#15301f;--warn:#f1b650;--warn-bg:#35290f}}
*{box-sizing:border-box}
body{margin:0;font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text)}
a{color:var(--accent);text-decoration:none}
.i{vertical-align:-3px;flex-shrink:0}
header{background:var(--card);border-bottom:1px solid var(--border)}
.bar{max-width:1240px;margin:0 auto;padding:10px 20px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:10px;font-weight:650;font-size:17px;color:var(--text)}
.brand .i{color:var(--accent)}
.spacer{flex:1}
.user{color:var(--muted);font-size:14px;display:flex;align-items:center;gap:6px}
main{max-width:1240px;margin:0 auto;padding:24px 20px 48px}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius)}
.head{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:18px}
h1{font-size:22px;margin:0;font-weight:650}
.sub{color:var(--muted);font-size:14px;width:100%;margin-top:-6px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:18px}
.stat{padding:14px 16px}.stat .l{font-size:13px;color:var(--muted)}.stat .v{font-size:24px;font-weight:650;margin-top:2px}
.stat .v.mono{font-size:19px}
.meter{height:6px;background:var(--border);border-radius:9px;margin-top:8px;overflow:hidden}
.meter span{display:block;height:100%;background:var(--accent)}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.search{position:relative;flex:1;min-width:220px}.search .i{position:absolute;left:11px;top:11px;color:var(--muted)}
.search input{width:100%;padding-left:34px}
input,select,textarea{font:inherit;color:inherit;background:var(--card);border:1px solid var(--border);border-radius:8px;padding:8px 10px}
textarea{resize:vertical}
input:focus,select:focus,textarea:focus{outline:2px solid var(--accent);outline-offset:-1px;border-color:transparent}
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:8px;border:1px solid var(--border);
background:var(--card);color:var(--text);cursor:pointer;font:inherit;font-size:14px;line-height:1.2;white-space:nowrap}
.btn:hover{border-color:var(--muted)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.primary:hover{filter:brightness(1.08)}
.btn.danger{color:var(--danger)}.btn.danger:hover{border-color:var(--danger)}
.btn.small{padding:6px 8px}
.btn.block{width:100%;justify-content:center;padding:10px}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:middle}
th{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:600;white-space:nowrap}
th[data-sort]{cursor:pointer;user-select:none}th[data-sort]:hover{color:var(--text)}
th[data-dir=asc]::after{content:" \\25B2";font-size:9px}th[data-dir=desc]::after{content:" \\25BC";font-size:9px}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--accent-bg)}
.mono{font-family:var(--mono);font-size:13.5px}
.muted{color:var(--muted)}.nowrap{white-space:nowrap}
.desc{max-width:340px;white-space:pre-line}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;background:var(--accent-bg);color:var(--accent);white-space:nowrap}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--border);margin-right:10px;vertical-align:1px;transition:background .3s}
.dot.up{background:var(--ok);box-shadow:0 0 0 3px var(--ok-bg)}
.dot.down{background:var(--danger);box-shadow:0 0 0 3px var(--danger-bg)}
.actions{white-space:nowrap;text-align:right}
form.inline{display:inline}
.flash{padding:10px 14px;border-radius:8px;margin-bottom:14px;font-size:14px}
.flash.ok{background:var(--ok-bg);color:var(--ok)}
.flash.warn{background:var(--warn-bg);color:var(--warn)}
.flash.error{background:var(--danger-bg);color:var(--danger)}
.flash ul{margin:4px 0 0;padding-left:18px}
.form{max-width:640px;padding:22px 24px}
.field{margin-bottom:14px}.field label{display:block;font-size:13px;font-weight:600;margin-bottom:5px}
.field input,.field textarea,.field select{width:100%}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:0 14px}
@media (max-width:600px){.grid2{grid-template-columns:1fr}}
.hint{font-size:12.5px;color:var(--muted);margin-top:4px}
.formbar{display:flex;gap:8px;margin-top:6px}
.login{max-width:370px;margin:12vh auto 0;padding:30px 28px}
.login .brand{justify-content:center;margin-bottom:22px;font-size:19px}
.empty{padding:48px 20px;text-align:center;color:var(--muted)}
.radio{display:flex;gap:18px;flex-wrap:wrap}.radio label{font-weight:400;display:flex;gap:6px;align-items:center}
code{font-family:var(--mono);font-size:13px;background:var(--accent-bg);padding:1px 5px;border-radius:5px}
footer{text-align:center;color:var(--muted);font-size:12px;padding:0 0 24px}
"""

COMMON_JS = """
document.addEventListener('submit',function(ev){var m=ev.target.getAttribute('data-confirm');
if(m&&!confirm(m))ev.preventDefault();});
"""

NET_JS = """
(function(){
var tbl=document.getElementById('hosts');if(!tbl)return;var tb=tbl.tBodies[0];
var q=document.getElementById('q');
q.addEventListener('input',function(){var t=q.value.toLowerCase().trim(),n=0;
 for(var i=0;i<tb.rows.length;i++){var r=tb.rows[i],s=r.getAttribute('data-search').indexOf(t)>=0;r.style.display=s?'':'none';if(s)n++;}
 document.getElementById('nomatch').style.display=n?'none':'';});
var sc=0,sd=1;
tbl.querySelectorAll('th[data-sort]').forEach(function(th){th.addEventListener('click',function(){
 var i=th.cellIndex,num=th.getAttribute('data-sort')==='num';if(sc===i)sd=-sd;else{sc=i;sd=1;}
 var rows=Array.prototype.slice.call(tb.rows).sort(function(a,b){var x=a.cells[i].getAttribute('data-v'),y=b.cells[i].getAttribute('data-v');
  if(num){x=+x;y=+y;}return (x>y?1:x<y?-1:0)*sd;});
 rows.forEach(function(r){tb.appendChild(r);});
 tbl.querySelectorAll('th').forEach(function(t){t.removeAttribute('data-dir');});th.setAttribute('data-dir',sd>0?'asc':'desc');});});
function ping(){fetch('api/ping/'+document.body.getAttribute('data-net'),{credentials:'same-origin'})
 .then(function(r){return r.ok?r.json():null;}).then(function(d){if(!d)return;var st=document.getElementById('reach');
  if(!d.enabled){document.querySelectorAll('.dot').forEach(function(x){x.title='Ping check disabled';});if(st)st.textContent='n/a';return;}
  var up=0,all=0;document.querySelectorAll('.dot[data-ip]').forEach(function(x){var v=d.results[x.getAttribute('data-ip')];all++;if(v)up++;
   x.classList.toggle('up',v===true);x.classList.toggle('down',v===false);x.title=v?'Reachable (answers ping)':'No ping response';});
  if(st)st.textContent=up+' / '+all;}).catch(function(){});}
ping();setInterval(ping,(+document.body.getAttribute('data-refresh')||60)*1000);
})();
"""

IMPORT_JS = """
document.getElementById('file').addEventListener('change',function(ev){var f=ev.target.files[0];if(!f)return;
var r=new FileReader();r.onload=function(){document.getElementById('csv').value=r.result;};r.readAsText(f);});
"""


def page(title, content, sess=None, networks=None, current_nid=None, body_attrs="", script="",
         base="", ingress=False):
    header = ""
    flashes = ""
    if sess is not None:
        options = []
        if current_nid is None:
            options.append('<option value="" selected>Select network&hellip;</option>')
        for n in networks or []:
            options.append('<option value="%s"%s>%s &middot; %s</option>' % (
                e(n["id"]), " selected" if n["id"] == current_nid else "", e(n["name"]), e(n["cidr"])))
        selector = ""
        if networks:
            selector = ('<select aria-label="Network" onchange="if(this.value)location.href=\'net/\'+this.value">'
                        '%s</select>' % "".join(options))
        if ingress:
            signout = ""
        else:
            signout = ('<form method="post" action="logout" class="inline">'
                       '<input type="hidden" name="csrf" value="%s">'
                       '<button class="btn" type="submit">%s Sign out</button></form>'
                       % (e(sess["csrf"]), icon("logout")))
        header = (
            '<header><div class="bar">'
            '<a class="brand" href="./">%s%s</a>%s<div class="spacer"></div>'
            '<a class="btn" href="networks">%s Networks</a>'
            '<span class="user">%s %s</span>%s'
            '</div></header>' % (icon("logo", 22), e(APP_NAME), selector, icon("layers"),
                                 icon("user"), e(sess["user"]), signout))
        for kind, message in sess["flash"]:
            flashes += '<div class="flash %s">%s</div>' % (e(kind), message)
        sess["flash"] = []
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<base href="%s/">'
        '<title>%s &middot; %s</title><link rel="icon" href="favicon.svg" type="image/svg+xml">'
        '<style>%s</style></head><body %s>%s<main>%s%s</main>'
        '<footer>%s %s</footer><script>%s%s</script></body></html>'
        % (e(base), e(title), e(APP_NAME), CSS, body_attrs, header, flashes, content,
           e(APP_NAME), e(VERSION), COMMON_JS, script))


def error_box(errors):
    if not errors:
        return ""
    return '<div class="flash error">Please fix the following:<ul>%s</ul></div>' % "".join(
        "<li>%s</li>" % e(x) for x in errors)


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------

ROUTES = [
    ("GET", r"/", "home"),
    ("GET", r"/favicon\.svg", "favicon"),
    ("GET", r"/login", "login_form"),
    ("POST", r"/login", "login"),
    ("POST", r"/logout", "logout"),
    ("GET", r"/net/(\w+)", "net_view"),
    ("GET", r"/net/(\w+)/host/new", "host_new"),
    ("GET", r"/net/(\w+)/host/(\w+)", "host_edit"),
    ("POST", r"/net/(\w+)/host/save", "host_save"),
    ("POST", r"/net/(\w+)/host/(\w+)/delete", "host_delete"),
    ("GET", r"/net/(\w+)/export\.csv", "export_csv"),
    ("GET", r"/net/(\w+)/import", "import_form"),
    ("POST", r"/net/(\w+)/import", "import_do"),
    ("GET", r"/networks", "networks"),
    ("GET", r"/networks/new", "network_new"),
    ("GET", r"/networks/(\w+)", "network_edit"),
    ("POST", r"/networks/save", "network_save"),
    ("POST", r"/networks/(\w+)/delete", "network_delete"),
    ("GET", r"/api/ping/(\w+)", "api_ping"),
]
PUBLIC = {"favicon", "login_form", "login"}


class App:
    """Holds the global state shared by all request handlers."""

    def __init__(self, cfg, cfg_path):
        self.cfg = cfg
        self.cfg_path = cfg_path
        base = os.path.dirname(os.path.abspath(cfg_path))
        self.store = Store(rel_path(base, cfg["data_file"]), cfg.get("default_network"))
        self.pinger = Pinger(cfg.get("ping", {}))
        self.sessions = Sessions(cfg.get("session_timeout_minutes", 60))
        self.throttle = LoginThrottle()


APP = None
INGRESS_PATH_RE = re.compile(r"(/[A-Za-z0-9._~-]+)*")


class Handler(BaseHTTPRequestHandler):
    server_version = "MPN/" + VERSION
    sys_version = ""
    timeout = 30
    protocol_version = "HTTP/1.1"

    # Set per listener by make_handler()
    tls = False
    ingress_mode = False
    trusted_proxies = frozenset()

    # -- plumbing --------------------------------------------------------

    def handle(self):
        try:
            super().handle()
        except (ssl.SSLError, ConnectionError, socket.timeout, OSError) as ex:
            log.debug("Connection from %s dropped: %s", self.client_address[0], ex)

    def log_message(self, fmt, *args):
        log.debug("%s %s", self.client_address[0], fmt % args)

    def do_GET(self):
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def dispatch(self, method):
        self.base = ""
        self.new_cookie = None
        try:
            self._dispatch(method)
        except Exception:
            log.exception("Error handling %s %s", method, self.path)
            try:
                self.send_html(page("Error", '<div class="card empty">Something went wrong. '
                                             'Details are in the log.</div>', base=self.base), 500)
            except Exception:
                pass

    def _ingress_user(self):
        return (self.headers.get("X-Remote-User-Display-Name")
                or self.headers.get("X-Remote-User-Name")
                or "Home Assistant").strip()[:64]

    def _dispatch(self, method):
        if self.ingress_mode:
            if self.client_address[0] not in self.trusted_proxies:
                log.warning("Rejected ingress request from %s", self.client_address[0])
                self.send_error(403, "Only Home Assistant ingress may connect to this port")
                return
            ingress_path = (self.headers.get("X-Ingress-Path") or "").rstrip("/")
            if INGRESS_PATH_RE.fullmatch(ingress_path):
                self.base = ingress_path
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        self.form = {}
        if method == "POST":
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                self.send_error(413, "Request too large")
                return
            raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            self.form = {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}
        self.token = None
        try:
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            if COOKIE_NAME in cookie:
                self.token = cookie[COOKIE_NAME].value
        except Exception:
            pass
        self.sess = APP.sessions.get(self.token)
        if self.ingress_mode:
            # Home Assistant has already authenticated the user.
            user = self._ingress_user()
            if not self.sess or self.sess["user"] != user:
                self.token = APP.sessions.create(user)
                self.sess = APP.sessions.get(self.token)
                self.new_cookie = self.cookie(self.token)
        for route_method, pattern, name in ROUTES:
            if route_method != method:
                continue
            match = re.fullmatch(pattern, path)
            if not match:
                continue
            if name not in PUBLIC and not self.sess:
                if name.startswith("api_"):
                    return self.send_json({"error": "unauthorized"}, 401)
                return self.redirect("/login")
            if method == "POST" and name != "login":
                if not hmac.compare_digest(self.form.get("csrf", ""), self.sess["csrf"]):
                    self.send_error(403, "Invalid or expired form token - reload the page and try again")
                    return
            return getattr(self, "r_" + name)(*match.groups())
        if not self.sess:
            return self.redirect("/login")
        self.not_found()

    def _security_headers(self):
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'self'")
        if self.new_cookie:
            self.send_header("Set-Cookie", self.new_cookie)

    def send_bytes(self, data, content_type, status=200, headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def send_html(self, body, status=200, headers=None):
        self.send_bytes(body.encode("utf-8"), "text/html; charset=utf-8", status, headers)

    def send_json(self, obj, status=200):
        self.send_bytes(json.dumps(obj).encode("utf-8"), "application/json", status)

    def redirect(self, location, cookie=None):
        self.send_response(303)
        self.send_header("Location", self.base + location)
        self.send_header("Content-Length", "0")
        if cookie:
            self.new_cookie = cookie
        if self.new_cookie:
            self.send_header("Set-Cookie", self.new_cookie)
        self.end_headers()

    def cookie(self, value, max_age=None):
        parts = ["%s=%s" % (COOKIE_NAME, value), "Path=%s/" % self.base, "HttpOnly", "SameSite=Strict"]
        if self.tls:
            parts.append("Secure")
        if max_age is not None:
            parts.append("Max-Age=%d" % max_age)
        return "; ".join(parts)

    def flash(self, kind, message_html):
        self.sess["flash"].append((kind, message_html))

    def audit(self, text, *args):
        log.info("[%s@%s] " + text, self.sess["user"], self.client_address[0], *args)

    def render(self, title, content, current_nid=None, body_attrs="", script="", status=200):
        self.send_html(page(title, content, self.sess, APP.store.networks(), current_nid,
                            body_attrs, script, base=self.base, ingress=self.ingress_mode), status)

    def not_found(self):
        self.render("Not found", '<div class="card empty">This page does not exist. '
                                 '<a href="./">Back to overview</a></div>', status=404)

    def csrf_input(self):
        return '<input type="hidden" name="csrf" value="%s">' % e(self.sess["csrf"])

    # -- auth ------------------------------------------------------------

    def r_favicon(self):
        self.send_bytes(FAVICON.encode(), "image/svg+xml")

    def login_page(self, error="", username="", status=200):
        err = '<div class="flash error">%s</div>' % e(error) if error else ""
        if not APP.cfg.get("users"):
            err += ('<div class="flash warn">No users are configured for direct access. '
                    'Add a user in the configuration first.</div>')
        body = (
            '<div class="card login"><div class="brand">%s<span>%s</span></div>%s'
            '<form method="post" action="login">'
            '<div class="field"><label for="u">Username</label>'
            '<input id="u" name="username" autocomplete="username" required autofocus value="%s"></div>'
            '<div class="field"><label for="p">Password</label>'
            '<input id="p" name="password" type="password" autocomplete="current-password" required></div>'
            '<button class="btn primary block" type="submit">Sign in</button></form></div>'
            % (icon("logo", 26), e(APP_NAME), err, e(username)))
        self.send_html(page("Sign in", body, base=self.base), status)

    def r_login_form(self):
        if self.sess:
            return self.redirect("/")
        self.login_page()

    def r_login(self):
        if self.ingress_mode:
            return self.redirect("/")
        client = self.client_address[0]
        username = self.form.get("username", "").strip()
        password = self.form.get("password", "")
        if APP.throttle.blocked(client):
            log.warning("Login blocked for %s (too many failures)", client)
            return self.login_page("Too many failed attempts. Try again in a few minutes.", username, 429)
        stored = APP.cfg.get("users", {}).get(username)
        ok = verify_password(password, stored or _DUMMY_HASH) and stored is not None
        if not ok:
            APP.throttle.fail(client)
            log.warning("Failed login for '%s' from %s", username, client)
            return self.login_page("Wrong username or password.", username, 401)
        APP.throttle.reset(client)
        if self.token:
            APP.sessions.destroy(self.token)
        token = APP.sessions.create(username)
        log.info("User '%s' signed in from %s", username, client)
        self.redirect("/", self.cookie(token))

    def r_logout(self):
        if self.ingress_mode:
            return self.redirect("/")
        APP.sessions.destroy(self.token)
        log.info("User '%s' signed out", self.sess["user"])
        self.redirect("/login", self.cookie("", 0))

    # -- overview --------------------------------------------------------

    def r_home(self):
        last = self.sess.get("last_net")
        if last and APP.store.network(last):
            return self.redirect("/net/%s" % last)
        nets = APP.store.networks()
        self.redirect("/net/%s" % nets[0]["id"] if nets else "/networks")

    def r_net_view(self, nid):
        net = APP.store.network(nid)
        if not net:
            return self.not_found()
        hosts = APP.store.hosts(nid)
        n = ipaddress.IPv4Network(net["cidr"])
        cap = capacity(n)
        used = len(hosts)
        pct = (used * 100.0 / cap) if cap else 0
        next_free = APP.store.next_free(nid)

        rows = []
        for h in hosts:
            search = " ".join([h["ip"], h.get("mac", ""), h["name"], h.get("type", ""),
                               h.get("description", "")]).lower()
            type_html = '<span class="badge">%s</span>' % e(h["type"]) if h.get("type") else ""
            rows.append(
                '<tr data-search="%s">'
                '<td class="nowrap" data-v="%d"><span class="dot" data-ip="%s" title="Checking&hellip;"></span>'
                '<span class="mono">%s</span></td>'
                '<td class="mono nowrap" data-v="%s">%s</td>'
                '<td data-v="%s"><strong>%s</strong></td>'
                '<td data-v="%s">%s</td>'
                '<td class="muted desc" data-v="%s">%s</td>'
                '<td class="muted nowrap" data-v="%s">%s</td>'
                '<td class="actions">'
                '<a class="btn small" href="net/%s/host/%s" title="Edit" aria-label="Edit">%s</a> '
                '<form class="inline" method="post" action="net/%s/host/%s/delete" data-confirm="%s">%s'
                '<button class="btn small danger" type="submit" title="Delete" aria-label="Delete">%s</button>'
                '</form></td></tr>' % (
                    e(search), int(ipaddress.IPv4Address(h["ip"])), e(h["ip"]), e(h["ip"]),
                    e(h.get("mac", "")), e(h.get("mac")) or '<span class="muted">&mdash;</span>',
                    e(h["name"].lower()), e(h["name"]),
                    e(h.get("type", "").lower()), type_html,
                    e(h.get("description", "").lower()), e(h.get("description", "")),
                    e(h.get("modified", "")), e(fmt_dt(h.get("modified"))),
                    e(nid), e(h["id"]), icon("edit"),
                    e(nid), e(h["id"]), e("Delete %s (%s)?" % (h["ip"], h["name"])),
                    self.csrf_input(), icon("trash")))

        if rows:
            table = (
                '<div class="card table-wrap"><table id="hosts"><thead><tr>'
                '<th data-sort="num" data-dir="asc">IP address</th><th data-sort="str">MAC address</th>'
                '<th data-sort="str">Name</th><th data-sort="str">Type</th>'
                '<th data-sort="str">Description</th><th data-sort="str">Modified</th><th></th>'
                '</tr></thead><tbody>%s</tbody></table>'
                '<div id="nomatch" class="empty" style="display:none">No addresses match your search.</div></div>'
                % "".join(rows))
        else:
            table = ('<div class="card empty">No addresses assigned in this network yet.<br><br>'
                     '<a class="btn primary" href="net/%s/host/new">%s Add address</a></div>'
                     % (e(nid), icon("plus")))

        content = (
            '<div class="head"><h1>%s</h1><span class="badge mono">%s</span>%s</div>'
            '<div class="stats">'
            '<div class="card stat"><div class="l">Assigned</div><div class="v">%d</div>'
            '<div class="meter"><span style="width:%.1f%%"></span></div></div>'
            '<div class="card stat"><div class="l">Free</div><div class="v">%d</div></div>'
            '<div class="card stat"><div class="l">Reachable (ping)</div><div class="v" id="reach">&hellip;</div></div>'
            '<div class="card stat"><div class="l">Next free address</div><div class="v mono">%s</div></div>'
            '</div>'
            '<div class="toolbar"><div class="search">%s<input id="q" type="search" '
            'placeholder="Search IP, MAC, name, type, description" autocomplete="off"></div>'
            '<a class="btn primary" href="net/%s/host/new">%s Add address</a>'
            '<a class="btn" href="net/%s/export.csv">%s Export CSV</a>'
            '<a class="btn" href="net/%s/import">%s Import CSV</a></div>%s' % (
                e(net["name"]), e(net["cidr"]),
                '<div class="sub">%s</div>' % e(net["description"]) if net.get("description") else "",
                used, min(pct, 100), cap - used,
                e(next_free) if next_free else "&mdash;",
                icon("search"), e(nid), icon("plus"), e(nid), icon("download"), e(nid), icon("upload"),
                table))
        self.sess["last_net"] = nid
        refresh = int(APP.cfg.get("ping", {}).get("refresh_seconds", 60))
        self.render(net["name"], content, nid, 'data-net="%s" data-refresh="%d"' % (e(nid), refresh),
                    NET_JS if rows else "")

    # -- hosts -----------------------------------------------------------

    def host_form(self, net, values, hid=None, errors=None, status=200):
        types = APP.cfg.get("types", [])
        datalist = "".join('<option value="%s">' % e(t) for t in types)
        title = "Edit address" if hid else "Add address"
        n = ipaddress.IPv4Network(net["cidr"])
        first = n.network_address + (0 if n.prefixlen >= 31 else 1)
        last = n.broadcast_address - (0 if n.prefixlen >= 31 else 1)
        content = (
            '<div class="head"><h1>%s</h1><span class="badge mono">%s &middot; %s</span></div>%s'
            '<form class="card form" method="post" action="net/%s/host/save">%s'
            '<input type="hidden" name="hid" value="%s">'
            '<div class="grid2">'
            '<div class="field"><label for="ip">IP address *</label>'
            '<input id="ip" name="ip" class="mono" required value="%s" autofocus>'
            '<div class="hint">Usable range %s &ndash; %s</div></div>'
            '<div class="field"><label for="mac">MAC address</label>'
            '<input id="mac" name="mac" class="mono" value="%s" placeholder="AA:BB:CC:DD:EE:FF">'
            '<div class="hint">Any format, will be normalized</div></div>'
            '<div class="field"><label for="name">Name *</label>'
            '<input id="name" name="name" required maxlength="64" value="%s" placeholder="nas01"></div>'
            '<div class="field"><label for="type">Type</label>'
            '<input id="type" name="type" list="types" maxlength="32" value="%s" placeholder="Server">'
            '<datalist id="types">%s</datalist></div></div>'
            '<div class="field"><label for="description">Description</label>'
            '<textarea id="description" name="description" rows="3" maxlength="1000">%s</textarea></div>'
            '<div class="formbar"><button class="btn primary" type="submit">Save</button>'
            '<a class="btn" href="net/%s">Cancel</a></div></form>' % (
                title, e(net["name"]), e(net["cidr"]), error_box(errors),
                e(net["id"]), self.csrf_input(), e(hid or ""),
                e(values.get("ip", "")), first, last,
                e(values.get("mac", "")), e(values.get("name", "")), e(values.get("type", "")),
                datalist, e(values.get("description", "")), e(net["id"])))
        self.render(title, content, net["id"], status=status)

    def r_host_new(self, nid):
        net = APP.store.network(nid)
        if not net:
            return self.not_found()
        self.host_form(net, {"ip": APP.store.next_free(nid) or ""})

    def r_host_edit(self, nid, hid):
        net = APP.store.network(nid)
        host = APP.store.host(nid, hid)
        if not net or not host:
            return self.not_found()
        self.host_form(net, host, hid)

    def r_host_save(self, nid):
        net = APP.store.network(nid)
        if not net:
            return self.not_found()
        hid = self.form.get("hid") or None
        host, errors, warnings = APP.store.save_host(nid, hid, self.form)
        if errors:
            return self.host_form(net, self.form, hid, errors, 400)
        for warning in warnings:
            self.flash("warn", e(warning))
        self.flash("ok", "Saved <strong>%s</strong> (%s)." % (e(host["ip"]), e(host["name"])))
        self.audit("%s %s (%s) in %s", "updated" if hid else "added", host["ip"], host["name"], net["name"])
        self.redirect("/net/%s" % nid)

    def r_host_delete(self, nid, hid):
        host = APP.store.delete_host(nid, hid)
        if host:
            self.flash("ok", "Deleted <strong>%s</strong> (%s)." % (e(host["ip"]), e(host["name"])))
            self.audit("deleted %s (%s)", host["ip"], host["name"])
        else:
            self.flash("warn", "That address was already deleted.")
        self.redirect("/net/%s" % nid)

    # -- CSV -------------------------------------------------------------

    def r_export_csv(self, nid):
        net = APP.store.network(nid)
        if not net:
            return self.not_found()
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\r\n")
        writer.writerow(["ip", "mac", "name", "type", "description", "modified"])
        for h in APP.store.hosts(nid):
            writer.writerow([csv_guard(h.get(k, "")) for k in HOST_FIELDS] +
                            [(h.get("modified") or "").replace("T", " ")])
        filename = re.sub(r"[^A-Za-z0-9._-]+", "_", "%s_%s" % (net["name"], net["cidr"].replace("/", "-")))
        self.audit("exported CSV of %s", net["name"])
        self.send_bytes(("\ufeff" + buf.getvalue()).encode("utf-8"), "text/csv; charset=utf-8",
                        headers={"Content-Disposition": 'attachment; filename="%s.csv"' % filename})

    def import_form(self, net, text="", mode="merge", errors=None, status=200):
        content = (
            '<div class="head"><h1>Import CSV</h1><span class="badge mono">%s &middot; %s</span></div>%s'
            '<form class="card form" method="post" action="net/%s/import">%s'
            '<div class="field"><label for="file">CSV file</label><input id="file" type="file" accept=".csv,text/csv">'
            '<div class="hint">The file is loaded into the text box below; you can also paste data directly.</div></div>'
            '<div class="field"><label for="csv">CSV data</label>'
            '<textarea id="csv" name="csv" rows="12" class="mono" required '
            'placeholder="ip,mac,name,type,description&#10;192.168.0.10,AA:BB:CC:DD:EE:FF,nas01,NAS,Backups">%s</textarea>'
            '<div class="hint">Header row required. Columns: <code>ip</code> and <code>name</code> (required), '
            '<code>mac</code>, <code>type</code>, <code>description</code>, <code>modified</code>. '
            'Comma, semicolon or tab separated. If any row is invalid, nothing is imported.</div></div>'
            '<div class="field"><label>Mode</label><div class="radio">'
            '<label><input type="radio" name="mode" value="merge"%s> Merge &ndash; add new, update existing by IP</label>'
            '<label><input type="radio" name="mode" value="replace"%s> Replace &ndash; delete all addresses in this network first</label>'
            '</div></div>'
            '<div class="formbar"><button class="btn primary" type="submit">%s Import</button>'
            '<a class="btn" href="net/%s">Cancel</a></div></form>' % (
                e(net["name"]), e(net["cidr"]), error_box(errors), e(net["id"]), self.csrf_input(),
                e(text), " checked" if mode != "replace" else "", " checked" if mode == "replace" else "",
                icon("upload"), e(net["id"])))
        self.render("Import CSV", content, net["id"], script=IMPORT_JS, status=status)

    def r_import_form(self, nid):
        net = APP.store.network(nid)
        if not net:
            return self.not_found()
        self.import_form(net)

    def r_import_do(self, nid):
        net = APP.store.network(nid)
        if not net:
            return self.not_found()
        text = self.form.get("csv", "")
        mode = "replace" if self.form.get("mode") == "replace" else "merge"
        result = APP.store.import_csv(nid, text, mode)
        if result["errors"]:
            errors = result["errors"]
            if len(errors) > 25:
                errors = errors[:25] + ["... and %d more." % (len(errors) - 25)]
            return self.import_form(net, text, mode, errors, 400)
        self.flash("ok", "Import finished: %d added, %d updated, %d unchanged." % (
            result["added"], result["updated"], result["unchanged"]))
        self.audit("imported CSV into %s (%s): +%d ~%d", net["name"], mode, result["added"], result["updated"])
        self.redirect("/net/%s" % nid)

    # -- networks --------------------------------------------------------

    def r_networks(self):
        rows = []
        for n in APP.store.networks():
            cap = capacity(ipaddress.IPv4Network(n["cidr"]))
            rows.append(
                '<tr><td><a href="net/%s"><strong>%s</strong></a></td><td class="mono">%s</td>'
                '<td class="nowrap">%d / %d</td><td class="muted desc">%s</td><td class="actions">'
                '<a class="btn small" href="networks/%s" title="Edit" aria-label="Edit">%s</a> '
                '<form class="inline" method="post" action="networks/%s/delete" data-confirm="%s">%s'
                '<button class="btn small danger" type="submit" title="Delete" aria-label="Delete">%s</button>'
                '</form></td></tr>' % (
                    e(n["id"]), e(n["name"]), e(n["cidr"]), n["count"], cap, e(n.get("description", "")),
                    e(n["id"]), icon("edit"), e(n["id"]),
                    e("Delete network %s (%s)%s?" % (
                        n["name"], n["cidr"],
                        " and its %d address(es)" % n["count"] if n["count"] else "")),
                    self.csrf_input(), icon("trash")))
        if rows:
            table = ('<div class="card table-wrap"><table><thead><tr><th>Name</th><th>Range</th>'
                     '<th>Assigned</th><th>Description</th><th></th></tr></thead><tbody>%s</tbody></table></div>'
                     % "".join(rows))
        else:
            table = '<div class="card empty">No networks yet. Add your first one.</div>'
        content = ('<div class="head"><h1>Networks</h1><div class="spacer"></div>'
                   '<a class="btn primary" href="networks/new">%s Add network</a></div>%s'
                   % (icon("plus"), table))
        self.render("Networks", content)

    def network_form(self, values, nid=None, errors=None, status=200):
        title = "Edit network" if nid else "Add network"
        content = (
            '<div class="head"><h1>%s</h1></div>%s'
            '<form class="card form" method="post" action="networks/save">%s'
            '<input type="hidden" name="nid" value="%s">'
            '<div class="grid2">'
            '<div class="field"><label for="name">Name *</label>'
            '<input id="name" name="name" required maxlength="64" value="%s" placeholder="IoT VLAN" autofocus></div>'
            '<div class="field"><label for="cidr">IP range (CIDR) *</label>'
            '<input id="cidr" name="cidr" class="mono" required value="%s" placeholder="192.168.20.0/24">'
            '<div class="hint">IPv4, /16 or smaller</div></div></div>'
            '<div class="field"><label for="description">Description</label>'
            '<textarea id="description" name="description" rows="2">%s</textarea></div>'
            '<div class="formbar"><button class="btn primary" type="submit">Save</button>'
            '<a class="btn" href="networks">Cancel</a></div></form>' % (
                title, error_box(errors), self.csrf_input(), e(nid or ""),
                e(values.get("name", "")), e(values.get("cidr", "")), e(values.get("description", ""))))
        self.render(title, content, status=status)

    def r_network_new(self):
        self.network_form({})

    def r_network_edit(self, nid):
        net = APP.store.network(nid)
        if not net:
            return self.not_found()
        self.network_form(net, nid)

    def r_network_save(self):
        nid = self.form.get("nid") or None
        net, errors, warnings = APP.store.save_network(nid, self.form)
        if errors:
            return self.network_form(self.form, nid, errors, 400)
        for warning in warnings:
            self.flash("warn", e(warning))
        self.flash("ok", "Saved network <strong>%s</strong> (%s)." % (e(net["name"]), e(net["cidr"])))
        self.audit("%s network %s (%s)", "updated" if nid else "added", net["name"], net["cidr"])
        self.redirect("/net/%s" % net["id"])

    def r_network_delete(self, nid):
        net, count = APP.store.delete_network(nid)
        if net:
            self.flash("ok", "Deleted network <strong>%s</strong> and %d address(es)." % (e(net["name"]), count))
            self.audit("deleted network %s (%s) with %d addresses", net["name"], net["cidr"], count)
        self.redirect("/networks")

    # -- API -------------------------------------------------------------

    def r_api_ping(self, nid):
        if not APP.store.network(nid):
            return self.send_json({"error": "not found"}, 404)
        if not APP.pinger.available:
            return self.send_json({"enabled": False})
        results = APP.pinger.check([h["ip"] for h in APP.store.hosts(nid)])
        self.send_json({"enabled": True, "results": results})


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# --------------------------------------------------------------------------
# Configuration and CLI
# --------------------------------------------------------------------------

def load_config(path):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            user_cfg = json.load(f)
        for key, value in user_cfg.items():
            if isinstance(value, dict) and isinstance(cfg.get(key), dict) and key != "users":
                cfg[key].update(value)
            else:
                cfg[key] = value
    return cfg


def save_config(path, cfg):
    save_json_atomic(path, cfg, mode=0o600)


def primary_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            return s.getsockname()[0]
    except OSError:
        return None


def generate_certificate(cfg, cfg_dir, days, extra_san):
    openssl = shutil.which("openssl")
    if not openssl:
        sys.exit("openssl not found. Install it with: sudo dnf install openssl")
    cert = rel_path(cfg_dir, cfg["tls"]["cert_file"])
    key = rel_path(cfg_dir, cfg["tls"]["key_file"])
    fqdn = socket.getfqdn()
    hostname = socket.gethostname()
    sans = ["DNS:" + fqdn, "DNS:" + hostname, "DNS:localhost", "IP:127.0.0.1"]
    ip = primary_ip()
    if ip:
        sans.append("IP:" + ip)
    for san in extra_san:
        if not re.match(r"^(DNS|IP):\S+$", san):
            sys.exit("Invalid --san value '%s' (use DNS:name or IP:address)" % san)
        sans.append(san)
    sans = list(dict.fromkeys(sans))
    cmd = [openssl, "req", "-x509", "-newkey", "rsa:3072", "-sha256", "-nodes", "-days", str(days),
           "-keyout", key, "-out", cert, "-subj", "/CN=" + fqdn,
           "-addext", "subjectAltName=" + ",".join(sans)]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if proc.returncode != 0:
        sys.exit("openssl failed:\n" + proc.stderr)
    os.chmod(key, 0o600)
    print("Certificate: %s\nKey:         %s\nValid for:   %d days\nNames:       %s"
          % (cert, key, days, ", ".join(sans)))


def read_new_password(user):
    if not sys.stdin.isatty():
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = getpass.getpass("New password for '%s': " % user)
        if password != getpass.getpass("Repeat password: "):
            sys.exit("Passwords do not match.")
    if len(password) < 8:
        sys.exit("Password must be at least 8 characters.")
    return password


def setup_logging(log_file=None, level=logging.INFO):
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S")
    root = logging.getLogger("mpn")
    root.setLevel(level)
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    root.addHandler(console)
    if log_file:
        try:
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(fmt)
            root.addHandler(fh)
        except OSError as ex:
            root.warning("Cannot open log file: %s", ex)


def make_tls_context(cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    return context


def start_server(host, port, tls_context=None, ingress=False, trusted=()):
    handler = type("IngressHandler" if ingress else "DirectHandler", (Handler,), {
        "tls": tls_context is not None,
        "ingress_mode": ingress,
        "trusted_proxies": frozenset(trusted),
    })
    httpd = Server((host, port), handler)
    if tls_context:
        httpd.socket = tls_context.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
    thread = threading.Thread(target=httpd.serve_forever, name="http-%d" % port, daemon=True)
    thread.start()
    log.info("%s listening on %s://%s:%d%s", "Ingress" if ingress else "Web UI",
             "https" if tls_context else "http", host, port,
             " (trusted proxy: %s)" % ", ".join(sorted(trusted)) if ingress else "")
    return httpd


def wait_for_shutdown(servers):
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    while not stop.wait(3600):
        pass
    log.info("Shutting down")
    for httpd in servers:
        httpd.shutdown()
        httpd.server_close()


# --------------------------------------------------------------------------
# Home Assistant app mode
# --------------------------------------------------------------------------

def addon_config(options, data_dir):
    """Translate the app options (set in the Home Assistant UI) into our config."""
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    cfg["data_file"] = os.path.join(data_dir, "data.json")
    cfg["log_file"] = ""
    cfg["default_network"] = {
        "name": (options.get("default_network_name") or "Home").strip(),
        "cidr": (options.get("default_network_cidr") or "192.168.0.0/24").strip(),
        "description": "",
    }
    types = [t.strip() for t in options.get("types") or [] if t and t.strip()]
    if types:
        cfg["types"] = types
    cfg["ping"].update({
        "enabled": bool(options.get("ping_enabled", True)),
        "timeout_seconds": int(options.get("ping_timeout", 1)),
        "refresh_seconds": int(options.get("ping_refresh_seconds", 60)),
    })
    cfg["session_timeout_minutes"] = int(options.get("session_timeout_minutes", 60))
    cfg["users"] = {}
    for user in options.get("direct_access_users") or []:
        name = (user.get("username") or "").strip()
        password = user.get("password") or ""
        if not name or not password:
            continue
        if len(password) < 8:
            log.warning("Password of direct access user '%s' is shorter than 8 characters", name)
        cfg["users"][name] = hash_password(password)
    return cfg


def run_addon(args):
    global APP
    args.data_dir = os.path.abspath(args.data_dir)
    args.ssl_dir = os.path.abspath(args.ssl_dir)
    try:
        with open(args.options, encoding="utf-8") as f:
            options = json.load(f)
    except (OSError, ValueError) as ex:
        sys.exit("Cannot read app options %s: %s" % (args.options, ex))
    level = getattr(logging, str(options.get("log_level", "info")).upper(), logging.INFO)
    setup_logging(level=logging.DEBUG if args.verbose else level)
    cfg = addon_config(options, args.data_dir)
    APP = App(cfg, cfg["data_file"])
    log.info("%s %s starting as Home Assistant app", APP_NAME, VERSION)

    servers = [start_server("0.0.0.0", args.ingress_port, ingress=True, trusted=args.trusted_proxy)]

    tls_context = None
    if options.get("direct_ssl"):
        cert = os.path.join(args.ssl_dir, options.get("certfile") or "fullchain.pem")
        key = os.path.join(args.ssl_dir, options.get("keyfile") or "privkey.pem")
        try:
            tls_context = make_tls_context(cert, key)
        except (OSError, ssl.SSLError) as ex:
            log.error("Direct access disabled: cannot load certificate %s / %s (%s)", cert, key, ex)
            servers.append(None)
    if servers[-1] is not None:
        servers.append(start_server("0.0.0.0", args.direct_port, tls_context))
        if not cfg["users"]:
            log.info("No direct access users configured - the direct port only shows a login page")
    wait_for_shutdown([s for s in servers if s is not None])


# --------------------------------------------------------------------------
# Standalone mode
# --------------------------------------------------------------------------

def main():
    global APP
    parser = argparse.ArgumentParser(description="%s %s - IP address manager" % (APP_NAME, VERSION))
    parser.add_argument("-c", "--config", default=os.path.join(SCRIPT_DIR, "config.json"),
                        help="path to config.json (default: next to this script)")
    parser.add_argument("-p", "--port", type=int, help="override the listen port")
    parser.add_argument("-l", "--listen", help="override the listen address")
    parser.add_argument("--no-tls", action="store_true", help="serve plain HTTP")
    parser.add_argument("--set-password", metavar="USER", help="create a user or change its password")
    parser.add_argument("--delete-user", metavar="USER", help="remove a user")
    parser.add_argument("--list-users", action="store_true", help="list configured users")
    parser.add_argument("--gen-cert", action="store_true", help="create a self-signed TLS certificate")
    parser.add_argument("--cert-days", type=int, default=3650, help="certificate validity (default 3650)")
    parser.add_argument("--san", action="append", default=[],
                        help="extra certificate name, e.g. DNS:ipam.home.lan or IP:192.168.0.10 (repeatable)")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    addon = parser.add_argument_group("Home Assistant app mode")
    addon.add_argument("--addon", action="store_true", help="run as Home Assistant app (ingress)")
    addon.add_argument("--options", default="/data/options.json", help="app options file")
    addon.add_argument("--data-dir", default="/data", help="persistent data directory")
    addon.add_argument("--ssl-dir", default="/ssl", help="directory of the Home Assistant certificates")
    addon.add_argument("--ingress-port", type=int, default=8099)
    addon.add_argument("--direct-port", type=int, default=8443)
    addon.add_argument("--trusted-proxy", action="append", default=None,
                       help="source IP allowed on the ingress port (default 172.30.32.2)")
    args = parser.parse_args()

    if args.addon:
        args.trusted_proxy = args.trusted_proxy or ["172.30.32.2"]
        return run_addon(args)

    cfg_path = os.path.abspath(args.config)
    cfg_dir = os.path.dirname(cfg_path)
    cfg = load_config(cfg_path)
    if not os.path.exists(cfg_path):
        save_config(cfg_path, cfg)
        print("Created default configuration: %s" % cfg_path)

    if args.set_password:
        user = args.set_password.strip()
        if not re.fullmatch(r"[A-Za-z0-9._@-]{1,32}", user):
            sys.exit("Invalid username (letters, digits, . _ @ - ; max 32).")
        cfg["users"][user] = hash_password(read_new_password(user))
        save_config(cfg_path, cfg)
        print("Password for '%s' saved." % user)
        return
    if args.delete_user:
        if cfg["users"].pop(args.delete_user, None) is None:
            sys.exit("User '%s' does not exist." % args.delete_user)
        save_config(cfg_path, cfg)
        print("User '%s' deleted." % args.delete_user)
        return
    if args.list_users:
        print("\n".join(sorted(cfg["users"])) or "(no users)")
        return
    if args.gen_cert:
        generate_certificate(cfg, cfg_dir, args.cert_days, args.san)
        return

    setup_logging(rel_path(cfg_dir, cfg["log_file"]) if cfg.get("log_file") else None,
                  logging.DEBUG if args.verbose else logging.INFO)
    if not cfg.get("users"):
        sys.exit("No users configured. Create one first:\n  python3 %s --set-password admin" % sys.argv[0])

    tls = bool(cfg["tls"].get("enabled")) and not args.no_tls
    host = args.listen or cfg.get("listen_address", "0.0.0.0")
    port = args.port or int(cfg.get("port", 8443))

    context = None
    if tls:
        cert = rel_path(cfg_dir, cfg["tls"]["cert_file"])
        key = rel_path(cfg_dir, cfg["tls"]["key_file"])
        if not (os.path.exists(cert) and os.path.exists(key)):
            sys.exit("TLS is enabled but %s / %s are missing.\nCreate them with:\n"
                     "  python3 %s --gen-cert\nor start with --no-tls." % (cert, key, sys.argv[0]))
        context = make_tls_context(cert, key)

    APP = App(cfg, cfg_path)
    log.info("%s %s starting", APP_NAME, VERSION)
    wait_for_shutdown([start_server(host, port, context)])


if __name__ == "__main__":
    main()
