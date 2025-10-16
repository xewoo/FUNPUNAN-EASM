#!/usr/bin/env python3
"""
easm.py
Run nmap + fscan, normalize results into sqlite, send Telegram alerts using telebot.
Dependencies:
  pip install pytelegrambotapi pyyaml
System tools required: nmap, fscan (linux binary)
"""

import os
import sys
import subprocess
import sqlite3
import json
import time
from datetime import datetime, timezone, timedelta
import yaml
import telebot
import tempfile
import xml.etree.ElementTree as ET

# ---- load config ----
CFG_PATH = "config.yaml"
if not os.path.exists(CFG_PATH):
    print("Please create config.yaml (see example).")
    sys.exit(1)

with open(CFG_PATH, "r") as f:
    cfg = yaml.safe_load(f)

TELE_TOKEN = cfg["telegram"]["token"]
TELE_CHAT = cfg["telegram"]["chat_id"]
FSCAN_BIN = cfg.get("fscan_bin", "./fscan_linux_amd64")
DB_PATH = cfg.get("database", "easm.db")
DEDUPE_MINUTES = cfg.get("dedupe_window_minutes", 30)

bot = telebot.TeleBot(TELE_TOKEN, threaded=False)

# ---- sqlite helpers ----
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS hosts (
      id INTEGER PRIMARY KEY,
      ip TEXT NOT NULL,
      port INTEGER,
      service TEXT,
      evidence TEXT,
      risk TEXT,
      first_seen TEXT,
      last_seen TEXT,
      tags TEXT,
      UNIQUE(ip, port)
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
      id INTEGER PRIMARY KEY,
      host_id INTEGER,
      severity TEXT,
      rule TEXT,
      message TEXT,
      sent INTEGER DEFAULT 0,
      created_at TEXT
    );""")
    conn.commit()
    conn.close()

def now_iso():
    return datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()

# upsert host, return host id
def upsert_host(ip, port, service, evidence, risk):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    now = now_iso()
    try:
        cur.execute("""
            INSERT INTO hosts (ip, port, service, evidence, risk, first_seen, last_seen)
            VALUES (?,?,?,?,?,?,?)
            """, (ip, port, service, evidence, risk, now, now))
        hid = cur.lastrowid
    except sqlite3.IntegrityError:
        # update
        cur.execute("""
            UPDATE hosts SET service=?, evidence=?, risk=?, last_seen=? WHERE ip=? AND port=?
        """, (service, evidence, risk, now, ip, port))
        cur.execute("SELECT id FROM hosts WHERE ip=? AND port=?", (ip, port))
        hid = cur.fetchone()[0]
    conn.commit()
    conn.close()
    return hid

def add_alert_if_needed(hid, severity, rule, message):
    if severity not in ("high","medium"):
        return
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    now = now_iso()
    cur.execute("INSERT INTO alerts (host_id, severity, rule, message, sent, created_at) VALUES (?,?,?,?,0,?)",
                (hid, severity, rule, message, now))
    conn.commit()
    conn.close()

# fetch pending alerts, dedupe by ip+port+rule within dedupe window
def get_pending_alerts():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # get unsent alerts joined with host fields
    cur.execute("""
        SELECT alerts.id, hosts.ip, hosts.port, alerts.severity, alerts.rule, alerts.message, alerts.created_at
        FROM alerts JOIN hosts ON alerts.host_id = hosts.id
        WHERE alerts.sent = 0
        ORDER BY alerts.created_at ASC
    """)
    rows = cur.fetchall()
    conn.close()
    # dedupe simple: keep first alert per (ip,port,rule) within dedupe window
    allowed = []
    seen = {}
    now = datetime.utcnow().replace(tzinfo=timezone.utc)
    window = timedelta(minutes=DEDUPE_MINUTES)
    for r in rows:
        aid, ip, port, sev, rule, msg, created = r
        key = f"{ip}:{port}:{rule}"
        created_dt = datetime.fromisoformat(created)
        if key in seen:
            prev_time = seen[key]
            if created_dt - prev_time <= window:
                # skip (duplicate in window)
                continue
        seen[key] = created_dt
        allowed.append({
            "id": aid, "ip": ip, "port": port, "severity": sev,
            "rule": rule, "message": msg, "created_at": created
        })
    return allowed

def mark_alert_sent(alert_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("UPDATE alerts SET sent = 1 WHERE id = ?", (alert_id,))
    conn.commit()
    conn.close()

# ---- scanning ----
def run_nmap(target, nmap_flags):
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.close()
    args = ["nmap"] + nmap_flags + ["-oX", tmp.name, target]
    try:
        subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3600)
    except Exception as e:
        print("nmap error:", e)
    return tmp.name

def parse_nmap_xml(xml_path):
    if not os.path.exists(xml_path):
        return
    try:
        tree = ET.parse(xml_path)
    except Exception:
        return
    root = tree.getroot()
    for host in root.findall('host'):
        addr = host.find('address')
        ip = addr.get('addr') if addr is not None else None
        ports_el = host.find('ports')
        if ports_el is None:
            continue
        for port_el in ports_el.findall('port'):
            try:
                portnum = int(port_el.get('portid'))
            except Exception:
                continue
            svc = port_el.find('service')
            service = svc.get('name') if svc is not None and 'name' in svc.attrib else ""
            banner = svc.get('product') if svc is not None and 'product' in svc.attrib else ""
            yield {"ip": ip, "port": portnum, "service": service, "banner": banner}

def run_fscan(target, fscan_flags):
    out = tempfile.NamedTemporaryFile(delete=False)
    out.close()
    args = [FSCAN_BIN] + fscan_flags + ["-o", out.name, target]
    try:
        subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1800)
    except Exception as e:
        print("fscan error:", e)
    return out.name

def parse_fscan_json(path):
    if not os.path.exists(path) or os.path.getsize(path)==0:
        return
    try:
        with open(path,"r") as f:
            j = json.load(f)
    except Exception:
        # fscan writes JSON lines or object; be forgiving
        try:
            with open(path,"r") as f:
                lines = f.read().strip().splitlines()
                for ln in lines:
                    if not ln: continue
                    try:
                        o=json.loads(ln)
                        # if hosts list
                        if isinstance(o, dict) and "hosts" in o:
                            for h in o["hosts"]:
                                ip = h.get("ip")
                                for p in h.get("ports",[]):
                                    yield {"ip": ip, "port": p.get("port"), "service": p.get("service"), "banner": p.get("banner")}
                        elif isinstance(o, dict) and "ip" in o:
                            ip = o.get("ip")
                            for p in o.get("ports",[]):
                                yield {"ip": ip, "port": p.get("port"), "service": p.get("service"), "banner": p.get("banner")}
                    except Exception:
                        continue
        except Exception:
            return
        return
    # if loaded successfully:
    # support two shapes: {"hosts":[...]} or list-of-hosts
    if isinstance(j, dict) and "hosts" in j:
        for h in j["hosts"]:
            ip = h.get("ip")
            for p in h.get("ports",[]):
                yield {"ip": ip, "port": p.get("port"), "service": p.get("service"), "banner": p.get("banner")}
    elif isinstance(j, list):
        for h in j:
            ip = h.get("ip")
            for p in h.get("ports",[]):
                yield {"ip": ip, "port": p.get("port"), "service": p.get("service"), "banner": p.get("banner")}

# ---- heuristics ----
def classify(service, banner, port):
    svc = (service or "").lower()
    b = (banner or "").lower()
    risk = "low"
    rule = ""
    if "swagger" in b or "swagger" in svc or "swagger" in service:
        risk = "high"; rule = "EXPOSED_SWAGGER"
    elif port == 3389:
        risk = "high"; rule = "OPEN_RDP"
    elif svc and "ssh" in svc or port == 22:
        risk = "medium"; rule = "OPEN_SSH"
    elif svc and ("http" in svc or "https" in svc) and ("admin" in b or "admin" in service):
        risk = "high"; rule = "POSSIBLE_ADMIN_PANEL"
    return risk, rule

# ---- notifications ----
def send_telegram_alerts():
    pend = get_pending_alerts()
    for a in pend:
        text = f"<b>[{a['severity'].upper()}] {a['rule']}</b>\nIP: {a['ip']}\nPort: {a['port']}\n{a['message']}\nTime: {a['created_at']}"
        try:
            bot.send_message(TELE_CHAT, text, parse_mode="HTML")
            mark_alert_sent(a["id"])
            print("Sent alert:", a["ip"], a["port"], a["rule"])
        except Exception as e:
            print("Telegram send error:", e)

# ---- main run loop (one-shot) ----
def scan_targets(targets, profile="deep"):
    profile_cfg = cfg["scan_profiles"].get(profile, {})
    nmap_flags = profile_cfg.get("nmap_flags", cfg.get("nmap_args", []))
    fscan_flags = profile_cfg.get("fscan_flags", [])
    for t in targets:
        print("Scanning", t)
        nx = run_nmap(t, nmap_flags)
        for rec in parse_nmap_xml(nx):
            ip = rec.get("ip"); port = rec.get("port"); svc = rec.get("service") or ""
            banner = rec.get("banner") or ""
            risk, rule = classify(svc, banner, port)
            hid = upsert_host(ip, port, svc, banner, risk)
            add_alert_if_needed(hid, risk, rule, f"{svc} / {banner}")
        try: os.remove(nx)
        except: pass

        fx = run_fscan(t, fscan_flags)
        for rec in parse_fscan_json(fx):
            ip = rec.get("ip"); port = int(rec.get("port")) if rec.get("port") else None
            svc = rec.get("service") or ""
            banner = rec.get("banner") or ""
            if not ip or not port: continue
            risk, rule = classify(svc, banner, port)
            hid = upsert_host(ip, port, svc, banner, risk)
            add_alert_if_needed(hid, risk, rule, f"{svc} / {banner}")
        try: os.remove(fx)
        except: pass

    # after processing targets, send notifications
    send_telegram_alerts()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: easm.py <target1> [target2 ...]")
        sys.exit(2)
    init_db()
    targets = sys.argv[1:]
    scan_targets(targets)
