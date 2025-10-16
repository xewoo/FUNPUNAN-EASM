#!/usr/bin/env python3
import subprocess
import xml.etree.ElementTree as ET
import requests
import shlex
import os
from datetime import datetime

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

def run_nmap(ip):
    cmd = ["nmap", "-sS", "-p-", "-T4", "--open", "--reason", "--max-retries", "2", "-oX", "-", ip]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return proc.stdout

def parse_nmap_xml(xml_str):
    root = ET.fromstring(xml_str)
    host_elems = []
    for host in root.findall("host"):
        addr = host.find("address").get("addr")
        ports = []
        ports_elem = host.find("ports")
        if ports_elem is None:
            continue
        for p in ports_elem.findall("port"):
            portid = int(p.get("portid"))
            state = p.find("state").get("state")
            service = p.find("service")
            svc_name = service.get("name") if service is not None else None
            banner = service.get("product") if service is not None and service.get("product") else ""
            if state == "open":
                ports.append({"port": portid, "service": svc_name, "banner": banner})
        if ports:
            host_elems.append({"ip": addr, "ports": ports})
    return host_elems

def send_telegram(text):
    if not TELEGRAM_TOKEN or not CHAT_ID:
        print("Telegram credentials not set in env")
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "parse_mode": "HTML",
        "text": text
    }
    r = requests.post(url, json=payload, timeout=10)
    r.raise_for_status()
    return r.json()

def main():
    target = "203.0.113.42"
    xml = run_nmap(target)
    hosts = parse_nmap_xml(xml)
    for h in hosts:
        ip = h["ip"]
        for p in h["ports"]:
            text = (
                f"<b>[OPEN PORT]</b>\nIP: {ip}\nPort: {p['port']}\nService: {p.get('service')}\n"
                f"Banner: {p.get('banner')}\nTime: {datetime.utcnow().isoformat()}Z"
            )
            print(text)
            # send_telegram(text)

if __name__ == "__main__":
    main()
