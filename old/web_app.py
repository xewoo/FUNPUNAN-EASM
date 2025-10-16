#!/usr/bin/env python3
# web_app.py
from flask import Flask, jsonify, render_template_string
import sqlite3, os
DB = os.path.join(os.path.dirname(__file__), "easm.db")
app = Flask(__name__)

def conn():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

@app.route("/api/hosts")
def api_hosts():
    c = conn()
    cur = c.execute("SELECT * FROM hosts ORDER BY last_seen DESC LIMIT 500")
    rows = [dict(r) for r in cur.fetchall()]
    c.close()
    return jsonify(rows)

@app.route("/api/alerts")
def api_alerts():
    c = conn()
    q = """SELECT alerts.*, hosts.ip, hosts.port FROM alerts JOIN hosts ON alerts.host_id=hosts.id ORDER BY alerts.created_at DESC LIMIT 200"""
    cur = c.execute(q)
    rows = [dict(r) for r in cur.fetchall()]
    c.close()
    return jsonify(rows)

INDEX = """
<!doctype html>
<html>
<head><meta charset="utf-8"><title>EASM Web</title>
<style>
body{font-family:monospace;padding:12px}
table{border-collapse:collapse;width:100%}
td,th{border:1px solid #ddd;padding:6px}
.high{background:#ffd6d6}
.medium{background:#fff0c2}
</style>
</head>
<body>
<h1>EASM — Hosts</h1>
<div id="alerts"></div>
<h2>Recent Hosts</h2>
<table id="hosts"><thead><tr><th>IP</th><th>Port</th><th>Service</th><th>Risk</th><th>Last seen</th></tr></thead><tbody></tbody></table>
<script>
async function load(){
 const h = await fetch('/api/hosts').then(r=>r.json())
 const t = document.querySelector('#hosts tbody')
 t.innerHTML = ''
 h.forEach(row=>{
   const tr = document.createElement('tr')
   tr.className = row.risk
   tr.innerHTML = `<td>${row.ip}</td><td>${row.port}</td><td>${row.service}</td><td>${row.risk}</td><td>${row.last_seen}</td>`
   t.appendChild(tr)
 })
 const a = await fetch('/api/alerts').then(r=>r.json())
 const ad = document.getElementById('alerts')
 ad.innerHTML = '<h2>Recent Alerts</h2>' + a.map(x=>`<div class="${x.severity}"><b>[${x.severity}] ${x.rule}</b> ${x.ip}:${x.port} - ${x.message}</div>`).join('')
}
load(); setInterval(load,15000);
</script>
</body></html>
"""

@app.route("/")
def index():
    return render_template_string(INDEX)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
