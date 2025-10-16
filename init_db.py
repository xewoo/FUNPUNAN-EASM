import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "easm.db")

con = sqlite3.connect(DB_PATH)
cur = con.cursor()

# Hosts table
cur.execute("""
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    port INTEGER,
    service TEXT,
    risk TEXT,
    last_seen TEXT
)
""")

# Alerts table
cur.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER,
    severity TEXT,
    rule TEXT,
    message TEXT,
    created_at TEXT,
    FOREIGN KEY(host_id) REFERENCES hosts(id)
)
""")

# Insert sample data
cur.execute("DELETE FROM hosts")
cur.execute("DELETE FROM alerts")

cur.execute("INSERT INTO hosts (ip, port, service, risk, last_seen) VALUES (?,?,?,?,datetime('now'))",
            ("192.168.1.10", 22, "ssh", "medium"))
cur.execute("INSERT INTO hosts (ip, port, service, risk, last_seen) VALUES (?,?,?,?,datetime('now'))",
            ("192.168.1.15", 80, "http", "high"))

cur.execute("INSERT INTO alerts (host_id, severity, rule, message, created_at) VALUES (?,?,?,?,datetime('now'))",
            (1, "high", "OpenSSH", "Weak SSH configuration",))
cur.execute("INSERT INTO alerts (host_id, severity, rule, message, created_at) VALUES (?,?,?,?,datetime('now'))",
            (2, "critical", "HTTP", "Exposed admin panel",))

con.commit()
con.close()

print("Database initialized with sample data.")
