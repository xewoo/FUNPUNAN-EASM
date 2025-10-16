import sqlite3
import os
import sys
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "easm.db")
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.txt")

# ---------- SETTINGS ----------
def load_config():
    if not os.path.exists(CONFIG_PATH):
        return {"telegram_token": "", "chat_id": ""}
    data = {}
    with open(CONFIG_PATH, "r") as f:
        for line in f:
            if "=" in line:
                k, v = line.strip().split("=", 1)
                data[k] = v
    return data

def save_config(cfg):
    with open(CONFIG_PATH, "w") as f:
        for k, v in cfg.items():
            f.write(f"{k}={v}\n")

# ---------- DB QUERIES ----------
def get_hosts(limit=10):
    if not os.path.exists(DB_PATH):
        return []
    con = sqlite3.connect(DB_PATH)
    cur = con.execute("SELECT ip, port, service, risk, last_seen FROM hosts ORDER BY last_seen DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    con.close()
    return rows

def get_alerts(limit=10):
    if not os.path.exists(DB_PATH):
        return []
    con = sqlite3.connect(DB_PATH)
    cur = con.execute("""SELECT hosts.ip, hosts.port, alerts.severity, alerts.rule, alerts.message, alerts.created_at
                         FROM alerts JOIN hosts ON alerts.host_id=hosts.id
                         ORDER BY alerts.created_at DESC LIMIT ?""", (limit,))
    rows = cur.fetchall()
    con.close()
    return rows

def get_scans_summary():
    """Get active scans information (mock data for now)"""
    # This is mock data - you would implement actual scan tracking in your database
    return [
        {
            "name": "Full Internet Scan",
            "type": "CRON",
            "started": "2025-09-29 10:12",
            "progress": 45,
            "eta": "00:08",
            "status": "running"
        },
        {
            "name": "Quick DMZ sweep",
            "type": "Manual",
            "last_run": "2025-09-28 23:00",
            "status": "completed"
        }
    ]

def get_recent_alerts_count():
    """Get count of new alerts"""
    if not os.path.exists(DB_PATH):
        return 0
    con = sqlite3.connect(DB_PATH)
    cur = con.execute("SELECT COUNT(*) FROM alerts WHERE created_at > datetime('now', '-1 day')")
    count = cur.fetchone()[0]
    con.close()
    return count

# ---------- UI HELPERS ----------
def clear_screen():
    """Clear the console screen (cross-platform)"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    """Print the FUNPUNAN ASCII banner"""
    banner = """
  ____  _  _  _   _  ____   _   _   _   _   _   _   _ 
 |  __|| || || \\ | ||  _ \\ | | | | | \\ | | / \\ | \\ | |
 | |__ | || ||  \\| || |_) || | | | |  \\| |/ _ \\|  \\| |
 |  __|| || || . ` ||  __/ | | | | | . ` / ___ \\ . ` |
 | |___|_||_||_|\\__||_|    |_| |_| |_|\\_/_/   \\_\\_|\\__|
 |_____|                                        v0.1
"""
    print(banner)

def print_dashboard():
    """Print the main dashboard interface"""
    clear_screen()
    print_banner()
    
    print(" [A] All scans    [N] New scan    [R] Results    [S] Settings   [Q] Quit\n")
    
    # Get data
    scans = get_scans_summary()
    alerts = get_alerts(5)
    new_alerts_count = get_recent_alerts_count()
    
    # Print two-column layout
    print(f" {'=== ACTIVE SCANS ===':<35} {'=== ALERTS (new:' + str(new_alerts_count) + ') ==='}")
    
    # Left column: Scans
    if scans:
        for idx, scan in enumerate(scans, 1):
            print(f" {idx}) {scan['name']:<25} ({scan['type']:<5})", end="")
            
            # Right column: Alerts (print alert for same row if exists)
            if idx <= len(alerts):
                ip, port, sev, rule, msg, created = alerts[idx-1]
                severity_marker = "[!]" if sev in ["High", "Critical"] else "[i]"
                print(f"   {severity_marker} {ip}:{port}  {rule}")
            else:
                print()
            
            # Scan details on next line
            if scan['status'] == 'running':
                print(f"    started: {scan['started']:<20}", end="")
                if idx <= len(alerts):
                    ip, port, sev, rule, msg, created = alerts[idx-1]
                    status = "TG sent" if sev == "High" else "suppressed"
                    print(f"       sev:{sev:<8} -> {status}")
                else:
                    print()
                print(f"    progress: {scan['progress']}%  ETA: {scan['eta']}")
            else:
                print(f"    last run: {scan.get('last_run', 'N/A'):<20}", end="")
                if idx <= len(alerts) and idx < len(scans):
                    print()
                else:
                    print()
        
        # Print remaining alerts if more alerts than scans
        if len(alerts) > len(scans):
            for idx in range(len(scans), len(alerts)):
                alert = alerts[idx]
                ip, port, sev, rule, msg, created = alert
                severity_marker = "[!]" if sev in ["High", "Critical"] else "[i]"
                print(f" {' '*35}   {severity_marker} {ip}:{port}  {rule}")
                status = "TG sent" if sev == "High" else "suppressed"
                print(f" {' '*35}       sev:{sev:<8} -> {status}")
    else:
        print(" No active scans", end="")
        if alerts:
            ip, port, sev, rule, msg, created = alerts[0]
            severity_marker = "[!]" if sev in ["High", "Critical"] else "[i]"
            print(f"                   {severity_marker} {ip}:{port}  {rule}")
        else:
            print("                   No alerts")
    
    print(f" {'-'*33}   {'-'*28}")
    print(" Use ↑↓ to select a scan. Enter to open details.\n")

def show_all_scans():
    clear_screen()
    print_banner()
    print(" === ALL SCANS ===\n")
    
    scans = get_scans_summary()
    if not scans:
        print("  No scans found.\n")
    else:
        for idx, scan in enumerate(scans, 1):
            print(f" {idx}. {scan['name']}")
            print(f"    Type: {scan.get('type', 'N/A')}")
            print(f"    Status: {scan.get('status', 'N/A')}")
            if scan['status'] == 'running':
                print(f"    Started: {scan.get('started', 'N/A')}")
                print(f"    Progress: {scan.get('progress', 0)}%")
                print(f"    ETA: {scan.get('eta', 'N/A')}")
            else:
                print(f"    Last run: {scan.get('last_run', 'N/A')}")
            print()
    
    choice = input("  Enter scan number to view details (or press Enter to return): ").strip()
    
    if choice.isdigit():
        scan_idx = int(choice) - 1
        if 0 <= scan_idx < len(scans):
            show_scan_detail(scans[scan_idx])

def show_new_scan():
    clear_screen()
    print_banner()
    print(" === NEW SCAN ===\n")
    
    print("  Scan Types:")
    print("  1. Quick Scan (Top 1000 ports)")
    print("  2. Full Scan (All 65535 ports)")
    print("  3. Custom Scan")
    print("  4. Cancel")
    
    choice = input("\n  Select scan type (1-4): ").strip()
    
    if choice in ["1", "2", "3"]:
        target = input("  Enter target IP/CIDR (e.g., 192.168.1.0/24): ").strip()
        if target:
            print(f"\n  ✓ Scan scheduled for {target}")
            print("  Note: Scan scheduling not yet implemented in database")
        else:
            print("\n  ✗ Invalid target")
    
    input("\n  Press Enter to return to dashboard...")

def show_results():
    clear_screen()
    print_banner()
    print(" === SCAN RESULTS ===\n")
    
    rows = get_hosts(20)
    
    if not rows:
        print("  No results found in database.\n")
    else:
        print(f"  {'IP':<15} {'Port':<8} {'Service':<12} {'Risk':<10} {'Last Seen':<20}")
        print("  " + "-" * 68)
        for ip, port, svc, risk, seen in rows:
            print(f"  {ip:<15} {port:<8} {svc:<12} {risk:<10} {seen:<20}")
    
    input("\n  Press Enter to return to dashboard...")

def show_settings():
    cfg = load_config()
    
    while True:
        clear_screen()
        print_banner()
        print(" === SETTINGS ===\n")
        print(f"  1. Telegram Token: {cfg.get('telegram_token', '(not set)')}")
        print(f"  2. Telegram Chat ID: {cfg.get('chat_id', '(not set)')}")
        print(f"  3. Save and Return")
        print(f"  4. Return Without Saving")
        
        choice = input("\n  Enter your choice (1-4): ").strip()
        
        if choice == "1":
            new_value = input("\n  Enter new Telegram Token: ").strip()
            cfg["telegram_token"] = new_value
            print("  ✓ Token updated (not saved yet)")
            input("  Press Enter to continue...")
        elif choice == "2":
            new_value = input("\n  Enter new Telegram Chat ID: ").strip()
            cfg["chat_id"] = new_value
            print("  ✓ Chat ID updated (not saved yet)")
            input("  Press Enter to continue...")
        elif choice == "3":
            save_config(cfg)
            print("\n  ✓ Settings saved successfully!")
            input("  Press Enter to continue...")
            break
        elif choice == "4":
            break
        else:
            print("\n  Invalid choice. Please try again.")
            input("  Press Enter to continue...")

def main_menu():
    while True:
        print_dashboard()
        
        choice = input(" Enter command: ").strip().lower()
        
        if choice == "a":
            show_all_scans()
        elif choice == "n":
            show_new_scan()
        elif choice == "r":
            show_results()
        elif choice == "s":
            show_settings()
        elif choice == "q":
            clear_screen()
            print("\n  Goodbye!\n")
            sys.exit(0)
        else:
            print("\n  Invalid command. Press Enter to continue...")
            input()

# ---------- MAIN ----------
if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        clear_screen()
        print("\n\n  Program interrupted. Goodbye!\n")
        sys.exit(0)
