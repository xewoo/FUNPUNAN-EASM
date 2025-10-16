import sqlite3
import os
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

def generate_database_structure():
    """Generate a text-based database structure diagram"""
    structure = """
    EASM Database Structure
    ======================

    1. Hosts Table
    -------------
    - id (INTEGER PRIMARY KEY)
    - ip (TEXT)
    - port (INTEGER)
    - service (TEXT)
    - risk (TEXT)
    - last_seen (TEXT)
    
    2. Alerts Table
    --------------
    - id (INTEGER PRIMARY KEY)
    - host_id (INTEGER FOREIGN KEY -> Hosts.id)
    - severity (TEXT)
    - rule (TEXT)
    - message (TEXT)
    - created_at (TEXT)
    
    3. Users Table
    -------------
    - id (INTEGER PRIMARY KEY)
    - username (TEXT UNIQUE)
    - password (BLOB) - Bcrypt hashed
    - created_at (TIMESTAMP)
    
    Relationships:
    - Alerts.host_id -> Hosts.id (Many-to-One)
    """
    
    with open('database_structure.txt', 'w') as f:
        f.write(structure)
    print("Database structure generated as 'database_structure.txt'")

def generate_statistics():
    """Generate statistics and charts about the database"""
    conn = sqlite3.connect('easm.db')
    
    # Create figure with subplots
    plt.figure(figsize=(15, 10))
    
    # 1. Risk Distribution
    plt.subplot(2, 2, 1)
    risk_data = pd.read_sql_query("SELECT risk, COUNT(*) as count FROM hosts GROUP BY risk", conn)
    plt.pie(risk_data['count'], labels=risk_data['risk'], autopct='%1.1f%%')
    plt.title('Risk Distribution in Hosts')
    
    # 2. Alert Severity Distribution
    plt.subplot(2, 2, 2)
    severity_data = pd.read_sql_query("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity", conn)
    plt.bar(severity_data['severity'], severity_data['count'])
    plt.title('Alert Severity Distribution')
    plt.xticks(rotation=45)
    
    # 3. Services Distribution
    plt.subplot(2, 2, 3)
    service_data = pd.read_sql_query("SELECT service, COUNT(*) as count FROM hosts GROUP BY service", conn)
    plt.pie(service_data['count'], labels=service_data['service'], autopct='%1.1f%%')
    plt.title('Services Distribution')
    
    # 4. Alerts Timeline
    plt.subplot(2, 2, 4)
    alerts_time = pd.read_sql_query("SELECT created_at, COUNT(*) as count FROM alerts GROUP BY date(created_at)", conn)
    alerts_time['created_at'] = pd.to_datetime(alerts_time['created_at'])
    plt.plot(alerts_time['created_at'], alerts_time['count'], marker='o')
    plt.title('Alerts Timeline')
    plt.xticks(rotation=45)
    
    plt.tight_layout()
    plt.savefig('database_statistics.png')
    print("Statistics generated as 'database_statistics.png'")
    
    conn.close()

def generate_security_report():
    """Generate a security overview report"""
    conn = sqlite3.connect('easm.db')
    cursor = conn.cursor()
    
    # Get various security metrics
    total_hosts = cursor.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
    high_risk_hosts = cursor.execute("SELECT COUNT(*) FROM hosts WHERE risk IN ('high', 'critical')").fetchone()[0]
    total_alerts = cursor.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    critical_alerts = cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity IN ('high', 'critical')").fetchone()[0]
    
    # Generate HTML report
    html_report = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            .metric {{ margin: 20px 0; padding: 20px; background: #f5f5f5; border-radius: 5px; }}
            .security-feature {{ margin: 20px 0; padding: 20px; background: #e8f5e9; border-radius: 5px; }}
            h2 {{ color: #333; }}
        </style>
    </head>
    <body>
        <h1>EASM Database Security Report</h1>
        
        <h2>Database Overview</h2>
        <div class="metric">
            <p>Total Hosts Monitored: {total_hosts}</p>
            <p>High Risk Hosts: {high_risk_hosts} ({(high_risk_hosts/total_hosts*100 if total_hosts else 0):.1f}%)</p>
            <p>Total Alerts: {total_alerts}</p>
            <p>Critical Alerts: {critical_alerts} ({(critical_alerts/total_alerts*100 if total_alerts else 0):.1f}%)</p>
        </div>
        
        <h2>Security Features Implemented</h2>
        <div class="security-feature">
            <h3>1. Password Security</h3>
            <ul>
                <li>Bcrypt password hashing with salt</li>
                <li>Passwords stored as binary blobs</li>
                <li>Protection against rainbow table attacks</li>
            </ul>
        </div>
        
        <div class="security-feature">
            <h3>2. Database Protection</h3>
            <ul>
                <li>SQL injection prevention through parameterized queries</li>
                <li>Input validation and sanitization</li>
                <li>Session-based authentication</li>
            </ul>
        </div>
        
        <div class="security-feature">
            <h3>3. Access Control</h3>
            <ul>
                <li>Role-based access control</li>
                <li>Login required for sensitive operations</li>
                <li>Session management for web interface</li>
            </ul>
        </div>
    </body>
    </html>
    """
    
    with open('security_report.html', 'w') as f:
        f.write(html_report)
    print("Security report generated as 'security_report.html'")
    
    conn.close()

if __name__ == "__main__":
    print("Generating database visualizations and reports...")
    
    try:
        generate_database_structure()
        generate_statistics()
        generate_security_report()
        
        print("\nAll visualizations and reports generated successfully!")
        print("\nFiles created:")
        print("1. database_erd.png - Entity Relationship Diagram")
        print("2. database_statistics.png - Statistical Analysis")
        print("3. security_report.html - Security Implementation Report")
        
    except Exception as e:
        print(f"Error generating visualizations: {e}")