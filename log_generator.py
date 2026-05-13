"""
log_generator.py — Generates realistic security log samples for the SIEM
"""
import sqlite3
import random
import datetime

USERS = ['root', 'admin', 'ujjwal', 'guest', 'john.smith', 'service_acct', 'deploy_bot']
IPS   = ['192.168.1.105', '10.0.0.22', '203.0.113.45', '198.51.100.8',
         '172.16.0.3', '45.33.32.156', '185.220.101.12', '8.8.8.8']
HOSTS = ['web-server-01', 'db-server-02', 'auth-server', 'file-server', 'vpn-gateway']

EVENTS = [
    # (event_type, severity, message_template)
    ('LOGIN_SUCCESS',   'LOW',      'Successful login for user {user} from {ip}'),
    ('LOGIN_FAILED',    'MEDIUM',   'Failed login attempt for user {user} from {ip}'),
    ('LOGIN_FAILED',    'MEDIUM',   'Authentication failure for {user}@{host} from {ip}'),
    ('BRUTE_FORCE',     'HIGH',     'Multiple failed login attempts detected for {user} from {ip}'),
    ('PRIVILEGE_ESC',   'CRITICAL', 'Privilege escalation attempt: {user} executed sudo on {host}'),
    ('FILE_ACCESS',     'LOW',      'File accessed by {user} from {ip} on {host}'),
    ('FILE_MODIFIED',   'MEDIUM',   'Critical file /etc/passwd modified by {user} on {host}'),
    ('PORT_SCAN',       'HIGH',     'Port scan detected from {ip} targeting {host}'),
    ('MALWARE',         'CRITICAL', 'Malware signature detected on {host} — process killed'),
    ('FIREWALL_BLOCK',  'MEDIUM',   'Firewall blocked connection from {ip} to {host}'),
    ('VPN_CONNECT',     'LOW',      'VPN connection established by {user} from {ip}'),
    ('ACCOUNT_LOCKED',  'HIGH',     'Account {user} locked after repeated failures from {ip}'),
    ('DATA_EXFIL',      'CRITICAL', 'Unusual data transfer volume detected from {host} to {ip}'),
    ('CONFIG_CHANGE',   'HIGH',     'System configuration changed by {user} on {host}'),
    ('SERVICE_START',   'LOW',      'Service started by {user} on {host}'),
]

SEVERITY_WEIGHT = {
    'LOW': 40, 'MEDIUM': 30, 'HIGH': 20, 'CRITICAL': 10
}

def generate_logs(db_path, count=200):
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            event_type  TEXT NOT NULL,
            severity    TEXT NOT NULL,
            user        TEXT,
            source_ip   TEXT,
            host        TEXT,
            message     TEXT NOT NULL,
            alerted     INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            severity    TEXT NOT NULL,
            title       TEXT NOT NULL,
            description TEXT NOT NULL,
            source_ip   TEXT,
            status      TEXT DEFAULT 'OPEN'
        )
    """)

    # Clear old data
    conn.execute("DELETE FROM logs")
    conn.execute("DELETE FROM alerts")

    now = datetime.datetime.now()
    for i in range(count):
        # Spread events over last 24 hours
        ts = now - datetime.timedelta(minutes=random.randint(0, 1440))

        # Weighted random event
        event_type, severity, msg_template = random.choice(EVENTS)
        user = random.choice(USERS)
        ip   = random.choice(IPS)
        host = random.choice(HOSTS)

        # Simulate brute force: cluster failed logins from same IP
        if event_type == 'BRUTE_FORCE':
            ip = '185.220.101.12'  # known bad IP

        message = msg_template.format(user=user, ip=ip, host=host)

        conn.execute(
            "INSERT INTO logs (timestamp, event_type, severity, user, source_ip, host, message) VALUES (?,?,?,?,?,?,?)",
            (ts.strftime('%Y-%m-%d %H:%M:%S'), event_type, severity, user, ip, host, message)
        )

    # Generate alerts for CRITICAL and HIGH events
    critical_logs = conn.execute(
        "SELECT * FROM logs WHERE severity IN ('CRITICAL','HIGH') ORDER BY timestamp DESC LIMIT 15"
    ).fetchall()

    for log in critical_logs:
        conn.execute(
            "INSERT INTO alerts (timestamp, severity, title, description, source_ip) VALUES (?,?,?,?,?)",
            (log[1], log[3], f"{log[2].replace('_',' ').title()} Detected",
             log[8], log[5])
        )

    conn.commit()
    conn.close()
    print(f"Generated {count} log entries and alerts.")

if __name__ == '__main__':
    generate_logs('siem.db')
