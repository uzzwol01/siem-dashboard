"""
threat_detector.py — Rule-based threat detection engine
Analyzes ingested logs and generates alerts based on security rules.
"""
import sqlite3
import datetime


RULES = [
    {
        'name':        'Brute Force Attack',
        'description': 'More than 5 failed login attempts from the same IP within 1 hour',
        'severity':    'CRITICAL',
        'query': """
            SELECT source_ip, COUNT(*) as cnt
            FROM logs
            WHERE event_type = 'LOGIN_FAILED'
            GROUP BY source_ip
            HAVING cnt >= 5
        """,
        'alert_title': 'Brute Force Attack Detected',
        'alert_desc':  'IP {source_ip} made {cnt} failed login attempts — possible brute force attack.'
    },
    {
        'name':        'Privilege Escalation',
        'description': 'Any privilege escalation event detected',
        'severity':    'CRITICAL',
        'query': """
            SELECT source_ip, user, COUNT(*) as cnt
            FROM logs
            WHERE event_type = 'PRIVILEGE_ESC'
            GROUP BY source_ip, user
        """,
        'alert_title': 'Privilege Escalation Attempt',
        'alert_desc':  'User {user} attempted privilege escalation from {source_ip}.'
    },
    {
        'name':        'Port Scan Detected',
        'description': 'Reconnaissance port scanning activity',
        'severity':    'HIGH',
        'query': """
            SELECT source_ip, COUNT(*) as cnt
            FROM logs
            WHERE event_type = 'PORT_SCAN'
            GROUP BY source_ip
        """,
        'alert_title': 'Network Port Scan Detected',
        'alert_desc':  'Port scanning activity detected from IP {source_ip} ({cnt} events).'
    },
    {
        'name':        'Data Exfiltration',
        'description': 'Unusual outbound data transfer detected',
        'severity':    'CRITICAL',
        'query': """
            SELECT source_ip, host, COUNT(*) as cnt
            FROM logs
            WHERE event_type = 'DATA_EXFIL'
            GROUP BY source_ip
        """,
        'alert_title': 'Potential Data Exfiltration',
        'alert_desc':  'Abnormal data transfer detected from host {host} to {source_ip}.'
    },
    {
        'name':        'Malware Detected',
        'description': 'Malware signature identified on a host',
        'severity':    'CRITICAL',
        'query': """
            SELECT source_ip, host, COUNT(*) as cnt
            FROM logs
            WHERE event_type = 'MALWARE'
            GROUP BY host
        """,
        'alert_title': 'Malware Signature Detected',
        'alert_desc':  'Malware detected on {host} — immediate containment required.'
    },
    {
        'name':        'Multiple Account Lockouts',
        'description': 'Several accounts locked out — possible credential stuffing',
        'severity':    'HIGH',
        'query': """
            SELECT source_ip, COUNT(*) as cnt
            FROM logs
            WHERE event_type = 'ACCOUNT_LOCKED'
            GROUP BY source_ip
            HAVING cnt >= 2
        """,
        'alert_title': 'Multiple Account Lockouts',
        'alert_desc':  'Multiple accounts locked from IP {source_ip} — possible credential stuffing attack.'
    },
    {
        'name':        'Critical File Modification',
        'description': 'System-critical file was modified',
        'severity':    'HIGH',
        'query': """
            SELECT source_ip, user, host, COUNT(*) as cnt
            FROM logs
            WHERE event_type = 'FILE_MODIFIED'
            GROUP BY host
        """,
        'alert_title': 'Critical File Modified',
        'alert_desc':  'Critical system file modified by {user} on {host} — verify integrity.'
    },
]


def run_detection(db_path):
    """Run all detection rules and insert new alerts."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Clear old rule-generated alerts (keep manually resolved ones)
    conn.execute("DELETE FROM alerts WHERE status='OPEN'")

    for rule in RULES:
        try:
            rows = conn.execute(rule['query']).fetchall()
            for row in rows:
                row_dict = dict(row)
                description = rule['alert_desc'].format(**{
                    k: row_dict.get(k, 'unknown') for k in
                    ['source_ip', 'user', 'host', 'cnt']
                    if k in row_dict
                })
                conn.execute(
                    "INSERT INTO alerts (timestamp, severity, title, description, source_ip, status) VALUES (?,?,?,?,?,?)",
                    (now, rule['severity'], rule['alert_title'],
                     description, row_dict.get('source_ip'), 'OPEN')
                )
        except Exception as e:
            print(f"Rule '{rule['name']}' error: {e}")

    conn.commit()
    conn.close()
    print("Threat detection complete.")


if __name__ == '__main__':
    run_detection('siem.db')
