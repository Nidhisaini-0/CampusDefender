from flask import Flask, render_template, redirect, url_for, request, session
from flask_socketio import SocketIO
import subprocess
import os
from dotenv import load_dotenv
import signal
from collections import Counter
from datetime import datetime
import sqlite3

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("CAMPUSDEFENDER_SECRET_KEY")
socketio = SocketIO(app)

DB_NAME = "campusdefender.db"

processes = {"brute": None, "portscan": None}


# ================= Utility =================

def is_running(process):
    return process is not None and process.poll() is None


def parse_logs():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT timestamp, attack_type, ip, action, details
        FROM attacks
        ORDER BY id ASC
    """)

    rows = cursor.fetchall()
    conn.close()

    brute = 0
    portscan = 0
    blocked = 0
    ip_counter = Counter()
    hourly_counter = Counter()

    parsed_logs = []

    for row in rows:
        timestamp, attack_type, ip, action, details = row

        if attack_type == "BRUTE_FORCE":
            brute += 1
        elif attack_type == "PORT_SCAN":
            portscan += 1

        if action == "BLOCKED":
            blocked += 1

        ip_counter[ip] += 1

        # Hourly anomaly tracking
        hour = timestamp[:13]
        hourly_counter[hour] += 1

        parsed_logs.append({
            "timestamp": timestamp,
            "type": attack_type,
            "ip": ip,
            "action": action,
            "details": details
        })

    most_ip = ip_counter.most_common(1)[0][0] if ip_counter else "N/A"

    # Basic anomaly scoring
    anomaly_score = "Normal"
    if hourly_counter:
        avg = sum(hourly_counter.values()) / len(hourly_counter)
        latest_hour = list(hourly_counter.values())[-1]
        if latest_hour > avg * 2:
            anomaly_score = "High"
        elif latest_hour > avg * 1.5:
            anomaly_score = "Medium"

    stats = {
        "brute": brute,
        "portscan": portscan,
        "blocked": blocked,
        "most_ip": most_ip,
        "anomaly": anomaly_score
    }

    # Return last 20 logs in reverse order (latest first)
    return parsed_logs[-20:][::-1], stats


# ================= Auth =================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form["password"] == os.getenv("CAMPUSDEFENDER_ADMIN_PASSWORD"):
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ================= Dashboard =================

@app.route("/")
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Get ALL attacks (needed for stats calculation)
    cursor.execute("""
        SELECT timestamp, attack_type, ip, action, details
        FROM attacks
        ORDER BY id ASC
    """)
    rows = cursor.fetchall()

    brute = 0
    portscan = 0
    blocked = 0
    ip_counter = Counter()
    hourly_counter = Counter()

    parsed_logs = []

    for row in rows:
        timestamp = row["timestamp"]
        attack_type = row["attack_type"]
        ip = row["ip"]
        action = row["action"]
        details = row["details"]

        if attack_type == "BRUTE_FORCE":
            brute += 1
        elif attack_type == "PORT_SCAN":
            portscan += 1

        if action == "BLOCKED":
            blocked += 1

        ip_counter[ip] += 1

        hour = timestamp[:13]
        hourly_counter[hour] += 1

        parsed_logs.append({
            "timestamp": timestamp,
            "type": attack_type,
            "ip": ip,
            "action": action,
            "details": details
        })

    most_ip = ip_counter.most_common(1)[0][0] if ip_counter else "N/A"

    anomaly_score = "Normal"
    if hourly_counter:
        avg = sum(hourly_counter.values()) / len(hourly_counter)
        latest_hour = list(hourly_counter.values())[-1]
        if latest_hour > avg * 2:
            anomaly_score = "High"
        elif latest_hour > avg * 1.5:
            anomaly_score = "Medium"

    stats = {
        "brute": brute,
        "portscan": portscan,
        "blocked": blocked,
        "most_ip": most_ip,
        "anomaly": anomaly_score
    }

    conn.close()

    # Return latest 20 logs (latest first)
    return render_template(
        "dashboard.html",
        logs=parsed_logs[-20:][::-1],
        stats=stats,
        brute_running=is_running(processes["brute"]),
        portscan_running=is_running(processes["portscan"])
    )

@app.route('/analytics')
def analytics():
    conn = sqlite3.connect("campusdefender.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Total attacks
    cursor.execute("SELECT COUNT(*) as total FROM attacks")
    total_attacks = cursor.fetchone()["total"]

    # Top 5 IPs
    cursor.execute("""
        SELECT ip, COUNT(*) as count
        FROM attacks
        GROUP BY ip
        ORDER BY count DESC
        LIMIT 5
    """)
    top_ips = cursor.fetchall()

    # Attack type distribution
    cursor.execute("""
        SELECT attack_type, COUNT(*) as count
        FROM attacks
        GROUP BY attack_type
    """)
    attack_types = cursor.fetchall()

    # Daily trend
    cursor.execute("""
        SELECT DATE(timestamp) as date, COUNT(*) as count
        FROM attacks
        GROUP BY date
        ORDER BY date ASC
    """)
    daily_trend = cursor.fetchall()

    # Latest attack
    cursor.execute("""
        SELECT * FROM attacks
        ORDER BY timestamp DESC
        LIMIT 1
    """)
    latest = cursor.fetchone()

    conn.close()

    return render_template(
        "analytics.html",
        total_attacks=total_attacks,
        top_ips=top_ips,
        attack_types=attack_types,
        daily_trend=daily_trend,
        latest=latest
    )

# ================= Process Controls =================

@app.route("/start_brute")
def start_brute():
    if not is_running(processes["brute"]):
        processes["brute"] = subprocess.Popen(
            ["sudo", "python3", "-m", "app.detector"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid
        )
    return redirect(url_for("dashboard"))


@app.route("/stop_brute")
def stop_brute():
    if is_running(processes["brute"]):
        os.killpg(os.getpgid(processes["brute"].pid), signal.SIGTERM)
        processes["brute"] = None
    return redirect(url_for("dashboard"))


@app.route("/start_portscan")
def start_portscan():
    if not is_running(processes["portscan"]):
        processes["portscan"] = subprocess.Popen(
            ["sudo", "python3", "-m", "app.portscan"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid
        )
    return redirect(url_for("dashboard"))


@app.route("/stop_portscan")
def stop_portscan():
    if is_running(processes["portscan"]):
        os.killpg(os.getpgid(processes["portscan"].pid), signal.SIGTERM)
        processes["portscan"] = None
    return redirect(url_for("dashboard"))


# ================= Unblock =================

@app.route("/unblock/<ip>")
def unblock(ip):
    result = subprocess.run(
        ["sudo", "ufw", "status", "numbered"],
        capture_output=True,
        text=True
    )

    lines = result.stdout.split("\n")

    for line in lines:
        if ip in line:
            rule_number = line.split("]")[0].strip("[ ")
            subprocess.run(
                ["sudo", "/usr/sbin/ufw", "delete", rule_number],
                input="y\n",
                text=True
            )
            break

    from app.logger import log_event
    log_event(
        attack_type="MANUAL_ACTION",
        ip=ip,
        action="UNBLOCKED",
        details="Removed via dashboard"
    )

    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    socketio.run(app, debug=True)
