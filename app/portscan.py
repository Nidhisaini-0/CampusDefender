from scapy.all import sniff, TCP, IP
from collections import defaultdict
import subprocess
import time

from app.logger import log_event

# ===== CONFIG =====
THRESHOLD = 5
TIME_WINDOW = 10
INTERFACE = "enp0s3"   # Change if needed (check using: ip a)
# ==================

scan_attempts = defaultdict(list)
blocked_ips = set()


def block_ip(ip):
    """Block IP using ufw and log event"""
    if ip in blocked_ips:
        return

    print(f"\n🚨 [ALERT] Port scan detected from {ip}! Blocking IP...\n")

    subprocess.run(
        ["sudo", "ufw", "deny", "from", ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    blocked_ips.add(ip)

    log_event(
        attack_type="PORT_SCAN",
        ip=ip,
        action="BLOCKED",
        details=f"threshold={THRESHOLD}"
    )


def detect_scan(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):

        src_ip = packet[IP].src

        if src_ip == "127.0.0.1":
            return

        current_time = time.time()

        scan_attempts[src_ip].append(current_time)

        scan_attempts[src_ip] = [
            t for t in scan_attempts[src_ip]
            if current_time - t <= TIME_WINDOW
        ]

        if len(scan_attempts[src_ip]) >= THRESHOLD:
            block_ip(src_ip)
            scan_attempts[src_ip] = []


def monitor_portscan():
    print("🚀 Port Scan Detection Started...\n")
    sniff(iface=INTERFACE, prn=detect_scan, store=0)


if __name__ == "__main__":
    monitor_portscan()
