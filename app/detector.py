import re
import time
import subprocess
from collections import defaultdict
from app.logger import log_event

# ===== CONFIG =====
LOG_FILE = "/var/log/auth.log"
THRESHOLD = 3
CHECK_INTERVAL = 0.5
# ==================

failed_attempts = defaultdict(int)
blocked_ips = set()


def block_ip(ip, attempts):
    """Block IP using UFW and log event"""
    if ip in blocked_ips:
        return

    print(f"\n🚨 [ALERT] Brute-force attack detected from {ip}! Blocking IP...\n")

    subprocess.run(
        ["sudo", "ufw", "deny", "from", ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    blocked_ips.add(ip)

    log_event(
        attack_type="BRUTE_FORCE",
        ip=ip,
        action="BLOCKED",
        details=f"attempts={attempts}"
    )


def monitor_bruteforce():
    print("🚀 SSH Brute-Force Detection Started...")
    print("Watching for brute-force attacks...\n")

    try:
        with open(LOG_FILE, "r") as file:
            file.seek(0, 2)

            while True:
                line = file.readline()

                if not line:
                    time.sleep(CHECK_INTERVAL)
                    continue

                if "Failed password" in line:
                    match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)

                    if match:
                        ip = match.group(1)
                        failed_attempts[ip] += 1

                        print(f"[INFO] Failed login from {ip} ({failed_attempts[ip]} attempts)")

                        # Skip localhost
                        if ip == "127.0.0.1":
                            log_event(
                                attack_type="BRUTE_FORCE",
                                ip=ip,
                                action="DETECTED",
                                details=f"attempts={failed_attempts[ip]} (localhost)"
                            )
                            continue

                        if failed_attempts[ip] >= THRESHOLD:
                            block_ip(ip, failed_attempts[ip])
                            failed_attempts[ip] = 0

    except PermissionError:
        print("❌ Permission denied. Run with sudo.")
    except FileNotFoundError:
        print("❌ SSH log file not found.")


if __name__ == "__main__":
    monitor_bruteforce()
