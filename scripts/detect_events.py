from pathlib import Path
from collections import Counter

BASE_DIR = Path(__file__).resolve().parent.parent

AUTH_LOG = BASE_DIR / "data" / "auth_logs" / "auth.log"
WEB_LOG = BASE_DIR / "data" / "web_logs" / "web.log"
NETWORK_LOG = BASE_DIR / "data" / "network_logs" / "network.log"


def detect_failed_logins():
    failures = []

    for line in AUTH_LOG.read_text().splitlines():
        if "event=LOGIN_FAILURE" in line:
            failures.append(line)

    return failures


def analyze_authentication():
    failures = detect_failed_logins()

    ip_counter = Counter()

    for line in failures:
        for part in line.split():
            if part.startswith("src_ip="):
                ip = part.split("=", 1)[1]
                ip_counter[ip] += 1

    print("\n=== AUTHENTICATION ANALYSIS ===")

    if not failures:
        print("No failed login events detected.")
        return

    print(f"Failed login events: {len(failures)}")

    for ip, count in ip_counter.items():
        print(f"Source IP: {ip} | Failed attempts: {count}")

        if count >= 5:
            print(f"ALERT: Possible brute-force activity from {ip}")


def analyze_web_events():
    print("\n=== WEB LOG ANALYSIS ===")

    suspicious_status = 0

    for line in WEB_LOG.read_text().splitlines():
        if "status=403" in line:
            suspicious_status += 1

            print(f"ALERT: HTTP 403 detected")
            print(line)

    print(f"HTTP 403 events: {suspicious_status}")


def analyze_network_events():
    print("\n=== NETWORK LOG ANALYSIS ===")

    dns_events = 0
    tcp_events = 0

    for line in NETWORK_LOG.read_text().splitlines():

        if "event=DNS_QUERY" in line:
            dns_events += 1

        if "event=TCP_CONNECTION" in line:
            tcp_events += 1
            print(f"Network connection: {line}")

    print(f"DNS queries: {dns_events}")
    print(f"TCP connections: {tcp_events}")


def main():
    print("========================================")
    print("      VIRTUAL SOC LAB - DETECTION")
    print("========================================")

    analyze_authentication()
    analyze_web_events()
    analyze_network_events()

    print("\nDetection analysis completed.")


if __name__ == "__main__":
    main()
