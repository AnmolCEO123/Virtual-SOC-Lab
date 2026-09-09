from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent

AUTH_LOG = BASE_DIR / "data" / "auth_logs" / "auth.log"
WEB_LOG = BASE_DIR / "data" / "web_logs" / "web.log"
ALERT_LOG = BASE_DIR / "data" / "alerts.log"


def generate_alerts():
    alerts = []

    # Authentication detection
    failed_attempts = {}

    for line in AUTH_LOG.read_text().splitlines():
        if "event=LOGIN_FAILURE" in line:
            for part in line.split():
                if part.startswith("src_ip="):
                    ip = part.split("=", 1)[1]
                    failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

    for ip, count in failed_attempts.items():
        if count >= 5:
            alerts.append(
                f"{datetime.now().isoformat()} "
                f"severity=HIGH "
                f"alert_type=BRUTE_FORCE "
                f"src_ip={ip} "
                f"description=Multiple failed login attempts detected"
            )

    # Web detection
    for line in WEB_LOG.read_text().splitlines():
        if "status=403" in line:
            parts = line.split()

            src_ip = "unknown"
            path = "unknown"

            for part in parts:
                if part.startswith("src_ip="):
                    src_ip = part.split("=", 1)[1]

                if part.startswith("path="):
                    path = part.split("=", 1)[1]

            alerts.append(
                f"{datetime.now().isoformat()} "
                f"severity=MEDIUM "
                f"alert_type=HTTP_403 "
                f"src_ip={src_ip} "
                f"path={path} "
                f"description=Forbidden web resource access detected"
            )

    ALERT_LOG.write_text("\n".join(alerts) + "\n")

    print("SOC alerts generated successfully.")
    print(f"Alert file: {ALERT_LOG}")
    print(f"Total alerts: {len(alerts)}")


if __name__ == "__main__":
    generate_alerts()
