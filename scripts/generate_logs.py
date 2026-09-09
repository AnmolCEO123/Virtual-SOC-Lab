from datetime import datetime, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

AUTH_LOG = BASE_DIR / "data" / "auth_logs" / "auth.log"
WEB_LOG = BASE_DIR / "data" / "web_logs" / "web.log"
NETWORK_LOG = BASE_DIR / "data" / "network_logs" / "network.log"

AUTH_LOG.parent.mkdir(parents=True, exist_ok=True)
WEB_LOG.parent.mkdir(parents=True, exist_ok=True)
NETWORK_LOG.parent.mkdir(parents=True, exist_ok=True)

start = datetime.now().replace(microsecond=0)


def write_auth_logs():
    events = []

    events.append(
        f"{start.isoformat()} event=LOGIN_SUCCESS " f"user=analyst src_ip=192.168.56.20"
    )

    for i in range(5):
        ts = start + timedelta(seconds=i * 10)

        events.append(
            f"{ts.isoformat()} event=LOGIN_FAILURE " f"user=admin src_ip=192.168.56.10"
        )

    events.append(
        f"{(start + timedelta(seconds=70)).isoformat()} "
        f"event=LOGIN_SUCCESS user=analyst src_ip=192.168.56.20"
    )

    AUTH_LOG.write_text("\n".join(events) + "\n")


def write_web_logs():
    events = [
        f"{start.isoformat()} method=GET path=/login "
        f"src_ip=192.168.56.20 status=200",
        f"{(start + timedelta(seconds=15)).isoformat()} "
        f"method=GET path=/admin src_ip=192.168.56.30 status=403",
        f"{(start + timedelta(seconds=30)).isoformat()} "
        f"method=GET path=/dashboard src_ip=192.168.56.20 status=200",
        f"{(start + timedelta(seconds=45)).isoformat()} "
        f"method=GET path=/robots.txt "
        f"src_ip=192.168.56.30 status=200",
    ]

    WEB_LOG.write_text("\n".join(events) + "\n")


def write_network_logs():
    events = [
        f"{start.isoformat()} event=DNS_QUERY "
        f"src_ip=192.168.56.20 destination=dns-server",
        f"{(start + timedelta(seconds=20)).isoformat()} "
        f"event=TCP_CONNECTION src_ip=192.168.56.20 "
        f"destination=192.168.56.1 dst_port=80",
        f"{(start + timedelta(seconds=40)).isoformat()} "
        f"event=TCP_CONNECTION src_ip=192.168.56.30 "
        f"destination=192.168.56.1 dst_port=8000",
    ]

    NETWORK_LOG.write_text("\n".join(events) + "\n")


write_auth_logs()
write_web_logs()
write_network_logs()

print("SOC lab logs generated successfully.")
print(f"Auth logs: {AUTH_LOG}")
print(f"Web logs: {WEB_LOG}")
print(f"Network logs: {NETWORK_LOG}")
