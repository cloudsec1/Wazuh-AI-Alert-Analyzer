#!/var/ossec/framework/python/bin/python3
# custom-abuseipdb — Wazuh Integrator script
# Minimal change from your working version: adds "level" under abuseipdb.source.
# Sends an event ONLY when AbuseIPDB has reports (found==1).
# stdout prints "ok" so integrator logs "ok".

import json
import sys
import os
import time
from socket import socket, AF_UNIX, SOCK_DGRAM

try:
    import requests
except Exception:
    print("No module 'requests' found. Install: /var/ossec/framework/python/bin/pip3 install requests")
    sys.exit(1)

BASE = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
SOCK = f"{BASE}/queue/sockets/queue"
LOG  = f"{BASE}/logs/integrations.log"
DEBUG = False


def log(msg: str):
    """Write to integrations.log only when DEBUG is True (keeps behavior quiet by default)."""
    if not DEBUG:
        return
    try:
        ts = time.strftime("%Y-%m-%d %H:%M:%S %z")
        with open(LOG, "a") as f:
            f.write(f"{ts} {msg}\n")
    except Exception:
        # Logging must never break the integration
        pass


def send_event(msg: dict, agent: dict | None = None):
    """Send a JSON event back to Wazuh manager via the queue socket."""
    if not agent or agent.get("id") == "000":
        payload = f"1:abuseipdb:{json.dumps(msg)}"
    else:
        ip = agent.get("ip", "any")
        payload = f"1:[{agent.get('id')}] ({agent.get('name')}) {ip}->abuseipdb:{json.dumps(msg)}"
    s = socket(AF_UNIX, SOCK_DGRAM)
    s.connect(SOCK)
    s.send(payload.encode())
    s.close()


def query_api(ip: str, key: str) -> dict:
    """Call AbuseIPDB check endpoint; return data{} or {} on error (and emit an error event)."""
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            headers={
                "Key": key,
                "Accept": "application/json",
                "Accept-Encoding": "gzip, deflate"
            },
            timeout=10
        )
    except Exception as e:
        # Network/transport error — emit an error event and return {}
        send_event({
            "integration": "custom-abuseipdb",
            "abuseipdb": {"error": "transport", "description": str(e)}
        })
        return {}

    if r.status_code != 200:
        try:
            detail = r.json().get("errors", [{}])[0].get("detail", r.text[:200])
        except Exception:
            detail = r.text[:200]
        send_event({
            "integration": "custom-abuseipdb",
            "abuseipdb": {"error": r.status_code, "description": detail}
        })
        return {}

    try:
        return r.json().get("data", {})
    except Exception:
        return {}


def build_output(alert: dict, data: dict) -> dict:
    """Build the enrichment JSON. Minimal change: include original rule level."""
    out = {
        "integration": "custom-abuseipdb",
        "abuseipdb": {
            "found": 0,
            "source": {
                "alert_id":    alert.get("id"),
                "rule":        alert.get("rule", {}).get("id"),
                "level":       alert.get("rule", {}).get("level"),  # ← added line
                "description": alert.get("rule", {}).get("description"),
                "full_log":    alert.get("full_log"),
                "srcip":       alert.get("data", {}).get("srcip"),
            }
        }
    }

    if data and data.get("totalReports", 0) > 0:
        out["abuseipdb"]["found"] = 1
        out["abuseipdb"]["abuse_confidence_score"] = data.get("abuseConfidenceScore")
        out["abuseipdb"]["country_code"]           = data.get("countryCode")
        out["abuseipdb"]["usage_type"]             = data.get("usageType")
        out["abuseipdb"]["isp"]                    = data.get("isp")
        out["abuseipdb"]["domain"]                 = data.get("domain")
        out["abuseipdb"]["total_reports"]          = data.get("totalReports")
        out["abuseipdb"]["last_reported_at"]       = data.get("lastReportedAt")

    return out


def main():
    # Expect: <script> <alert_json_path> <api_key> [debug]
    if len(sys.argv) < 3:
        log("Bad arguments")
        sys.exit(1)

    alert_path = sys.argv[1].strip()
    apikey     = sys.argv[2].strip()

    global DEBUG
    DEBUG = (len(sys.argv) > 3 and sys.argv[3] == "debug")

    log(f"Starting custom-abuseipdb for {alert_path}")

    with open(alert_path, "r") as f:
        alert = json.load(f)

    srcip = alert.get("data", {}).get("srcip")
    if not srcip:
        log("No srcip in alert, exiting")
        print("ok")
        return

    data = query_api(srcip, apikey)
    out  = build_output(alert, data)

    # send only when AbuseIPDB has reports.
    if out["abuseipdb"]["found"] == 1:
        send_event(out, alert.get("agent"))

    print("ok")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(f"Exception: {e}")
        raise
