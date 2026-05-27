#!/usr/bin/env python3
import json, sys, os, socket
from datetime import datetime
import urllib.request

def main(report_path="/var/log/aide/aide_report.json"):
    hostname = socket.gethostname()
    ts = datetime.now(datetime.timezone.utc()).isoformat() + "Z"
    jsonl_path = "/var/log/aide/aide_events.jsonl"

    try:
        with open(report_path) as f:
            report = json.load(f)
        events = [{"@timestamp": ts, "host.name": hostname, "source": "aide", "event.module": "file_integrity", "aide": report}]
    except Exception:
        with open(report_path, errors="ignore") as f:
            text = f.read()[:20000]
        events = [{"@timestamp": ts, "host.name": hostname, "source": "aide", "event.module": "file_integrity", "message": text}]

    # Always write JSONL (universal for Filebeat/Splunk UF/Fluent Bit)
    with open(jsonl_path, "a") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

    # Optional HTTP ship (set env vars or /etc/aide/shipper.conf)
    url = os.getenv("AIDE_SIEM_HTTP_URL")
    if url:
        try:
            data = json.dumps(events[0]).encode()
            req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "Authorization": f"Bearer {os.getenv('AIDE_SIEM_TOKEN','')}"})
            with urllib.request.urlopen(req, timeout=10):
                pass
        except Exception as e:
            print(f"HTTP ship failed: {e}", file=sys.stderr)

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)