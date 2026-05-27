# Advanced Intrusion Detection Environment (AIDE) - Enhanced

**Comprehensive, performant File Integrity Monitoring** for Linux workstations and servers with native SIEM integration.

## Features
- Tiered rules (FIPSR on critical paths, PERMS on homes/logs) for strong coverage + excellent performance
- Automatic exclusion of volatile paths (/proc, /sys, containers, caches, etc.)
- Full AIDE database initialization + activation + backup
- Daily systemd timer (low-priority + randomized)
- Structured JSONL output + dedicated SIEM shipper (ELK/Filebeat, Splunk, any generic JSON receiver)
- Cron/AT hardening + rsyslog integration
- Self-protection of AIDE itself
- Docker/Podman/Kubernetes ready (DaemonSet recommended)

## Quick Start

### Bare Metal / VM
```bash
sudo python3 configure_aide.py --verbose --json
```

### Docker / Podman
```bash
docker build -t aide:latest .
docker run --rm --cap-add SYS_ADMIN \
  -v /etc/aide:/etc/aide \
  -v /var/log:/var/log \
  -v /var/backups:/var/backups \
  -v /:/host:ro \
  aide:latest
```

### Kubernetes
```bash
kubectl apply -f container.yaml
```

## SIEM Integration
- Always writes clean JSONL to `/var/log/aide/aide_events.jsonl`
- Optional direct HTTP forwarding (Splunk HEC, Logstash, etc.):
  ```bash
  export AIDE_SIEM_HTTP_URL="https://your-hec-endpoint"
  export AIDE_SIEM_TOKEN="your-token"
  ```

## Verification
```bash
sudo aide --check
systemctl status aidecheck.timer
tail -f /var/log/aide/aide_events.jsonl | jq
```