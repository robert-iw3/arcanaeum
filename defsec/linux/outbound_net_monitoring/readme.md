# Outbound Network Traffic Monitor

This project deploys a Docker-based system to monitor outbound network traffic, extract unique public destination IPs, and log them in a SIEM-compatible JSON format.

## Features
- Captures outbound traffic using `tcpdump` with optimized filters.
- Extracts unique public IPs using `tshark`.
- Logs IPs to `/var/log/outbound_collector/unique_ips.json` on the host.
- Generates SIEM-compatible JSON logs in `/var/log/siem/siem_outbound_ips.jsonl`.
- Runs in Docker containers with resource limits and health checks.
- Supports periodic IP extraction and log rotation.

## Prerequisites
- Docker and Docker Compose (v2) installed.
- Root privileges for deployment and traffic capture.
- A valid network interface (e.g., `eth0`).

## Setup
1. Place all files in a directory (e.g., `/opt/outbound-monitor`).
2. Run the deployment script:
   ```bash
   sudo python3 deploy_monitor.py
   ```
3. Enter the network interface when prompted.

## Files
- `Dockerfile`: Builds the container image with dependencies.
- `docker-compose.yml`: Orchestrates the monitor and SIEM logger containers.
- `deploy_monitor.py`: Handles interface input and deployment.
- `outbound_monitor_v2.py`: Captures traffic and extracts IPs.
- `siem_logger.py`: Generates SIEM-compatible logs.
- `requirements.txt`: Python dependencies.

## Logs
- **PCAP Files**: Stored in `/var/log/outbound_collector/conn-all-*.pcap`.
- **Unique IPs**: Stored in `/var/log/outbound_collector/unique_ips.json`.
- **SIEM Logs**: Stored in `/var/log/siem/siem_outbound_ips.jsonl`.
- **Application Logs**: Stored in `/var/log/outbound_collector/*.log`.

## Monitoring
- Check container status: `docker ps`
- View logs: `docker logs outbound_monitor` or `docker logs siem_logger`
- Stop containers: `docker compose down`

## Customization
- Adjust `ROTATION_SECONDS` and `RETENTION_FILES` in `docker-compose.yml`.
- Modify `SIEM_LOG_INTERVAL` (seconds) for SIEM logging frequency.

## Security Notes
- Containers require `NET_ADMIN` and `NET_RAW` capabilities for `tcpdump`.
- Logs are stored with restricted permissions (750).
- Non-root user (`nobody`) is used where possible.