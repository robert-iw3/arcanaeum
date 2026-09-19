#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

# Configuration
BASE_DIR="/var/log/outbound_collector"
PCAP_PATTERN="$BASE_DIR/conn-all-%Y%m%d%H%M.pcap"
UNIQUE_IP_FILE="$BASE_DIR/unique_ips.json"
SIEM_LOG_FILE="/var/log/siem/siem_outbound_ips.jsonl"
LOG_FILE="$BASE_DIR/outbound_ip_collector.log"
EXTRACT_SCRIPT="/usr/local/bin/extract_unique_ips.sh"
STATE_FILE="$BASE_DIR/processed_pcaps.txt"
QUARANTINE_DIR="$BASE_DIR/quarantine"
ROTATION_SECONDS=3600
RETENTION_FILES=24
TEMP_DIR="/tmp/outbound_collector_$$"

# JSON log function
log_json() {
  local level="$1"
  shift
  local timestamp
  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  local message="$*"
  local log_entry
  log_entry=$(jq -n --arg t "$timestamp" --arg l "$level" --arg m "$message" \
    '{timestamp: $t, level: $l, message: $m}')
  echo "$log_entry" | sudo tee -a "$LOG_FILE" >/dev/null
  echo "$log_entry" >&2
}

# Validate sudo privileges
if ! sudo -n true 2>/dev/null; then
  log_json "ERROR" "This script requires sudo privileges."
  exit 1
fi

# Check dependencies
for cmd in tcpdump tshark ip jq; do
  if ! command -v "$cmd" &>/dev/null; then
    log_json "ERROR" "Missing dependency: $cmd"
    exit 1
  fi
done

# Check disk space (require at least 1GB free)
free_kb=$(df --output=avail "$BASE_DIR" 2>/dev/null | tail -n 1)
if [[ -z "$free_kb" || "$free_kb" -lt 1048576 ]]; then
  log_json "ERROR" "Insufficient disk space in $BASE_DIR (<1GB free), free_kb=$free_kb"
  exit 1
fi

# Prompt and validate network interface
log_json "INFO" "Listing available interfaces"
interfaces=$(ip link show | awk -F': ' '/^[0-9]+: / {if ($2 != "lo") print $2}')
if [[ -z "$interfaces" ]]; then
  log_json "ERROR" "No network interfaces found"
  exit 1
fi
echo "Available interfaces:"
echo "$interfaces"
read -rp "Enter the network interface (e.g., eth0, ens5): " IFACE
if ! ip link show "$IFACE" up &>/dev/null; then
  log_json "ERROR" "Invalid or down interface: $IFACE"
  exit 1
fi

# Create directories with secure permissions
sudo mkdir -p "$BASE_DIR" "$QUARANTINE_DIR" "/var/log/siem"
sudo chown root:root "$BASE_DIR" "$QUARANTINE_DIR" "/var/log/siem"
sudo chmod 750 "$BASE_DIR" "$QUARANTINE_DIR" "/var/log/siem"

# Ensure file permissions
for file in "$LOG_FILE" "$UNIQUE_IP_FILE" "$STATE_FILE" "$SIEM_LOG_FILE"; do
  sudo touch "$file"
  sudo chown root:root "$file"
  sudo chmod 640 "$file"
done

# Create temporary directory
mkdir -p "$TEMP_DIR"
chmod 700 "$TEMP_DIR"

# Start tcpdump with optimized filters
log_json "INFO" "Starting tcpdump on interface $IFACE (rotating every ${ROTATION_SECONDS}s, keeping $RETENTION_FILES files)"
sudo nohup tcpdump -n -i "$IFACE" -s 0 "tcp or udp" \
  -G "$ROTATION_SECONDS" -W "$RETENTION_FILES" \
  -w "$PCAP_PATTERN" \
  > /dev/null 2>>"$LOG_FILE" &
TCPDUMP_PID=$!

# Verify tcpdump started
sleep 2
if ! ps -p "$TCPDUMP_PID" &>/dev/null; then
  log_json "ERROR" "Failed to start tcpdump. Check $LOG_FILE for details."
  exit 1
fi
log_json "INFO" "tcpdump started, pid=$TCPDUMP_PID"

# Cleanup old PCAPs
cleanup_pcaps() {
  local time_threshold=$(( $(date +%s) - (RETENTION_FILES * ROTATION_SECONDS) ))
  find "$BASE_DIR" -maxdepth 1 -type f -name 'conn-all-*.pcap' | while read -r pcap; do
    if [[ $(stat -c %Y "$pcap") -lt $time_threshold ]]; then
      sudo mv "$pcap" "$QUARANTINE_DIR/$(basename "$pcap")" 2>/dev/null && \
        log_json "INFO" "Moved old PCAP to quarantine: $(basename "$pcap")" || \
        log_json "ERROR" "Failed to move PCAP $(basename "$pcap") to quarantine"
    fi
  done
}

# Create extraction script
sudo tee "$EXTRACT_SCRIPT" > /dev/null << 'EOF'
#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

BASE_DIR="/var/log/outbound_collector"
UNIQUE_IP_FILE="$BASE_DIR/unique_ips.json"
SIEM_LOG_FILE="/var/log/siem/siem_outbound_ips.jsonl"
STATE_FILE="$BASE_DIR/processed_pcaps.txt"
QUARANTINE_DIR="$BASE_DIR/quarantine"
LOG_FILE="$BASE_DIR/outbound_ip_collector.log"
TEMP_DIR="/tmp/outbound_collector_$$"

# JSON log function
log_json() {
  local level="$1"
  shift
  local timestamp
  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  local message="$*"
  local log_entry
  log_entry=$(jq -n --arg t "$timestamp" --arg l "$level" --arg m "$message" \
    '{timestamp: $t, level: $l, message: $m}')
  echo "$log_entry" | sudo tee -a "$LOG_FILE" >/dev/null
  echo "$log_entry" >&2
}

# Create temporary directory
mkdir -p "$TEMP_DIR"
chmod 700 "$TEMP_DIR"

# Prevent concurrent runs
exec 200>"$BASE_DIR/lockfile"
flock -n 200 || { log_json "ERROR" "Another instance is running, exiting."; exit 1; }

# Check disk space
free_kb=$(df --output=avail "$BASE_DIR" 2>/dev/null | tail -n 1)
if [[ -z "$free_kb" || "$free_kb" -lt 1048576 ]]; then
  log_json "ERROR" "Insufficient disk space in $BASE_DIR (<1GB free), free_kb=$free_kb"
  exit 1
fi

log_json "INFO" "Starting IP extraction"

# Cleanup old PCAPs
time_threshold=$(( $(date +%s) - (24 * 3600) ))
find "$BASE_DIR" -maxdepth 1 -type f -name 'conn-all-*.pcap' | while read -r pcap; do
  if [[ $(stat -c %Y "$pcap") -lt $time_threshold ]]; then
    sudo mv "$pcap" "$QUARANTINE_DIR/$(basename "$pcap")" 2>/dev/null && \
      log_json "INFO" "Moved old PCAP to quarantine: $(basename "$pcap")" || \
      log_json "ERROR" "Failed to move PCAP $(basename "$pcap") to quarantine"
  fi
done

# Initialize JSON output
temp_json="$TEMP_DIR/recent_ips.json"
recent_ips="$TEMP_DIR/recent_ips.txt"
timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "{\"ips\": [], \"timestamp\": \"$timestamp\"}" > "$temp_json"
touch "$recent_ips" "$STATE_FILE"

# Process unprocessed PCAPs (modified in last 24 hours)
start_time=$(date +%s)
find "$BASE_DIR" -maxdepth 1 -type f -name 'conn-all-*.pcap' -mmin -1440 2>/dev/null | while read -r pcap; do
  if ! grep -Fx "$pcap" "$STATE_FILE" &>/dev/null; then
    for attempt in {1..3}; do
      if tshark -r "$pcap" -Y "ip and (tcp or udp)" -T fields -e ip.dst 2>/dev/null > "$recent_ips.partial"; then
        mv "$recent_ips.partial" "$recent_ips"
        echo "$pcap" | sudo tee -a "$STATE_FILE" >/dev/null
        log_json "INFO" "Processed PCAP $(basename "$pcap"), attempt=$attempt"
        break
      else
        log_json "WARNING" "Failed to process $(basename "$pcap") on attempt $attempt"
        [[ $attempt -eq 3 ]] && {
          sudo mv "$pcap" "$QUARANTINE_DIR/$(basename "$pcap")" 2>/dev/null
          log_json "ERROR" "Moved failed PCAP $(basename "$pcap") to quarantine"
        }
        sleep $((2 ** (attempt - 1)))
      fi
    done
  fi
done

# Deduplicate IPs and update JSON
if [[ -s "$recent_ips" ]]; then
  sort -u "$recent_ips" | jq -R . | jq -s '{"ips": .}' > "$temp_json"
  ip_count=$(jq '.ips | length' "$temp_json")
  while read -r ip; do
    jq -n --arg ip "$ip" --arg ts "$timestamp" \
      '{event_type: "outbound_connection", destination_ip: $ip, timestamp: $ts, source: "bash_monitor", interface: "'"$IFACE"'"}' \
      | sudo tee -a "$SIEM_LOG_FILE" >/dev/null
  done < "$recent_ips"
else
  ip_count=0
fi

# Merge with existing JSON
if [[ -s "$UNIQUE_IP_FILE" ]]; then
  jq -s '.[0].ips + .[1].ips | unique | {"ips": ., "timestamp": .[0].timestamp}' \
    "$temp_json" "$UNIQUE_IP_FILE" > "$TEMP_DIR/combined.json"
  sudo mv "$TEMP_DIR/combined.json" "$UNIQUE_IP_FILE"
else
  sudo mv "$temp_json" "$UNIQUE_IP_FILE"
fi

total_ips=$(jq '.ips | length' "$UNIQUE_IP_FILE")
process_time=$(( $(date +%s) - start_time ))
log_json "INFO" "Unique IP list updated, total_ips=$total_ips, new_ips=$ip_count, process_time=${process_time}s"

# Clean up
rm -rf "$TEMP_DIR"

# Schedule next run (use cron in Docker for reliability)
if [[ -n "${DOCKER_CONTAINER:-}" ]]; then
  echo "0 */12 * * * root $EXTRACT_SCRIPT" | sudo tee /etc/cron.d/outbound_ip_extract >/dev/null
else
  echo "$EXTRACT_SCRIPT" | at now + 12 hours 2>>"$LOG_FILE"
fi

exit 0
EOF

# Make extraction script executable
sudo chmod 750 "$EXTRACT_SCRIPT"

# Schedule first run
log_json "INFO" "Scheduling first IP extraction in 12 hours"
if [[ -n "${DOCKER_CONTAINER:-}" ]]; then
  echo "0 */12 * * * root $EXTRACT_SCRIPT" | sudo tee /etc/cron.d/outbound_ip_extract >/dev/null
else
  echo "$EXTRACT_SCRIPT" | at now + 12 hours 2>>"$LOG_FILE"
fi

# Final log
log_json "INFO" "Setup complete, pcap_dir=$BASE_DIR, unique_ips=$UNIQUE_IP_FILE, siem_log=$SIEM_LOG_FILE, extract_script=$EXTRACT_SCRIPT"

# Clean up
rm -rf "$TEMP_DIR"