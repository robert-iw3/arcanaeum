#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

# Configuration
LOG_FILE="/var/log/docker_stig.log"
BACKUP_DIR="/var/backups/docker"
DOCKER_DAEMON_JSON="/etc/docker/daemon.json"
DOCKER_SOCK="/run/containerd/containerd.sock"
DOCKER_LEGACY_CONF="/etc/default/docker"
ETC_DOCKER_PATH="/etc/docker"
DOCKER_SOCKET_PATH="/lib/systemd/system/docker.socket"
DOCKER_SERVICE_PATH="/lib/systemd/system/docker.service"
SYSLOG_ADDRESS="udp://127.0.0.1:25224"
AUDIT_RULES_FILE="/etc/audit/rules.d/docker.rules"
VERBOSE=${VERBOSE:-"N"}
JSON_OUTPUT=${JSON_OUTPUT:-"N"}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
NC='\033[0m'

# Logging functions
log() {
  echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] $*" | tee -a "$LOG_FILE"
}

log_success() {
  log "$1, ${GREEN}PASS${NC}, $2"
  [[ "$JSON_OUTPUT" == "Y" ]] && echo "{\"id\":\"$1\",\"status\":\"PASS\",\"message\":\"$2\"}" >> "$LOG_FILE.json"
}

log_failure() {
  log "$1, ${RED}FAIL${NC}, $2"
  [[ "$JSON_OUTPUT" == "Y" ]] && echo "{\"id\":\"$1\",\"status\":\"FAIL\",\"message\":\"$2\"}" >> "$LOG_FILE.json"
}

log_manual() {
  log "$1, ${ORANGE}MANUAL${NC}, $2"
  [[ "$JSON_OUTPUT" == "Y" ]] && echo "{\"id\":\"$1\",\"status\":\"MANUAL\",\"message\":\"$2\"}" >> "$LOG_FILE.json"
}

log_na() {
  log "$1, ${ORANGE}N/A${NC}, $2"
  [[ "$JSON_OUTPUT" == "Y" ]] && echo "{\"id\":\"$1\",\"status\":\"N/A\",\"message\":\"$2\"}" >> "$LOG_FILE.json"
}

# Display help
display_help() {
  echo "Usage: $0 [options]"
  echo "Options:"
  echo "  -h, --help        Display this help menu"
  echo "  -v, --verbose     Show detailed command output"
  echo "  -j, --json        Output results in JSON format to $LOG_FILE.json"
  echo "  -i, --ip <IP>     Set Docker bind IP (default: auto-detect)"
  echo "  -s, --sock <PATH> Set Docker socket path (default: $DOCKER_SOCK)"
}

# Backup file
backup_file() {
  local file=$1
  if [[ -f "$file" ]]; then
    local backup="$BACKUP_DIR/$(basename "$file").$(date +%s)"
    mkdir -p "$BACKUP_DIR"
    cp "$file" "$backup"
    log "Backed up $file to $backup"
  fi
}

# Check dependencies
check_deps() {
  local deps=("jq" "auditctl" "ausearch" "docker" "rsyslogd")
  for cmd in "${deps[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then
      log "Error: $cmd is required but not installed"
      exit 1
    fi
  done
}

# Check privileges
check_privileges() {
  if ! capsh --print | grep -q "cap_sys_admin"; then
    log "Error: This script requires root or CAP_SYS_ADMIN privileges"
    exit 1
  fi
}

# Validate path
validate_path() {
  local path=$1
  path=$(realpath -m "$path" 2>/dev/null)
  if [[ ! -e "$path" ]] || [[ "$path" == */..* ]]; then
    log "Error: Invalid path $path"
    exit 1
  fi
  echo "$path"
}

# Configure file permissions and ownership
configure_file() {
  local path=$1 owner=$2 perms=$3 stig_id=$4 desc=$5
  path=$(validate_path "$path")
  if [[ -e "$path" ]]; then
    backup_file "$path"
    chown "$owner" "$path"
    log_success "$stig_id" "$desc (ownership set to $owner)"
    [[ "$VERBOSE" == "Y" ]] && echo "Command: stat -c %U:%G $path" && stat -c %U:%G "$path"
    chmod "$perms" "$path"
    log_success "$stig_id" "$desc (permissions set to $perms)"
    [[ "$VERBOSE" == "Y" ]] && echo "Command: stat -c %a $path" && stat -c %a "$path"
  else
    log_na "$stig_id" "$path does not exist"
  fi
}

# Update daemon.json
update_daemon_json() {
  local key=$1 value=$2 stig_id=$3 desc=$4
  backup_file "$DOCKER_DAEMON_JSON"
  if jq -e ".$key" "$DOCKER_DAEMON_JSON" >/dev/null; then
    if [[ "$(jq -r ".$key" "$DOCKER_DAEMON_JSON")" == "$value" ]]; then
      log_success "$stig_id" "$desc (already set)"
    else
      log_failure "$stig_id" "$desc (incorrect value, updating)"
      jq ".$key = $value" "$DOCKER_DAEMON_JSON" > /tmp/daemon.json.$$
      mv /tmp/daemon.json.$$ "$DOCKER_DAEMON_JSON"
      log_success "$stig_id" "$desc (updated)"
    fi
  else
    jq ". + {$key: $value}" "$DOCKER_DAEMON_JSON" > /tmp/daemon.json.$$
    mv /tmp/daemon.json.$$ "$DOCKER_DAEMON_JSON"
    log_success "$stig_id" "$desc (added)"
  fi
  [[ "$VERBOSE" == "Y" ]] && echo "Command: jq .$key $DOCKER_DAEMON_JSON" && jq ".$key" "$DOCKER_DAEMON_JSON"
}

# Check containers
check_containers() {
  local format=$1 pattern=$2 stig_id=$3 fail_msg=$4 pass_msg=$5
  local containers
  containers=$(docker ps --quiet --all | xargs --no-run-if-empty docker inspect --format "$format")
  if echo "$containers" | grep -q -i "$pattern"; then
    log_failure "$stig_id" "$fail_msg"
    [[ "$VERBOSE" == "Y" ]] && echo "Command: docker ps --quiet --all | xargs --no-run-if-empty docker inspect --format '$format'" && echo "Output: $containers"
  else
    log_success "$stig_id" "$pass_msg"
    [[ "$VERBOSE" == "Y" ]] && echo "Command: docker ps --quiet --all | xargs --no-run-if-empty docker inspect --format '$format'" && echo "Output: $containers"
  fi
}

# Main
main() {
  # Parse arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -v|--verbose) VERBOSE="Y"; shift ;;
      -j|--json) JSON_OUTPUT="Y"; shift ;;
      -i|--ip) PRI_IP="$2"; shift 2 ;;
      -s|--sock) DOCKER_SOCK="$2"; shift 2 ;;
      -h|--help) display_help; exit 0 ;;
      *) log "Error: Unknown option $1"; display_help; exit 1 ;;
    esac
  done

  # Initialize logging
  mkdir -p "$(dirname "$LOG_FILE")" "$BACKUP_DIR"
  touch "$LOG_FILE" "$LOG_FILE.json"
  chown root:root "$LOG_FILE" "$LOG_FILE.json"
  chmod 640 "$LOG_FILE" "$LOG_FILE.json"
  log "Starting Docker STIG configuration"

  # Check dependencies and privileges
  check_deps
  check_privileges

  # Validate socket
  DOCKER_SOCK=$(validate_path "$DOCKER_SOCK")
  if [[ ! -S "$DOCKER_SOCK" ]]; then
    log "Error: Docker socket $DOCKER_SOCK does not exist"
    exit 1
  fi

  # Initialize daemon.json
  DOCKER_DAEMON_JSON=$(validate_path "$DOCKER_DAEMON_JSON")
  if [[ ! -f "$DOCKER_DAEMON_JSON" ]]; then
    echo "{}" > "$DOCKER_DAEMON_JSON"
    log "Created $DOCKER_DAEMON_JSON"
  fi

  # Auto-detect IP if not provided
  if [[ -z "${PRI_IP:-}" ]]; then
    PRI_INTERFACE=$(ip route | grep -m 1 'default via' | grep -Po '(?<=dev )\S+' || true)
    PRI_IP=$(ip -f inet addr show "${PRI_INTERFACE}" | grep -Po '(?<=inet )(\d{1,3}\.)+\d{1,3}' || echo "127.0.0.1")
    log "Auto-detected IP: $PRI_IP (interface: $PRI_INTERFACE)"
    read -rp "Confirm Docker bind to $PRI_IP? (y/n): " choice
    case "$choice" in
      n|N) log "Error: User declined IP $PRI_IP, please specify with --ip"; exit 1 ;;
      y|Y|*) ;;
    esac
  fi

  # File permissions and ownership
  configure_file "$DOCKER_DAEMON_JSON" "root:root" "0644" "V-235867" "Set daemon.json ownership and permissions"
  configure_file "$DOCKER_SOCK" "root:docker" "0660" "V-235865" "Set docker socket ownership and permissions"
  configure_file "$ETC_DOCKER_PATH" "root:root" "0755" "V-235855" "Set /etc/docker ownership and permissions"
  configure_file "$DOCKER_SOCKET_PATH" "root:root" "0644" "V-235853" "Set docker.socket ownership and permissions"
  configure_file "$DOCKER_SERVICE_PATH" "root:root" "0644" "V-235851" "Set docker.service ownership and permissions"
  configure_file "$DOCKER_LEGACY_CONF" "root:root" "0644" "V-235869" "Set legacy docker conf ownership and permissions"

  # Container checks
  check_containers '{{ .Id }}: SecurityOpt={{ .HostConfig.SecurityOpt }}' 'unconfined' 'V-235812' 'Found containers with seccomp unconfined' 'No seccomp unconfined containers found'
  check_containers '{{ .Id }}: Ulimits={{ .HostConfig.Ulimits }}' 'no value' 'V-235844' 'Containers override ulimit' 'No containers override default ulimit'
  check_containers '{{ .Id }}: PidMode={{ .HostConfig.PidMode }}' 'host' 'V-235784' 'Containers running with host PID namespace' 'No containers with host PID namespace'
  check_containers '{{ .Id }}: IpcMode={{ .HostConfig.IpcMode }}' 'host' 'V-235785' 'Containers running with host IPC namespace' 'No containers with host IPC namespace'
  check_containers '{{ .Id }}: UsernsMode={{ .HostConfig.UsernsMode }}' 'host' 'V-235817' 'Containers sharing host user namespace' 'No containers sharing host user namespace'
  check_containers '{{ .Id }}: UTSMode={{ .HostConfig.UTSMode }}' 'host' 'V-235811' 'Containers sharing host UTS namespace' 'No containers with host UTS namespace'
  check_containers '{{ .Id }}: Devices={{ .HostConfig.Devices }}' 'pathincontainer' 'V-235809' 'Containers with host devices passed in' 'No containers with host devices'
  check_containers '{{ .Id }}: Volumes={{ .Mounts }}' 'Source:[^ ]+:(/|/boot|/dev|/etc|/lib|/proc|/sys|/usr)$' 'V-235783' 'Sensitive directories mapped into containers' 'No sensitive directories mapped'
  check_containers '{{ .Id }}: Propagation={{range $mnt := .Mounts}} {{json $mnt.Propagation}} {{end}}' 'shared' 'V-235810' 'Mount propagation set to shared' 'No mounts set to shared propagation'
  check_containers '{{ .Id }}: CapAdd={{ .HostConfig.CapAdd }} CapDrop={{ .HostConfig.CapDrop }}' 'CapAdd=<no value> CapDrop=<no value>$' 'V-235801' 'Containers with added capabilities' 'No containers with additional capabilities'
  check_containers '{{ .Id }}: Privileged={{ .HostConfig.Privileged }}' 'true' 'V-235802' 'Containers running as privileged' 'No containers running as privileged'

  # AppArmor check
  if docker ps --quiet --all | xargs --no-run-if-empty docker inspect --format '{{ .Id }}: AppArmorProfile={{ .AppArmorProfile }}' | grep -q 'unconfined'; then
    log_failure 'V-235799' 'Containers running without AppArmor profiles'
  else
    log_success 'V-235799' 'All containers running with AppArmor profiles'
  fi
  [[ "$VERBOSE" == "Y" ]] && echo "Command: docker ps --quiet --all | xargs --no-run-if-empty docker inspect --format '{{ .Id }}: AppArmorProfile={{ .AppArmorProfile }}'" && docker ps --quiet --all | xargs --no-run-if-empty docker inspect --format '{{ .Id }}: AppArmorProfile={{ .AppArmorProfile }}'

  # SSHD check
  PASS=1
  for i in $(docker ps -qa); do
    if docker exec "$i" ps -el 2>/dev/null | grep -q -i sshd; then
      log_failure 'V-235803' "Container $i running sshd"
      [[ "$VERBOSE" == "Y" ]] && echo "Command: docker exec $i ps -el | grep -i sshd" && docker exec "$i" ps -el | grep -i sshd
      PASS=0
    fi
  done
  [[ $PASS -eq 1 ]] && log_success 'V-235803' 'No containers running sshd'

  # Storage driver check
  if docker info --format '{{ .Driver }}' | grep -q '^aufs$'; then
    log_failure 'V-235790' 'AUFS storage driver detected'
  else
    log_success 'V-235790' 'No AUFS storage driver detected'
  fi
  [[ "$VERBOSE" == "Y" ]] && echo "Command: docker info --format '{{ .Driver }}'" && docker info --format '{{ .Driver }}'

  # Experimental features
  if docker version --format '{{ .Server.Experimental }}' | grep -q false; then
    log_success 'V-235792' 'Experimental features disabled'
  else
    log_failure 'V-235792' 'Experimental features enabled'
  fi
  [[ "$VERBOSE" == "Y" ]] && echo "Command: docker version --format '{{ .Server.Experimental }}'" && docker version --format '{{ .Server.Experimental }}'

  # Insecure registries
  if pgrep -af dockerd | grep -q 'insecure-registry' || grep -q 'insecure-registry' "$DOCKER_DAEMON_JSON"; then
    log_failure 'V-235789' 'Insecure registries configured'
  else
    log_success 'V-235789' 'No insecure registries configured'
  fi
  [[ "$VERBOSE" == "Y" ]] && echo "Command: pgrep -af dockerd && grep 'insecure-registry' $DOCKER_DAEMON_JSON" && pgrep -af dockerd && grep 'insecure-registry' "$DOCKER_DAEMON_JSON"

  # Userland proxy
  if pgrep -af dockerd | grep -q 'userland-proxy'; then
    log_failure 'V-235791' 'Userland-proxy flag used in dockerd arguments'
  elif jq -e '."userland-proxy" == false' "$DOCKER_DAEMON_JSON" >/dev/null; then
    log_success 'V-235791' 'Userland-proxy disabled in daemon.json'
  else
    update_daemon_json '"userland-proxy"' 'false' 'V-235791' 'Disable userland-proxy'
  fi

  # IP binding
  if jq -e '."ip" and ."ip" != "0.0.0.0"' "$DOCKER_DAEMON_JSON" >/dev/null; then
    log_success 'V-235820' 'Docker configured to listen on specific IP'
  else
    update_daemon_json '"ip"' "\"$PRI_IP\"" 'V-235820' 'Bind Docker to specific IP'
  fi

  # Logging configuration
  if jq -e '."log-driver" == "syslog"' "$DOCKER_DAEMON_JSON" >/dev/null; then
    log_success 'V-235831' 'Log driver set to syslog'
  else
    update_daemon_json '"log-driver"' '"syslog"' 'V-235831' 'Configure log driver to syslog'
  fi

  if jq -e '."log-opts"."syslog-address"' "$DOCKER_DAEMON_JSON" >/dev/null; then
    log_success 'V-235833' 'Remote syslog configured'
  else
    update_daemon_json '"log-opts"' "{\"syslog-address\": \"$SYSLOG_ADDRESS\", \"tag\": \"container_name/{{.Name}}\", \"syslog-facility\": \"daemon\"}" 'V-235833' 'Configure remote syslog'
  fi

  # Log size limits (CIS 2.11)
  if jq -e '."log-opts"."max-size" and ."log-opts"."max-file"' "$DOCKER_DAEMON_JSON" >/dev/null; then
    log_success 'V-235786' 'Log max-size and max-file configured'
  else
    update_daemon_json '"log-opts"' '{"max-size": "10m", "max-file": "3"}' 'V-235786' 'Configure log max-size and max-file'
  fi

  # Audit rules
  if ! auditctl -l | grep -qE "-w $DOCKER_DAEMON_JSON" || ! auditctl -l | grep -qE "-w $DOCKER_SERVICE_PATH" || ! auditctl -l | grep -qE "-w $DOCKER_SOCKET_PATH"; then
    log "Adding audit rules for Docker"
    cat << EOF > "$AUDIT_RULES_FILE"
-w $DOCKER_DAEMON_JSON -p wa -k docker
-w $DOCKER_SERVICE_PATH -p wa -k docker
-w $DOCKER_SOCKET_PATH -p wa -k docker
EOF
    chmod 640 "$AUDIT_RULES_FILE"
    augenrules --load
    log_success 'V-235779' 'Audit rules added for Docker files'
  else
    log_success 'V-235779' 'Audit rules present for Docker files'
  fi
  [[ "$VERBOSE" == "Y" ]] && echo "Command: auditctl -l | grep -E '(-w $DOCKER_DAEMON_JSON|-w $DOCKER_SERVICE_PATH|-w $DOCKER_SOCKET_PATH)'" && auditctl -l | grep -E "(-w $DOCKER_DAEMON_JSON|-w $DOCKER_SERVICE_PATH|-w $DOCKER_SOCKET_PATH)"

  # Privileged exec sessions
  if ausearch -k docker | grep exec | grep -q privileged; then
    log_failure 'V-235813' 'Exec sessions running with privileged flag'
  else
    log_success 'V-235813' 'No privileged exec sessions found'
  fi
  [[ "$VERBOSE" == "Y" ]] && echo "Command: ausearch -k docker | grep exec | grep privileged" && ausearch -k docker | grep exec | grep privileged

  # User flag in exec
  if pgrep -af 'docker exec' | grep -qE '\-u|\-\-user'; then
    log_failure 'V-235814' 'Exec sessions running with user flag'
  else
    log_success 'V-235814' 'No exec sessions with user flag found'
  fi
  [[ "$VERBOSE" == "Y" ]] && echo "Command: pgrep -af 'docker exec' | grep -E '\-u|\-\-user'" && pgrep -af 'docker exec' | grep -E '\-u|\-\-user'

  # Host port check
  LOW_HOST_PORT=$(docker ps --quiet --all | xargs --no-run-if-empty docker inspect --format '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}' | grep -Po '(?<=HostPort:)\d+' | sort -n | head -n 1)
  if [[ -n "$LOW_HOST_PORT" ]] && [[ "$LOW_HOST_PORT" -lt 1024 ]]; then
    log_failure 'V-235819' 'Host ports below 1024 mapped into containers'
  else
    log_success 'V-235819' 'No host ports mapped below 1024'
  fi
  [[ "$VERBOSE" == "Y" ]] && echo "Command: docker ps --quiet --all | xargs --no-run-if-empty docker inspect --format '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}'" && docker ps --quiet --all | xargs --no-run-if-empty docker inspect --format '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}'

  # Manual port checks
  log_manual 'V-235837' 'Review exposed ports in SSP (HostPort field)'
  docker ps -q | xargs --no-run-if-empty docker inspect --format '{{ .Id }}: {{ .Name }}: Ports={{ .NetworkSettings.Ports }}' | grep HostPort
  log_manual 'V-235804' 'Review exposed ports in SSP (Host field)'
  docker ps --quiet | xargs --no-run-if-empty docker inspect --format '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}' | grep -i host

  log "Docker STIG configuration complete. Restart Docker service to apply changes."
  [[ "$JSON_OUTPUT" == "Y" ]] && log "JSON output written to $LOG_FILE.json"
}

main "$@"