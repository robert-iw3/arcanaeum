#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

# Configuration
LOG_FILE="/var/log/ssh_key_audit.log"
JSON_LOG_FILE="/var/log/ssh_key_audit.json"
KEY_COUNT=${KEY_COUNT:-10}
SECONDS_LIMIT=${SECONDS_LIMIT:-86400}  # 24 hours
VERBOSE=${VERBOSE:-"N"}
JSON_OUTPUT=${JSON_OUTPUT:-"N"}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Logging functions
log() {
  echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] $*" | tee -a "$LOG_FILE"
}

log_result() {
  local status=$1 message=$2
  local color=$([ "$status" == "FAIL" ] && echo "$RED" || echo "$GREEN")
  log "$status, ${color}${message}${NC}"
  [[ "$JSON_OUTPUT" == "Y" ]] && echo "{\"timestamp\":\"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\",\"status\":\"$status\",\"message\":\"$message\"}" >> "$JSON_LOG_FILE"
}

# Display help
display_help() {
  echo "Usage: $0 [options]"
  echo "Options:"
  echo "  -h, --help        Display this help menu"
  echo "  -v, --verbose     Show detailed command output"
  echo "  -j, --json        Output results in JSON format"
  echo "  -k, --key-count   Set max keys threshold (default: $KEY_COUNT)"
  echo "  -s, --seconds     Set modification time limit in seconds (default: $SECONDS_LIMIT)"
}

# Check dependencies
check_deps() {
  local deps=("awk" "grep" "sort" "uniq" "stat")
  for cmd in "${deps[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then
      log "Error: $cmd is required but not installed"
      exit 1
    fi
  done
}

# Check privileges
check_privileges() {
  if ! capsh --print | grep -q "cap_dac_read_search"; then
    log "Error: This script requires root or CAP_DAC_READ_SEARCH privileges"
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

# Check SSH private keys
find_ssh_private_key() {
  log "Checking for SSH private keys"
  for dir in $home_dirs; do
    dir=$(validate_path "$dir")
    ssh_dir="$dir/.ssh"
    if [[ -d "$ssh_dir" ]]; then
      if [[ "$(stat -c %a "$ssh_dir")" != "700" ]]; then
        log_result "FAIL" "Incorrect permissions on $ssh_dir (should be 700)"
      fi
      while IFS= read -r file; do
        if [[ -f "$file" ]]; then
          if grep -q "PRIVATE KEY" "$file"; then
            log_result "FAIL" "Private key found in $file"
            [[ "$VERBOSE" == "Y" ]] && echo "Command: grep -l 'PRIVATE KEY' $file" && head -n 1 "$file"
          fi
          if [[ "$(stat -c %a "$file")" != "600" ]]; then
            log_result "FAIL" "Incorrect permissions on $file (should be 600)"
          fi
        fi
      done < <(find "$ssh_dir" -type f)
    fi
  done
}

# Check duplicate keys
find_ssh_keys_duplicates() {
  log "Checking for duplicate SSH keys"
  for dir in $home_dirs; do
    dir=$(validate_path "$dir")
    auth_keys="$dir/.ssh/authorized_keys"
    if [[ -f "$auth_keys" ]]; then
      if [[ "$(stat -c %a "$auth_keys")" != "600" ]]; then
        log_result "FAIL" "Incorrect permissions on $auth_keys (should be 600)"
      fi
      while read -r count key; do
        if [[ "$count" -gt 1 ]]; then
          log_result "FAIL" "$key is duplicated $count times in $auth_keys"
          [[ "$VERBOSE" == "Y" ]] && echo "Command: sort $auth_keys | uniq -c" && grep "$key" "$auth_keys"
        fi
      done < <(sort "$auth_keys" | uniq -c | awk '$1 > 1')
    fi
  done
}

# Check excessive keys
find_ssh_keys_excessive() {
  log "Checking for excessive SSH keys (threshold: $KEY_COUNT)"
  for dir in $home_dirs; do
    dir=$(validate_path "$dir")
    auth_keys="$dir/.ssh/authorized_keys"
    if [[ -f "$auth_keys" ]]; then
      num_keys=$(wc -l < "$auth_keys")
      if [[ "$num_keys" -ge "$KEY_COUNT" ]]; then
        log_result "FAIL" "$auth_keys has $num_keys keys (exceeds $KEY_COUNT)"
        [[ "$VERBOSE" == "Y" ]] && echo "Command: wc -l $auth_keys" && echo "Output: $num_keys"
      fi
    fi
  done
}

# Check recently modified keys
find_ssh_keys_modified_24hr() {
  log "Checking for recently modified SSH keys (within $SECONDS_LIMIT seconds)"
  now=$(date +%s)
  for dir in $home_dirs; do
    dir=$(validate_path "$dir")
    auth_keys="$dir/.ssh/authorized_keys"
    if [[ -f "$auth_keys" ]]; then
      mtime=$(stat -c %Y "$auth_keys")
      diff=$((now - mtime))
      if [[ "$diff" -le "$SECONDS_LIMIT" ]]; then
        log_result "FAIL" "$auth_keys modified $diff seconds ago"
        [[ "$VERBOSE" == "Y" ]] && echo "Command: stat -c %Y $auth_keys" && echo "Output: $mtime"
      fi
    fi
  done
}

# Check SSH key options
find_ssh_keys_options_search() {
  log "Checking for SSH key options"
  for dir in $home_dirs; do
    dir=$(validate_path "$dir")
    auth_keys="$dir/.ssh/authorized_keys"
    if [[ -f "$auth_keys" ]]; then
      while IFS= read -r line; do
        if [[ "$line" =~ ^(command|environment|agent-forwarding|port-forwarding|user-rc|X11-forwarding) ]]; then
          log_result "FAIL" "Option found in $auth_keys: $line"
          [[ "$VERBOSE" == "Y" ]] && echo "Command: grep -E '^(command|environment|agent-forwarding|port-forwarding|user-rc|X11-forwarding)' $auth_keys" && echo "Output: $line"
        fi
      done < <(grep -E '^(command|environment|agent-forwarding|port-forwarding|user-rc|X11-forwarding)' "$auth_keys" 2>/dev/null)
    fi
  done
}

# Check for authorized_keys2
ssh_keys2_search() {
  log "Checking for deprecated authorized_keys2 files"
  for dir in $home_dirs; do
    dir=$(validate_path "$dir")
    auth_keys2="$dir/.ssh/authorized_keys2"
    if [[ -f "$auth_keys2" ]]; then
      log_result "FAIL" "Deprecated authorized_keys2 found at $auth_keys2"
      [[ "$VERBOSE" == "Y" ]] && echo "Command: find $dir/.ssh -name authorized_keys2" && ls -l "$auth_keys2"
    fi
  done
}

# Main
main() {
  # Parse arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -v|--verbose) VERBOSE="Y"; shift ;;
      -j|--json) JSON_OUTPUT="Y"; shift ;;
      -k|--key-count) KEY_COUNT="$2"; shift 2 ;;
      -s|--seconds) SECONDS_LIMIT="$2"; shift 2 ;;
      -h|--help) display_help; exit 0 ;;
      *) log "Error: Unknown option $1"; display_help; exit 1 ;;
    esac
  done

  # Initialize logging
  mkdir -p "$(dirname "$LOG_FILE")"
  touch "$LOG_FILE" "$JSON_LOG_FILE"
  chown root:root "$LOG_FILE" "$JSON_LOG_FILE"
  chmod 640 "$LOG_FILE" "$JSON_LOG_FILE"
  log "Starting SSH key audit"

  check_deps
  check_privileges

  # Get home directories
  home_dirs=$(awk -F':' '$6 && $6 !~ /\/nologin|\/false/ {print $6}' /etc/passwd | sort -u)

  find_ssh_private_key
  find_ssh_keys_duplicates
  find_ssh_keys_excessive
  find_ssh_keys_modified_24hr
  find_ssh_keys_options_search
  ssh_keys2_search

  log "SSH key audit complete"
  [[ "$JSON_OUTPUT" == "Y" ]] && log "JSON output written to $JSON_LOG_FILE"
}

main "$@"