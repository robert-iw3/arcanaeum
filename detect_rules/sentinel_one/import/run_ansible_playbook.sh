#!/usr/bin/env bash

# Interactive wrapper to run the SentinelOne threat hunting query pipeline via Ansible
# Prompts for all necessary inputs and executes ansible-playbook safely

set -euo pipefail

PLAYBOOK="pipeline_playbook.yml"

# Colors for better UX
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}SentinelOne Deep Visibility Query Pipeline Launcher${NC}"
echo "======================================================"
echo

# Check if playbook exists
if [[ ! -f "$PLAYBOOK" ]]; then
    echo -e "${RED}Error: $PLAYBOOK not found in current directory.${NC}"
    echo "Please run this script from the directory containing your Ansible playbook."
    exit 1
fi

# Prompt for required values
read -p "SentinelOne API URL (e.g. https://yourcompany.s1.systems/api/v2.0): " api_url
while [[ -z "$api_url" ]]; do
    echo -e "${RED}API URL is required.${NC}"
    read -p "SentinelOne API URL: " api_url
done

read -s -p "SentinelOne API Token (input hidden): " api_token
echo
while [[ -z "$api_token" ]]; do
    echo -e "${RED}API Token is required.${NC}"
    read -s -p "SentinelOne API Token: " api_token
    echo
done

# Optional settings with defaults
echo
echo "Optional settings (press Enter to accept default):"
read -p "Container engine [docker/podman] (default: docker): " engine
engine=${engine:-docker}

read -p "Working directory (default: /opt/sentinelone-threat-pipeline): " work_dir
work_dir=${work_dir:-/opt/sentinelone-threat-pipeline}

read -p "Cleanup generated JSON files after upload? [y/N]: " cleanup_input
case "${cleanup_input,,}" in
    y|yes) cleanup="true" ;;
    *) cleanup="false" ;;
esac

read -p "Verbose output? [y/N]: " verbose_input
case "${verbose_input,,}" in
    y|yes) verbose_flag="-vvv" ;;
    *) verbose_flag="" ;;
esac

# Confirm before running
echo
echo -e "${YELLOW}Review your settings:${NC}"
echo "   API URL      : $api_url"
echo "   Work Dir     : $work_dir"
echo "   Engine       : $engine"
echo "   Cleanup      : $cleanup"
echo "   Verbose      : $verbose_flag"
echo
read -p "Proceed with playbook execution? [Y/n]: " confirm
case "${confirm,,}" in
    n|no) echo "Aborted by user."; exit 0 ;;
    *) ;;
esac

# Build and run the ansible-playbook command
echo
echo -e "${GREEN}Launching Ansible playbook...${NC}"
echo "ansible-playbook $PLAYBOOK \\"
echo "  -e \"api_token=$api_token\" \\"
echo "  -e \"api_url=$api_url\" \\"
echo "  -e \"engine=$engine\" \\"
echo "  -e \"work_dir=$work_dir\" \\"
echo "  -e \"cleanup=$cleanup\" $verbose_flag"
echo

ansible-playbook "$PLAYBOOK" \
    -e "api_token=$api_token" \
    -e "api_url=$api_url" \
    -e "engine=$engine" \
    -e "work_dir=$work_dir" \
    -e "cleanup=$cleanup" \
    $verbose_flag

echo
echo -e "${GREEN}Pipeline execution completed.${NC}"
echo "Generated queries (if not cleaned up) are in: $work_dir/generated_queries"