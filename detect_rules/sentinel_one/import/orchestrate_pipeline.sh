#!/usr/bin/env bash
# orchestrate_pipeline.sh
# Usage: ./orchestrate_pipeline.sh [--config pipeline-config.yaml] [--engine podman] [--cleanup]

set -euo pipefail

CONFIG_FILE="${1:-pipeline-config.yaml}"
ENGINE="docker"
CLEANUP=0

# Parse optional flags
while [[ $# -gt 0 ]]; do
    case $1 in
        --config) CONFIG_FILE="$2"; shift 2 ;;
        --engine) ENGINE="$2"; shift 2 ;;
        --cleanup) CLEANUP=1; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: Config file not found: $CONFIG_FILE"
    exit 1
fi

# Extract values using yq (install with: sudo snap install yq or brew install yq, etc.)
# If you don't want to depend on yq, we can use python -c 'import yaml; ...' instead
API_URL=$(yq '.sentinelone.api_url' "$CONFIG_FILE")
SITES=$(yq '.sentinelone.sites // [] | join(",")' "$CONFIG_FILE")
MD_FILES=$(yq '.parsing.markdown_files // [] | join(" ")' "$CONFIG_FILE")
OUTPUT_DIR=$(yq '.output.json_directory' "$CONFIG_FILE")
FROM_TIME=$(yq '.output.time_range.from' "$CONFIG_FILE")
TO_TIME=$(yq '.output.time_range.to' "$CONFIG_FILE")

# Fallbacks / validation
API_URL=${API_URL:? "api_url is required in config"}
[ -z "$SITES" ] && echo "Warning: No sites defined — queries will fail!" && exit 1

echo "┌──────────────────────────────────────────────────────┐"
echo "│ Pipeline Configuration                               │"
echo "├──────────────────────────────────────────────────────┤"
printf "│ API URL    │ %s\n" "$API_URL"
printf "│ Sites      │ %s\n" "${SITES//,/, }"
printf "│ Markdowns  │ %s\n" "$MD_FILES"
printf "│ Output dir │ %s\n" "$OUTPUT_DIR"
echo "└──────────────────────────────────────────────────────┘"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Step 1: Run parser with targeted files and config params
# (assumes updated parser accepts --files, --output-dir, --sites, --from, --to)
echo "Parsing selected Markdown files..."
python3 parse_md_to_json.py \
    --config "$CONFIG_FILE"

# Check if we actually generated anything
if ! ls "$OUTPUT_DIR"/*.json >/dev/null 2>&1; then
    echo "Error: No JSON files were generated."
    exit 1
fi

# Step 2: Build image (if needed — can be cached)
echo "Building container image..."
$ENGINE build -t sentinelone-importer .

# Step 3: Run upload (mount output dir, pass env vars)
echo "Uploading queries to SentinelOne..."
$ENGINE run --rm \
    -e API_TOKEN="${API_TOKEN:-}" \
    -e SENTINELONE_API_URL="$API_URL" \
    -v "$(pwd)/$OUTPUT_DIR:/import" \
    sentinelone-importer

# Optional cleanup
if [ "$CLEANUP" -eq 1 ] || yq '.logging.cleanup_after_run // false' "$CONFIG_FILE" | grep -qi true; then
    echo "Cleaning up generated JSON files..."
    rm -rf "$OUTPUT_DIR"
fi

echo "Pipeline finished successfully."