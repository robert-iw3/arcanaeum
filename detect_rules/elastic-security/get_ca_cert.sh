#!/bin/bash
# Script to retrieve the CA certificate (http_ca.crt) from an Elasticsearch on-prem deployment
# Supports Docker and host/VM-based deployments
# Usage: ./get_ca_cert.sh --container <container_name> --output <output_path> [--host <es_host> --user <ssh_user>]

set -e

# Default values
CONTAINER_NAME=""
ES_HOST=""
SSH_USER="elastic"
OUTPUT_PATH="ca.crt"
ES_CERT_PATH="/usr/share/elasticsearch/config/certs/http_ca.crt"  # Docker default
ES_HOST_CERT_PATH="/etc/elasticsearch/certs/http_ca.crt"         # Host/VM default

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --container)
            CONTAINER_NAME="$2"
            shift 2
            ;;
        --host)
            ES_HOST="$2"
            shift 2
            ;;
        --user)
            SSH_USER="$2"
            shift 2
            ;;
        --output)
            OUTPUT_PATH="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--container <container_name>] [--host <es_host> --user <ssh_user>] --output <output_path>"
            exit 1
            ;;
    esac
done

# Validate inputs
if [ -z "$CONTAINER_NAME" ] && [ -z "$ES_HOST" ]; then
    echo "Error: Must provide either --container or --host"
    exit 1
fi
if [ -z "$OUTPUT_PATH" ]; then
    echo "Error: Must provide --output path"
    exit 1
fi

# Retrieve CA certificate
if [ -n "$CONTAINER_NAME" ]; then
    echo "Retrieving CA certificate from Docker container: $CONTAINER_NAME"
    docker cp "$CONTAINER_NAME:$ES_CERT_PATH" "$OUTPUT_PATH"
elif [ -n "$ES_HOST" ]; then
    echo "Retrieving CA certificate from host: $ES_HOST"
    scp "$SSH_USER@$ES_HOST:$ES_HOST_CERT_PATH" "$OUTPUT_PATH"
fi

# Verify the certificate exists
if [ -f "$OUTPUT_PATH" ]; then
    echo "Successfully retrieved CA certificate to $OUTPUT_PATH"
    openssl x509 -in "$OUTPUT_PATH" -noout -text | grep -E "Subject:|Issuer:"
else
    echo "Error: Failed to retrieve CA certificate to $OUTPUT_PATH"
    exit 1
fi