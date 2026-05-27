#!/bin/bash
set -e

# Generate self-signed certificate for development
openssl req -x509 -newkey rsa:4096 -nodes -out /etc/nginx/certs/server.crt -keyout /etc/nginx/certs/server.key -days 365 -subj "/C=US/ST=State/L=City/O=StaticCodeAnalyzer/CN=localhost"

echo "Self-signed certificate generated at /etc/nginx/certs/"