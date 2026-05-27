#!/bin/bash
set -e

DOMAIN=$1
EMAIL=$2

if [ -z "$DOMAIN" ] || [ -z "$EMAIL" ]; then
  echo "Usage: $0 <domain> <email>"
  exit 1
fi

# Install certbot if not present
if ! command -v certbot &> /dev/null; then
  apt-get update
  apt-get install -y certbot python3-certbot-nginx
fi

# Obtain Let's Encrypt certificate
certbot --nginx -d $DOMAIN --email $EMAIL --agree-tos --non-interactive --http-01-port 80

# Update NGINX config to use Let's Encrypt certificates
sed -i 's|/etc/nginx/certs/server.crt|/etc/letsencrypt/live/$DOMAIN/fullchain.pem|' /etc/nginx/conf.d/default.conf
sed -i 's|/etc/nginx/certs/server.key|/etc/letsencrypt/live/$DOMAIN/privkey.pem|' /etc/nginx/conf.d/default.conf

# Setup auto-renewal cron job
echo "0 0,12 * * * root certbot renew --quiet --nginx" >> /etc/crontab

# Reload NGINX
nginx -s reload

echo "Let's Encrypt certificate installed for $DOMAIN"