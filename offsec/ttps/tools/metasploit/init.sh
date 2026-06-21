#!/usr/bin/env bash

set -e

echo '-------------------------------------------'
echo '[+] ---------------------- Initializing tor'
echo '-------------------------------------------'

/usr/bin/torproxy.sh &
sleep 30

echo '------------------------------------------------'
echo '[+] ---------------------- Initializing postgres'
echo '------------------------------------------------'

PG_DIR="/var/lib/postgresql/data"
if [ ! -d "$PG_DIR" ] && [ -d "/var/lib/postgresql" ]; then
    FOUND_DIR=$(find /var/lib/postgresql -type d -name "main" -print -quit 2>/dev/null || echo "")
    if [ -n "$FOUND_DIR" ]; then
        PG_DIR="$FOUND_DIR"
    else
        PG_DIR="/var/lib/postgresql/data"
    fi
fi

mkdir -p "$PG_DIR" /var/run/postgresql

chown -R postgres:postgres /var/lib/postgresql /var/run/postgresql 2>/dev/null || true
chmod 700 "$PG_DIR" 2>/dev/null || true
chmod 775 /var/run/postgresql && chown :postgres /var/run/postgresql 2>/dev/null || true

if [ ! -f "$PG_DIR/PG_VERSION" ]; then
    echo "[*] Data cluster file structures absent. Running structure setup..."
    su - postgres -c "pg_ctlinit -D $PG_DIR" || su - postgres -c "initdb -D $PG_DIR" || true
fi

if command -v service &>/dev/null && service postgresql start; then
    echo "[+] Postgres started via traditional service manager."
elif command -v systemctl &>/dev/null && systemctl start postgresql; then
    echo "[+] Postgres started via systemctl daemon."
else
    echo "[+] Service tools absent. Launching cluster engine directly via pg_ctl..."
    su - postgres -c "pg_ctl -D $PG_DIR start" || true
fi

echo "[*] Waiting for PostgreSQL database system to bind..."
for i in {1..15}; do
    if [ -S /run/postgresql/.s.PGSQL.5432 ] || [ -S /tmp/.s.PGSQL.5432 ]; then
        echo "[+] PostgreSQL service successfully localized via Unix socket."
        break
    fi
    sleep 2
done

cd /usr/share/metasploit-framework

MSFUSER=${MSFUSER:-postgres}
MSFPASS=${MSFPASS:-postgres}

# Set up local database role and schema using direct socket access (no network flags)
if ! su - postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='$MSFUSER'\"" | grep -q "1"; then
    su - postgres -c "psql -c \"CREATE ROLE $MSFUSER LOGIN PASSWORD '$MSFPASS';\""
fi

if ! su - postgres -c "psql -lqtA" | grep -q "^msf|"; then
    su - postgres -c "psql -c \"CREATE DATABASE msf OWNER $MSFUSER;\""
fi

echo '----------------------------------------'
echo '[+]           Loading shell             '
echo '----------------------------------------'

cat <<EOF > /usr/share/metasploit-framework/config/database.yml
production:
  adapter: postgresql
  database: msf
  username: $MSFUSER
  password: $MSFPASS
  host: 127.0.0.1
  port: 5432
  pool: 75
  timeout: 5
EOF

export MSF_DATABASE_CONFIG=/usr/share/metasploit-framework/config/database.yml
mkdir -p /root/.msf4/
ln -sf /usr/share/metasploit-framework/config/database.yml /root/.msf4/database.yml

/usr/share/metasploit-framework/msfconsole -x "setg Proxies SOCKS5:127.0.0.1:9050"