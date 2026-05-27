#!/bin/sh
set -e

# Check for CAP_SYS_ADMIN
if ! capsh --print | grep -q "cap_sys_admin"; then
  echo "Error: This container requires CAP_SYS_ADMIN to access /proc"
  exit 1
fi

# Execute the command as root (su-exec escalates privileges)
exec su-exec 0:0 "$@"