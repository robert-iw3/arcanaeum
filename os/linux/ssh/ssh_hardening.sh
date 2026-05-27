#!/bin/bash
# ssh hardening
# RW

set -euo pipefail

if [ "$(id -u)" -ne 0 ] ; then
  echo "❌ Run me as root"
  exit 1
fi

# variables
SSH=$(which ssh)
SSHFILE='/etc/ssh/ssh_config'
SSHDFILE='/etc/ssh/sshd_config'
SSH_GRPS='sudo'
SSH_PORT='22'
VERBOSE='N'

function sshdconfig {
  echo "[$SCRIPT_COUNT] $SSHDFILE"

  awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.tmp
  mv /etc/ssh/moduli.tmp /etc/ssh/moduli

  if grep -q '^Include' /etc/ssh/sshd_config; then
    local INCLUDEDIR
    # shellcheck disable=SC2046
    INCLUDEDIR="$(dirname $(grep '^Include' /etc/ssh/sshd_config | awk '{print $NF}'))"

    if [ ! -d "$INCLUDEDIR" ]; then
      mkdir -p "$INCLUDEDIR"
    fi

    SSHDCONF="$INCLUDEDIR/hardening.conf"

    cp "$SSHDFILE" "$SSHDCONF"

    sed -i '/.*Subsystem.*/d' "$SSHDFILE"
    sed -i '/Include.*/d' "$SSHDCONF"
  else
    SSHDCONF="$SSHDFILE"
  fi


  if [[ $VERBOSE == "Y" ]]; then
    echo "Using $SSHDCONF"
  fi

  sed -i '/HostKey.*ssh_host_dsa_key.*/d' "$SSHDCONF"
  sed -i '/KeyRegenerationInterval.*/d' "$SSHDCONF"
  sed -i '/ServerKeyBits.*/d' "$SSHDCONF"
  sed -i '/UseLogin.*/d' "$SSHDCONF"

  sed -i 's/.*X11Forwarding.*/X11Forwarding no/' "$SSHDCONF"
  sed -i 's/.*LoginGraceTime.*/LoginGraceTime 20/' "$SSHDCONF"
  sed -i 's/.*PermitRootLogin.*/PermitRootLogin no/' "$SSHDCONF"
  sed -i 's/.*UsePrivilegeSeparation.*/UsePrivilegeSeparation sandbox/' "$SSHDCONF"
  sed -i 's/.*LogLevel.*/LogLevel VERBOSE/' "$SSHDCONF"
  sed -i 's/.*Banner.*/Banner \/etc\/issue.net/' "$SSHDCONF"
  sed -i 's/.*Subsystem.*sftp.*/Subsystem sftp internal-sftp/' "$SSHDCONF"
  sed -i 's/^#.*Compression.*/Compression no/' "$SSHDCONF"
  sed -i "s/.*Port.*/Port $SSH_PORT/" "$SSHDCONF"

  echo "" >> "$SSHDCONF"

  if ! grep -q "^LogLevel" "$SSHDCONF" 2> /dev/null; then
    echo "LogLevel VERBOSE" >> "$SSHDCONF"
  fi

  if ! grep -q "^PrintLastLog" "$SSHDCONF" 2> /dev/null; then
    echo "PrintLastLog yes" >> "$SSHDCONF"
  fi

  if ! grep -q "^IgnoreUserKnownHosts" "$SSHDCONF" 2> /dev/null; then
    echo "IgnoreUserKnownHosts yes" >> "$SSHDCONF"
  fi

  if ! grep -q "^PermitEmptyPasswords" "$SSHDCONF" 2> /dev/null; then
    echo "PermitEmptyPasswords no" >> "$SSHDCONF"
  fi

  if ! grep -q "^AllowGroups" "$SSHDCONF" 2> /dev/null; then
    echo "AllowGroups $SSH_GRPS" >> "$SSHDCONF"
  fi

  if ! grep -q "^MaxAuthTries" "$SSHDCONF" 2> /dev/null; then
    echo "MaxAuthTries 3" >> "$SSHDCONF"
  else
    sed -i 's/MaxAuthTries.*/MaxAuthTries 3/' "$SSHDCONF"
  fi

  if ! grep -q "^ClientAliveInterval" "$SSHDCONF" 2> /dev/null; then
    echo "ClientAliveInterval 200" >> "$SSHDCONF"
  fi

  if ! grep -q "^ClientAliveCountMax" "$SSHDCONF" 2> /dev/null; then
    echo "ClientAliveCountMax 3" >> "$SSHDCONF"
  fi

  if ! grep -q "^PermitUserEnvironment" "$SSHDCONF" 2> /dev/null; then
    echo "PermitUserEnvironment no" >> "$SSHDCONF"
  fi

  if ! grep -q "^KexAlgorithms" "$SSHDCONF" 2> /dev/null; then
    echo 'KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256' >> "$SSHDCONF"
  fi

  if ! grep -q "^Ciphers" "$SSHDCONF" 2> /dev/null; then
    echo 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr' >> "$SSHDCONF"
  fi

  if ! grep -q "^Macs" "$SSHDCONF" 2> /dev/null; then
    echo 'Macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256' >> "$SSHDCONF"
  fi

  if ! grep -q "^MaxSessions" "$SSHDCONF" 2> /dev/null; then
    echo "MaxSessions 3" >> "$SSHDCONF"
  else
    sed -i 's/MaxSessions.*/MaxSessions 3/' "$SSHDCONF"
  fi

  if ! grep -q "^UseDNS" "$SSHDCONF" 2> /dev/null; then
    echo "UseDNS no" >> "$SSHDCONF"
  else
    sed -i 's/UseDNS.*/UseDNS no/' "$SSHDCONF"
  fi

  if ! grep -q "^StrictModes" "$SSHDCONF" 2> /dev/null; then
    echo "StrictModes yes" >> "$SSHDCONF"
  else
    sed -i 's/StrictModes.*/StrictModes yes/' "$SSHDCONF"
  fi

  if ! grep -q "^MaxStartups" "$SSHDCONF" 2> /dev/null; then
    echo "MaxStartups 10:30:60" >> "$SSHDCONF"
  else
    sed -i 's/MaxStartups.*/MaxStartups 10:30:60/' "$SSHDCONF"
  fi

  if ! grep -q "^HostbasedAuthentication" "$SSHDCONF" 2> /dev/null; then
    echo "HostbasedAuthentication no" >> "$SSHDCONF"
  else
    sed -i 's/HostbasedAuthentication.*/HostbasedAuthentication no/' "$SSHDCONF"
  fi

  if ! grep -q "^KerberosAuthentication" "$SSHDCONF" 2> /dev/null; then
    echo "KerberosAuthentication no" >> "$SSHDCONF"
  else
    sed -i 's/KerberosAuthentication.*/KerberosAuthentication no/' "$SSHDCONF"
  fi

  if ! grep -q "^GSSAPIAuthentication" "$SSHDCONF" 2> /dev/null; then
    echo "GSSAPIAuthentication no" >> "$SSHDCONF"
  else
    sed -i 's/GSSAPIAuthentication.*/GSSAPIAuthentication no/' "$SSHDCONF"
  fi

  if ! grep -q "^RekeyLimit" "$SSHDCONF" 2> /dev/null; then
    echo "RekeyLimit 512M 1h" >> "$SSHDCONF"
  else
    sed -i 's/RekeyLimit.*/RekeyLimit 512M 1h/' "$SSHDCONF"
  fi

  if ! grep -q "^AllowTcpForwarding" "$SSHDCONF" 2> /dev/null; then
    echo "AllowTcpForwarding no" >> "$SSHDCONF"
  else
    sed -i 's/AllowTcpForwarding.*/AllowTcpForwarding no/' "$SSHDCONF"
  fi

  if ! grep -q "^AllowAgentForwarding" "$SSHDCONF" 2> /dev/null; then
    echo "AllowAgentForwarding no" >> "$SSHDCONF"
  else
    sed -i 's/AllowAgentForwarding.*/AllowAgentForwarding no/' "$SSHDCONF"
  fi

  if ! grep -q "^TCPKeepAlive" "$SSHDCONF" 2> /dev/null; then
    echo "TCPKeepAlive no" >> "$SSHDCONF"
  else
    sed -i 's/TCPKeepAlive.*/TCPKeepAlive no/' "$SSHDCONF"
  fi

  cp "$SSHDCONF" "/etc/ssh/sshd_config.$(date +%y%m%d)"
  grep -vE '#|^$' "/etc/ssh/sshd_config.$(date +%y%m%d)" | sort | uniq > "$SSHDCONF"
  rm "/etc/ssh/sshd_config.$(date +%y%m%d)"

  chown root:root "$SSHDCONF"
  chmod 0600 "$SSHDCONF"

  systemctl restart ssh.service

  if [[ $VERBOSE == "Y" ]]; then
    systemctl status ssh.service --no-pager
    echo
  fi

  ((SCRIPT_COUNT++))
}

function sshconfig {
  echo "[$SCRIPT_COUNT] $SSHFILE"

  cp "$SSHFILE" "/etc/ssh/ssh_config.$(date +%y%m%d)"

  if ! grep -q "^\s.*HashKnownHosts" "$SSHFILE" 2> /dev/null; then
    sed -i '/HashKnownHosts/d' "$SSHFILE"
    echo "    HashKnownHosts yes" >> "$SSHFILE"
  fi

  sed -i 's/#.*Ciphers .*/    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr/g' "$SSHFILE"
  sed -i 's/#.*MACs .*/    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256/' "$SSHFILE"
}

function issue {
  echo "[$SCRIPT_COUNT] /etc/issue"

  local TEXT

  for f in /etc/issue /etc/issue.net /etc/motd; do
    TEXT="\\n\n
Call trans opt: received. 2-19-98 13:24:18 REC:Loc

     Trace program: running

           wake up, Neo...
        the matrix has you
      follow the white rabbit.

          knock, knock, Neo.

By accessing this system, you consent to the following conditions:

- This system is for authorized use only.
- Any or all uses of this system and all files on this system may be monitored.
- Communications using, or data stored on, this system are not private.
"
    echo -e "$TEXT" > $f
  done

  chmod a-x /etc/update-motd.d/*

  ((SCRIPT_COUNT++))
}

if [ -n "$SSH" ] ; then
  issue
  sshconfig
  sshdconfig
else
  echo "ssh not installed, install and rerun script"
fi
