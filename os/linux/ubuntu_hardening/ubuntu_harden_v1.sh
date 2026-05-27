#!/bin/bash
# ubuntu hardening

set -euo pipefail

if [ "$(id -u)" -ne 0 ] ; then
  echo "❌ Run me as root"
  exit 1
fi

# variables
APT=$(which apt)
VERBOSE='N'
LXC='0'
NTPSERVERPOOL='0.ubuntu.pool.ntp.org 1.ubuntu.pool.ntp.org 2.ubuntu.pool.ntp.org 3.ubuntu.pool.ntp.org pool.ntp.org'
TIMESYNCD='/etc/systemd/timesyncd.conf'
SYSTEMCONF='/etc/systemd/system.conf'
USERCONF='/etc/systemd/user.conf'
TIMEDATECTL=''

function apport {
  echo "[$SCRIPT_COUNT] Disable apport, ubuntu-report and popularity-contest"

  if command -v gsettings 2>/dev/null 1>&2; then
    gsettings set com.ubuntu.update-notifier show-apport-crashes false
  fi

  if command -v ubuntu-report 2>/dev/null 1>&2; then
    ubuntu-report -f send no
  fi

  if [ -f /etc/default/apport ]; then
    sed -i 's/enabled=.*/enabled=0/' /etc/default/apport
    systemctl stop apport.service
    systemctl mask apport.service
  fi

  if dpkg -l | grep -E '^ii.*popularity-contest' 2>/dev/null 1>&2; then
    $APT purge popularity-contest
  fi

  systemctl daemon-reload

  if [[ $VERBOSE == "Y" ]]; then
    systemctl status apport.service --no-pager
    echo
  fi

  ((SCRIPT_COUNT++))
}

function aptget {
  echo "[$SCRIPT_COUNT] Updating the package index files from their sources"

  $APT update

  ((SCRIPT_COUNT++))

  echo "[$SCRIPT_COUNT] Upgrading installed packages"

  $APT -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" --with-new-pkgs upgrade

  ((SCRIPT_COUNT++))
}

function aptget_clean {
  echo "[$SCRIPT_COUNT] Removing unused packages"

  apt-get -qq clean
  apt-get -qq autoremove

  for deb_clean in $(dpkg -l | grep '^rc' | awk '{print $2}'); do
    $APT purge "$deb_clean"
  done

  ((SCRIPT_COUNT++))
}

function aptget_configure {
  echo "[$SCRIPT_COUNT] Configure APT"

  if ! grep '^Acquire::http::AllowRedirect' /etc/apt/apt.conf.d/* ; then
    echo 'Acquire::http::AllowRedirect "false";' >> /etc/apt/apt.conf.d/98-hardening-ubuntu
  else
    sed -i 's/.*Acquire::http::AllowRedirect.*/Acquire::http::AllowRedirect "false";/g' "$(grep -l 'Acquire::http::AllowRedirect' /etc/apt/apt.conf.d/*)"
  fi

  if ! grep '^APT::Get::AllowUnauthenticated' /etc/apt/apt.conf.d/* ; then
    echo 'APT::Get::AllowUnauthenticated "false";' >> /etc/apt/apt.conf.d/98-hardening-ubuntu
  else
    sed -i 's/.*APT::Get::AllowUnauthenticated.*/APT::Get::AllowUnauthenticated "false";/g' "$(grep -l 'APT::Get::AllowUnauthenticated' /etc/apt/apt.conf.d/*)"
  fi

  if ! grep '^APT::Periodic::AutocleanInterval' /etc/apt/apt.conf.d/*; then
    echo 'APT::Periodic::AutocleanInterval "7";' >> /etc/apt/apt.conf.d/10periodic
  else
    sed -i 's/.*APT::Periodic::AutocleanInterval.*/APT::Periodic::AutocleanInterval "7";/g' "$(grep -l 'APT::Periodic::AutocleanInterval' /etc/apt/apt.conf.d/*)"
  fi

  if ! grep '^APT::Install-Recommends' /etc/apt/apt.conf.d/*; then
    echo 'APT::Install-Recommends "false";' >> /etc/apt/apt.conf.d/98-hardening-ubuntu
  else
    sed -i 's/.*APT::Install-Recommends.*/APT::Install-Recommends "false";/g' "$(grep -l 'APT::Install-Recommends' /etc/apt/apt.conf.d/*)"
  fi

  if ! grep '^APT::Get::AutomaticRemove' /etc/apt/apt.conf.d/*; then
    echo 'APT::Get::AutomaticRemove "true";' >> /etc/apt/apt.conf.d/98-hardening-ubuntu
  else
    sed -i 's/.*APT::Get::AutomaticRemove.*/APT::Get::AutomaticRemove "true";/g' "$(grep -l 'APT::Get::AutomaticRemove' /etc/apt/apt.conf.d/*)"
  fi

  if ! grep '^APT::Install-Suggests' /etc/apt/apt.conf.d/*; then
    echo 'APT::Install-Suggests "false";' >> /etc/apt/apt.conf.d/98-hardening-ubuntu
  else
    sed -i 's/.*APT::Install-Suggests.*/APT::Install-Suggests "false";/g' "$(grep -l 'APT::Install-Suggests' /etc/apt/apt.conf.d/*)"
  fi

  if ! grep '^Unattended-Upgrade::Remove-Unused-Dependencies' /etc/apt/apt.conf.d/*; then
    echo 'Unattended-Upgrade::Remove-Unused-Dependencies "true";' >> /etc/apt/apt.conf.d/50unattended-upgrades
  else
    sed -i 's/.*Unattended-Upgrade::Remove-Unused-Dependencies.*/Unattended-Upgrade::Remove-Unused-Dependencies "true";/g' "$(grep -l 'Unattended-Upgrade::Remove-Unused-Dependencies' /etc/apt/apt.conf.d/*)"
  fi

  if ! grep '^Unattended-Upgrade::Remove-Unused-Kernel-Packages' /etc/apt/apt.conf.d/*; then
    echo 'Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";' >> /etc/apt/apt.conf.d/50unattended-upgrades
  else
    sed -i 's/.*Unattended-Upgrade::Remove-Unused-Kernel-Packages.*/Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";/g' "$(grep -l 'Unattended-Upgrade::Remove-Unused-Kernel-Packages' /etc/apt/apt.conf.d/*)"
  fi

  if ! grep '^Acquire::AllowDowngradeToInsecureRepositories' /etc/apt/apt.conf.d/*; then
    echo 'Acquire::AllowDowngradeToInsecureRepositories "false";' >> /etc/apt/apt.conf.d/98-hardening-ubuntu
  else
    sed -i 's/.*Acquire::AllowDowngradeToInsecureRepositories.*/Acquire::AllowDowngradeToInsecureRepositories "false";/g' "$(grep -l 'Acquire::AllowDowngradeToInsecureRepositories' /etc/apt/apt.conf.d/*)"
  fi

  if ! grep '^Acquire::AllowInsecureRepositories' /etc/apt/apt.conf.d/*; then
    echo 'Acquire::AllowInsecureRepositories "false";' >> /etc/apt/apt.conf.d/98-hardening-ubuntu
  else
    sed -i 's/.*Acquire::AllowInsecureRepositories.*/Acquire::AllowInsecureRepositories "false";/g' "$(grep -l 'Acquire::AllowInsecureRepositories' /etc/apt/apt.conf.d/*)"
  fi

  if ! grep '^APT::Sandbox::Seccomp' /etc/apt/apt.conf.d/*; then
    echo 'APT::Sandbox::Seccomp "1";' >> /etc/apt/apt.conf.d/98-hardening-ubuntu
  else
    sed -i 's/.*APT::Sandbox::Seccomp.*/APT::Sandbox::Seccomp "1";/g' "$(grep -l 'APT::Sandbox::Seccomp' /etc/apt/apt.conf.d/*)"
  fi

  ((SCRIPT_COUNT++))
}

function aptget_noexec {
  if [[ $LXC == "1" ]]; then
    return
  fi

  echo "[$SCRIPT_COUNT] Configure DPkg noexec"

  if ! grep 'mount.* /tmp' /etc/apt/apt.conf.d/* ; then
    echo 'DPkg::Pre-Invoke {"mount -o remount,exec,nodev,nosuid /tmp";};' >> /etc/apt/apt.conf.d/99noexec-tmp
    echo 'DPkg::Post-Invoke {"mount -o remount,mode=1777,strictatime,noexec,nodev,nosuid /tmp";};' >> /etc/apt/apt.conf.d/99noexec-tmp
  fi

  ((SCRIPT_COUNT++))
}

function remove_users {
  echo "[$SCRIPT_COUNT] Remove users"

  for user in games gnats irc list news sync uucp; do
    if id "$user" &>/dev/null; then
      pkill -u "$user"
      if userdel -r "$user" &>/dev/null; then
        echo "User $user deleted successfully."
      else
        echo "Failed to delete user $user."
      fi
    else
      echo "User $user does not exist."
    fi
  done

  ((SCRIPT_COUNT++))
}

function timesyncd {
  echo "[$SCRIPT_COUNT] Systemd/timesyncd.conf"

  local LATENCY
  local SERVERS
  local SERVERARRAY
  local FALLBACKARRAY
  local TMPCONF

  APPLY="YES"
  CONF="$TIMESYNCD"
  FALLBACKARRAY=()
  FALLBACKSERV=0
  LATENCY="50"
  NUMSERV=0
  SERVERARRAY=()
  SERVERS="4"
  TMPCONF=$(mktemp --tmpdir ntpconf.XXXXX)

  if [[ -z "$NTPSERVERPOOL" ]]; then
    local NTPSERVERPOOL
    NTPSERVERPOOL="0.ubuntu.pool.ntp.org 1.ubuntu.pool.ntp.org 2.ubuntu.pool.ntp.org 3.ubuntu.pool.ntp.org pool.ntp.org"
  fi

  echo "[Time]" > "$TMPCONF"

  PONG="${PINGBIN} -c2"

  # shellcheck disable=2086
  while read -r s; do
    if [[ $NUMSERV -ge $SERVERS ]]; then
      break
    fi

    local PINGSERV
    PINGSERV=$($PONG "$s" | grep 'rtt min/avg/max/mdev' | awk -F "/" '{printf "%.0f\n",$6}')
    if [[ $PINGSERV -gt "1" && $PINGSERV -lt "$LATENCY" ]]; then
      OKSERV=$(nslookup "$s"|grep "name = " | awk '{print $4}'|sed 's/.$//')
      # shellcheck disable=2143
      # shellcheck disable=2243
      # shellcheck disable=2244
      if [[ $OKSERV && $NUMSERV -lt $SERVERS && ! (( $(grep "$OKSERV" "$TMPCONF") )) ]]; then
        echo "$OKSERV has latency < $LATENCY"
        SERVERARRAY+=("$OKSERV")
        ((NUMSERV++))
      fi
    fi
  done <<< "$(${DIGBIN} +noall +answer +nocomments $NTPSERVERPOOL | awk '{print $5}')"

  for l in $NTPSERVERPOOL; do
    if [[ $FALLBACKSERV -le "2" ]]; then
      FALLBACKARRAY+=("$l")
      ((FALLBACKSERV++))
    else
      break
    fi
  done

  if [[ ${#SERVERARRAY[@]} -le "2" ]]; then
    for s in $(echo "$NTPSERVERPOOL" | awk '{print $(NF-1),$NF}'); do
      SERVERARRAY+=("$s")
    done
  fi

  {
    echo "NTP=${SERVERARRAY[*]}"
    echo "FallbackNTP=${FALLBACKARRAY[*]}"
    echo "RootDistanceMaxSec=1"
  } >> "$TMPCONF"

  if [[ $APPLY = "YES" ]]; then
    cat "$TMPCONF" > "$CONF"
    systemctl restart systemd-timesyncd
    rm "$TMPCONF"
  else
    echo "Configuration saved to $TMPCONF."
  fi

  if [[ -n "$TIMEDATECTL" ]]; then
    echo "Setting time zone to $TIMEDATECTL"
    timedatectl set-timezone "$TIMEDATECTL"
  fi

  if [[ $VERBOSE == "Y" ]]; then
    systemctl status systemd-timesyncd --no-pager
    echo
    timedatectl
    echo
  fi

  ((SCRIPT_COUNT++))
}

function systemdconf {
  echo "[$SCRIPT_COUNT] Systemd/system.conf and Systemd/user.conf"

  sed -i 's/^#DumpCore=.*/DumpCore=no/' "$SYSTEMCONF"
  sed -i 's/^#CrashShell=.*/CrashShell=no/' "$SYSTEMCONF"
  sed -i 's/^#DefaultLimitCORE=.*/DefaultLimitCORE=0/' "$SYSTEMCONF"
  sed -i 's/^#DefaultLimitNOFILE=.*/DefaultLimitNOFILE=1024/' "$SYSTEMCONF"
  sed -i 's/^#DefaultLimitNPROC=.*/DefaultLimitNPROC=1024/' "$SYSTEMCONF"

  sed -i 's/^#DefaultLimitCORE=.*/DefaultLimitCORE=0/' "$USERCONF"
  sed -i 's/^#DefaultLimitNOFILE=.*/DefaultLimitNOFILE=1024/' "$USERCONF"
  sed -i 's/^#DefaultLimitNPROC=.*/DefaultLimitNPROC=1024/' "$USERCONF"

  systemctl daemon-reload

  ((SCRIPT_COUNT++))
}

# function call, comment out ones you do not want to run below:
if command -v apt &> /dev/null; then
  echo "this is ubuntu/debian"
    apport
    aptget
    aptget_clean
    aptget_configure
    remove_users
    timesyncd
    systemdconf
else
  echo "this ain't ubuntu, get your type of penguin right!"
fi