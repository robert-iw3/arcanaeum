#!/bin/bash
# user hardening
# RW

set -euo pipefail

if [ "$(id -u)" -ne 0 ] ; then
  echo "❌ Run me as root"
  exit 1
fi

# variables
SECURITYACCESS='/etc/security/access.conf'
VERBOSE='N'
COMMONPASSWD='/etc/pam.d/common-password'
COMMONACCOUNT='/etc/pam.d/common-account'
COMMONAUTH='/etc/pam.d/common-auth'
PAMLOGIN='/etc/pam.d/login'
LOGINDCONF='/etc/systemd/logind.conf'
LOGINDEFS='/etc/login.defs'
ADDUSER='/etc/adduser.conf'
USERADD='/etc/default/useradd'

function rootaccess {
  echo "[$SCRIPT_COUNT] root access"

  if ! grep -E '^+\s:\sroot\s:\s127.0.0.1$|^:root:127.0.0.1' "$SECURITYACCESS"; then
    sed -i 's/^#.*root.*:.*127.0.0.1$/+:root:127.0.0.1/' "$SECURITYACCESS"
  fi

  echo "console" > /etc/securetty

  ((SCRIPT_COUNT++))

  echo "[$SCRIPT_COUNT] Mask debug-shell"

  systemctl mask debug-shell.service
  systemctl stop debug-shell.service
  systemctl daemon-reload

  if [[ $VERBOSE == "Y" ]]; then
    systemctl status debug-shell.service --no-pager
    echo
  fi

  ((SCRIPT_COUNT++))
}

function sudo {
  echo "[$SCRIPT_COUNT] sudo configuration"

  if ! grep -qER '^Defaults.*use_pty$' /etc/sudo*; then
    echo "Defaults use_pty" > /etc/sudoers.d/011_use_pty
  fi

  if ! grep -qER '^Defaults.*logfile' /etc/sudo*; then
    echo 'Defaults logfile="/var/log/sudo.log"' > /etc/sudoers.d/012_logfile
  fi

  if ! grep -qER '^Defaults.*pwfeedback' /etc/sudo*; then
    echo 'Defaults !pwfeedback' > /etc/sudoers.d/013_pwfeedback
  fi

  if ! grep -qER '^Defaults.*visiblepw' /etc/sudo*; then
    echo 'Defaults !visiblepw' > /etc/sudoers.d/014_visiblepw
  fi

  if ! grep -qER '^Defaults.*passwd_timeout' /etc/sudo*; then
    echo 'Defaults passwd_timeout=1' > /etc/sudoers.d/015_passwdtimeout
  fi

  if ! grep -qER '^Defaults.*timestamp_timeout' /etc/sudo*; then
    echo 'Defaults timestamp_timeout=5' > /etc/sudoers.d/016_timestamptimeout
  fi

  find /etc/sudoers.d/ -type f -name '[0-9]*' -exec chmod 0440 {} \;

  if ! grep -qER '^auth required pam_wheel.so' /etc/pam.d/su; then
    echo "auth required pam_wheel.so use_uid group=sudo" >> /etc/pam.d/su
  fi

  if [[ $VERBOSE == "Y" ]]; then
    sudo -ll
    echo
  fi

  ((SCRIPT_COUNT++))
}

function password {
  echo "[$SCRIPT_COUNT] $COMMONPASSWD, $COMMONAUTH and $PAMLOGIN"

  if ! grep pam_pwhistory.so "$COMMONPASSWD"; then
    sed -i '/the "Primary" block/apassword\trequired\t\t\tpam_pwhistory.so\tremember=5' "$COMMONPASSWD"
  fi

  cp ./config/pwquality.conf /etc/security/pwquality.conf
  chmod 0644 /etc/security/pwquality.conf

  if grep 'use_authtok try_first_pass sha512' "$COMMONPASSWD"; then
    sed -i 's/try_first_pass sha512.*/try_first_pass sha512 rounds=65536/' "$COMMONPASSWD"
  fi

  sed -i -E 's/(nullok|nullok_secure)//g' "$COMMONAUTH"

  if ! grep retry= "$COMMONPASSWD"; then
    echo 'password requisite pam_pwquality.so retry=3' >> "$COMMONPASSWD"
  fi

  if [ -f "$FAILLOCKCONF" ]; then
    if ! grep faillock "$COMMONAUTH"; then
      sed -i 's/^# audit$/audit/' "$FAILLOCKCONF"
      sed -i 's/^# local_users_only$/local_users_only/' "$FAILLOCKCONF"
      sed -i 's/^# deny.*/deny = 5/' "$FAILLOCKCONF"
      sed -i 's/^# fail_interval.*/fail_interval = 900/' "$FAILLOCKCONF"
      sed -i '/pam_tally.*/d' "$COMMONACCOUNT"
      sed -i 's/auth.*pam_unix.so/auth required pam_faillock.so preauth\nauth [success=1 default=ignore] pam_unix.so\nauth [default=die] pam_faillock.so authfail\nauth sufficient pam_faillock.so authsucc\n/' "$COMMONAUTH"
    fi
    if ! grep faillock "$COMMONACCOUNT"; then
      echo 'account required pam_faillock.so' >> "$COMMONACCOUNT"
    fi
  else
    if ! grep tally2 "$COMMONAUTH"; then
      sed -i '/^$/a auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900' "$COMMONAUTH"
      sed -i '/pam_tally/d' "$COMMONACCOUNT"
    fi
    if ! grep tally2 "$COMMONACCOUNT"; then
      sed -i '/^$/a account required pam_tally2.so' "$COMMONACCOUNT"
    fi
  fi

  sed -i 's/pam_lastlog.so.*/pam_lastlog.so showfailed/' "$PAMLOGIN"
  sed -i 's/delay=.*/delay=4000000/' "$PAMLOGIN"

  cp "./misc/passwords.list" "/usr/share/dict/passwords"
  grep -v '^$' /usr/share/dict/passwords | strings > /usr/share/dict/passwords_text
  update-cracklib

  ((SCRIPT_COUNT++))
}

function logindconf {
  echo "[$SCRIPT_COUNT] Systemd/logind.conf"

  sed -i 's/^#KillUserProcesses=no/KillUserProcesses=1/' "$LOGINDCONF"
  sed -i 's/^#KillExcludeUsers=root/KillExcludeUsers=root/' "$LOGINDCONF"
  sed -i 's/^#IdleAction=ignore/IdleAction=lock/' "$LOGINDCONF"
  sed -i 's/^#IdleActionSec=30min/IdleActionSec=15min/' "$LOGINDCONF"
  sed -i 's/^#RemoveIPC=yes/RemoveIPC=yes/' "$LOGINDCONF"

  systemctl daemon-reload

  ((SCRIPT_COUNT++))
}

function logindefs {
  echo "[$SCRIPT_COUNT] /etc/login.defs"

  sed -i 's/^.*LOG_OK_LOGINS.*/LOG_OK_LOGINS yes/' "$LOGINDEFS"
  sed -i 's/^UMASK.*/UMASK 077/' "$LOGINDEFS"
  sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' "$LOGINDEFS"
  sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 60/' "$LOGINDEFS"
  sed -i 's/DEFAULT_HOME.*/DEFAULT_HOME no/' "$LOGINDEFS"
  sed -i 's/ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' "$LOGINDEFS"
  sed -i 's/USERGROUPS_ENAB.*/USERGROUPS_ENAB no/' "$LOGINDEFS"
  sed -i 's/^#.*SHA_CRYPT_MIN_ROUNDS .*/SHA_CRYPT_MIN_ROUNDS 10000/' "$LOGINDEFS"
  sed -i 's/^#.*SHA_CRYPT_MAX_ROUNDS .*/SHA_CRYPT_MAX_ROUNDS 65536/' "$LOGINDEFS"

  ((SCRIPT_COUNT++))
}

function lockroot {
  echo "[$SCRIPT_COUNT] Lock root account"

  usermod -L root

  if [[ $VERBOSE == "Y" ]]; then
    passwd -S root
    echo
  fi

  ((SCRIPT_COUNT++))
}

function adduser {
  echo "[$SCRIPT_COUNT] $ADDUSER and $USERADD"


  sed -i -e 's/^DIR_MODE=.*/DIR_MODE=0750/' -e 's/^#DIR_MODE=.*/DIR_MODE=0750/' "$ADDUSER"
  sed -i -e 's/^DSHELL=.*/DSHELL=\/bin\/false/' -e 's/^#DSHELL=.*/DSHELL=\/bin\/false/' "$ADDUSER"
  sed -i -e 's/^USERGROUPS=.*/USERGROUPS=yes/' -e 's/^#USERGROUPS=.*/USERGROUPS=yes/' "$ADDUSER"

  sed -i 's/^SHELL=.*/SHELL=\/bin\/false/' "$USERADD"
  sed -i 's/^# INACTIVE=.*/INACTIVE=30/' "$USERADD"

  awk -F ':' '{if($3 >= 1000 && $3 <= 65000) print $6}' /etc/passwd | while read -r userhome; do
    chmod 0750 "$userhome"
  done

  ((SCRIPT_COUNT++))
}

# function last call
rootaccess
sudo
password
logindconf
logindefs
lockroot
adduser