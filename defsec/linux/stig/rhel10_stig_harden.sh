#!/bin/bash
########################################################################
#
# DISA STIG Hardening configurations for RedHat Enterprise Linux 10
#
# By: RW
# Date: July 2025
#
########################################################################

set -euo pipefail
shopt -s extglob

# Global variables
AUDIT_LOG="/var/log/hardening.log"
BACKUP_DIR="/tmp/hardening_backups_$(date +%s)"
DRY_RUN=false
CONFIRM_CHANGES=false  # Set to true for interactive mode
TARGET_OS="Red Hat Enterprise Linux [0-9]+\.0|CentOS Stream [0-9]+\.0|Rocky Linux [0-9]+\.0|AlmaLinux [0-9]+\.0|Fedora [0-9]+\.0|Oracle Linux [0-9]+\.0"

# Logging function
log() {
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$message" | tee -a "$AUDIT_LOG" >&2
}

# Validate integer variable
validate_integer() {
    local var_name=$1 value=$2
    if ! [[ "$value" =~ ^[0-9]+$ ]]; then
        log "Invalid value for $var_name: $value must be a positive integer"
        exit 1
    fi
}

# Backup file function with verification
backup_file() {
    local file=$1
    mkdir -p "$BACKUP_DIR"
    local backup="$BACKUP_DIR/$(basename "$file").$(date +%s)"
    if [[ -f "$file" ]]; then
        cp -p "$file" "$backup" || { log "Failed to backup $file"; exit 1; }
        log "Backed up $file to $backup"
    fi
    echo "$backup"
}

# Restore backup on failure
restore_backup() {
    local file=$1
    local backup=$2
    if [[ -f "$backup" ]]; then
        mv "$backup" "$file" || log "Failed to restore $file from $backup"
        log "Restored $file from $backup"
    fi
}

# Check file permissions
check_permissions() {
    local file=$1
    local expected_perm=$2
    if [[ -f "$file" ]]; then
        local current_perm
        current_perm=$(stat -c "%a" "$file")
        if [[ "$current_perm" != "$expected_perm" ]]; then
            chmod "$expected_perm" "$file" || { log "Failed to set permissions on $file"; exit 1; }
            log "Set permissions on $file to $expected_perm"
        fi
    fi
}

# User confirmation
confirm() {
    local message=$1
    if [[ "$CONFIRM_CHANGES" == "true" ]]; then
        read -p "$message (y/N): " confirm
        [[ "$confirm" =~ ^[Yy]$ ]] || return 1
    fi
    return 0
}

# Generic replace or append function with locking and dry-run
replace_or_append() {
    local config_file=$1
    local key=$2
    local value=$3
    local cce=$4
    local format=${5:-'%s = %s'}
    local case_insensitive_mode=yes
    local sed_case_insensitive_option='' grep_case_insensitive_option=''

    [[ "$case_insensitive_mode" == "yes" ]] && { sed_case_insensitive_option="i"; grep_case_insensitive_option="-i"; }
    [[ -z "$format" ]] && format="%s = %s"
    [[ $# -ge 3 ]] || { log "Usage: replace_or_append <config_file> <key> <value> [<cce>] [format]"; exit 1; }

    # Ensure file exists and has correct permissions
    [[ -f "$config_file" ]] || { touch "$config_file" || { log "Failed to create $config_file"; exit 1; }; }
    check_permissions "$config_file" "644"

    # File locking
    exec 200>"$config_file.lock"
    flock -n 200 || { log "Cannot lock $config_file, another process is modifying it"; exit 1; }

    # Backup file
    local backup
    backup=$(backup_file "$config_file")

    # Dry-run check
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry-run: Would configure $key=$value in $config_file"
        flock -u 200
        return 0
    fi

    # User confirmation for critical files
    if [[ "$config_file" == *"/etc/sudoers"* || "$config_file" == *"/etc/pam.d/"* ]]; then
        confirm "Apply changes to $config_file?" || { flock -u 200; restore_backup "$config_file" "$backup"; return 1; }
    fi

    # Strip special characters from key
    local stripped_key
    stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

    # Format output
    local formatted_output
    printf -v formatted_output "$format" "$stripped_key" "$value"

    # Replace or append
    if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
        sed -i "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file" || \
            { flock -u 200; restore_backup "$config_file" "$backup"; exit 1; }
    else
        printf '\n# Per %s: Set %s in %s\n' "${cce:-CCE}" "$formatted_output" "$config_file" >> "$config_file"
        printf '%s\n' "$formatted_output" >> "$config_file" || \
            { flock -u 200; restore_backup "$config_file" "$backup"; exit 1; }
    fi

    # Verify changes
    grep -q "$formatted_output" "$config_file" || \
        { flock -u 200; log "Failed to verify $key in $config_file"; restore_backup "$config_file" "$backup"; exit 1; }
    flock -u 200
    rm -f "$backup"
}

# Validate PAM file
validate_pam_file() {
    local pam_file=$1
    [[ -f "$pam_file" ]] || { log "PAM file $pam_file does not exist"; return 1; }
    pam-auth-update --package >/dev/null 2>&1 || { log "PAM file $pam_file validation failed"; return 1; }
    return 0
}

# Check package installation
check_package() {
    local package=$1
    rpm --quiet -q "$package" || { log "Package $package is not installed"; return 1; }
    return 0
}

# Check environment
check_environment() {
    if [[ ! -f /etc/os-release ]]; then
        log "Error: /etc/os-release not found"
        exit 1
    fi
    . /etc/os-release
    if [[ ! "$ID" =~ ^(rhel|centos|rocky)$ || "${VERSION_ID%%.*}" != "10" ]]; then
        if ! grep -q "$TARGET_OS" /etc/os-release; then
            log "This script is designed for RHEL 10 or compatible derivatives (CentOS Stream 10, Rocky Linux 10) only"
            exit 1
        fi
    fi
}

# Reload services where applicable
reload_service() {
    local service=$1
    if systemctl is-active --quiet "$service"; then
        systemctl reload "$service" || log "Failed to reload $service"
        log "Reloaded $service"
    fi
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true; log "Running in dry-run mode"; shift ;;
        --confirm) CONFIRM_CHANGES=true; log "Interactive confirmation enabled"; shift ;;
        *) log "Unknown option: $1"; exit 1 ;;
    esac
done

# Initialize
check_environment
mkdir -p "$BACKUP_DIR"
touch "$AUDIT_LOG"
check_permissions "$AUDIT_LOG" "644"

# Remediation functions (modularized)
remediate_account_disable_post_pw_expiration() {
    if check_package "shadow-utils"; then
        log "Remediating: xccdf_org.ssgproject.content_rule_account_disable_post_pw_expiration"
        replace_or_append '/etc/default/useradd' '^INACTIVE' '35' 'CCE-80954-1' '%s=%s'
    else
        log "Remediation not applicable: shadow-utils not installed"
    fi
}

remediate_accounts_logon_fail_delay() {
    if check_package "shadow-utils"; then
        log "Remediating: xccdf_org.ssgproject.content_rule_accounts_logon_fail_delay"
        validate_integer "var_accounts_fail_delay" "4"
        replace_or_append '/etc/login.defs' '^FAIL_DELAY' '4' 'CCE-84037-1' '%s %s'
    else
        log "Remediation not applicable: shadow-utils not installed"
    fi
}

remediate_accounts_max_concurrent_login_sessions() {
    if check_package "pam"; then
        log "Remediating: xccdf_org.ssgproject.content_rule_accounts_max_concurrent_login_sessions"
        validate_integer "var_accounts_max_concurrent_login_sessions" "10"
        local limits_conf="/etc/security/limits.conf"
        local limits_d="/etc/security/limits.d"

        check_permissions "$limits_conf" "644"
        backup=$(backup_file "$limits_conf")

        if [[ "$DRY_RUN" == "true" ]]; then
            log "Dry-run: Would set maxlogins to 10 in limits.conf"
            return 0
        fi

        if [[ -d "$limits_d" && -n "$(ls -A $limits_d/*.conf)" ]]; then
            for file in "$limits_d"/*.conf; do
                if grep -q '^[^#]*\<maxlogins\>' "$file"; then
                    sed -i --follow-symlinks "/^[^#]*\<maxlogins\>/ s/maxlogins.*/maxlogins 10/" "$file" || \
                        { restore_backup "$limits_conf" "$backup"; exit 1; }
                fi
            done
        elif grep -q '^[^#]*\<maxlogins\>' "$limits_conf"; then
            sed -i --follow-symlinks "/^[^#]*\<maxlogins\>/ s/maxlogins.*/maxlogins 10/" "$limits_conf" || \
                { restore_backup "$limits_conf" "$backup"; exit 1; }
        else
            echo "* hard maxlogins 10" >> "$limits_conf" || \
                { restore_backup "$limits_conf" "$backup"; exit 1; }
        fi
        rm -f "$backup"
    else
        log "Remediation not applicable: pam not installed"
    fi
}

remediate_accounts_maximum_age_login_defs() {
    if check_package "shadow-utils"; then
        log "Remediating: xccdf_org.ssgproject.content_rule_accounts_maximum_age_login_defs"
        validate_integer "var_accounts_maximum_age_login_defs" "60"
        replace_or_append '/etc/login.defs' '^PASS_MAX_DAYS' '60' 'CCE' '%s %s'
    else
        log "Remediation not applicable: shadow-utils not installed"
    fi
}

remediate_accounts_minimum_age_login_defs() {
    if check_package "shadow-utils"; then
        log "Remediating: xccdf_org.ssgproject.content_rule_accounts_minimum_age_login_defs"
        validate_integer "var_accounts_minimum_age_login_defs" "1"
        replace_or_append '/etc/login.defs' '^PASS_MIN_DAYS' '1' 'CCE' '%s %s'
    else
        log "Remediation not applicable: shadow-utils not installed"
    fi
}

remediate_accounts_password_minlen_login_defs() {
    if check_package "shadow-utils"; then
        log "Remediating: xccdf_org.ssgproject.content_rule_accounts_password_minlen_login_defs"
        validate_integer "var_accounts_password_minlen_login_defs" "15"
        replace_or_append '/etc/login.defs' '^PASS_MIN_LEN' '15' 'CCE' '%s %s'
    else
        log "Remediation not applicable: shadow-utils not installed"
    fi
}

remediate_password_complexity() {
    if check_package "pam"; then
        log "Remediating: Password complexity rules"
        local pwquality_conf="/etc/security/pwquality.conf"
        check_permissions "$pwquality_conf" "644"
        backup=$(backup_file "$pwquality_conf")
        for option in "dcredit -1 CCE-80653-9" "dictcheck 1 CCE-86233-4" "difok 8 CCE-80654-7" \
                      "lcredit -1 CCE-80655-4" "maxclassrepeat 4 CCE-81034-1" "maxrepeat 3 CCE-82066-2" \
                      "minclass 4 CCE-82046-4" "minlen 15 CCE-80656-2" "ocredit -1 CCE-80663-8" \
                      "ucredit -1 CCE-80665-3"; do
            local key=${option%% *}
            local value=${option#* }
            local cce=${value#* }
            value=${value%% *}
            replace_or_append "$pwquality_conf" "^$key" "$value" "$cce" '%s = %s'
        done
        rm -f "$backup"
        # Enforce for root
        log "Remediating: xccdf_org.ssgproject.content_rule_accounts_password_pam_enforce_root"
        sed -i --follow-symlinks "/^\s*enforce_for_root/Id" "$pwquality_conf"
        printf '\n# Per CCE-86356-3: Set enforce_for_root in %s\n' "$pwquality_conf" >> "$pwquality_conf"
        printf 'enforce_for_root\n' >> "$pwquality_conf" || \
            { restore_backup "$pwquality_conf" "$backup"; exit 1; }
    else
        log "Remediation not applicable: pam not installed"
    fi
}

remediate_pam_password_history() {
    if check_package "pam"; then
        log "Remediating: PAM password history"
        local var_password_pam_remember="5"
        local var_password_pam_remember_control_flag="required"
        local pam_files=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")

        for pam_file in "${pam_files[@]}"; do
            if validate_pam_file "$pam_file"; then
                backup=$(backup_file "$pam_file")
                if grep -q "^password.*pam_pwhistory.so.*" "$pam_file"; then
                    if ! grep -q "remember=$var_password_pam_remember" "$pam_file"; then
                        sed -i --follow-symlinks "/pam_pwhistory.so/ s/$/ remember=$var_password_pam_remember/" "$pam_file" || \
                            { restore_backup "$pam_file" "$backup"; exit 1; }
                    fi
                    if ! grep -q "^password.*$var_password_pam_remember_control_flag.*pam_pwhistory.so.*" "$pam_file"; then
                        sed -r -i --follow-symlinks "s/(^password.*)(required|requisite)(.*pam_pwhistory\.so.*)/\1$var_password_pam_remember_control_flag\3/" "$pam_file" || \
                            { restore_backup "$pam_file" "$backup"; exit 1; }
                    fi
                else
                    sed -i --follow-symlinks "/^password.*pam_unix.so.*/i password $var_password_pam_remember_control_flag pam_pwhistory.so use_authtok remember=$var_password_pam_remember" "$pam_file" || \
                        { restore_backup "$pam_file" "$backup"; exit 1; }
                fi
                rm -f "$backup"
            fi
        done
    else
        log "Remediation not applicable: pam not installed"
    fi
}

remediate_pam_faillock() {
    if check_package "pam"; then
        log "Remediating: PAM faillock settings"
        local var_accounts_passwords_pam_faillock_deny="3"
        local var_accounts_passwords_pam_faillock_fail_interval="900"
        local var_accounts_passwords_pam_faillock_unlock_time="0"
        local pam_files=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
        local faillock_conf="/etc/security/faillock.conf"

        if [[ -f "/usr/sbin/authconfig" ]]; then
            authconfig --enablefaillock --update || log "Failed to enable faillock with authconfig"
        elif [[ -f "/usr/bin/authselect" ]] && authselect check; then
            authselect enable-feature with-faillock && authselect apply-changes || \
                { log "authselect integrity check failed"; exit 1; }
        fi

        if [[ -f "$faillock_conf" ]]; then
            check_permissions "$faillock_conf" "644"
            backup=$(backup_file "$faillock_conf")
            for option in "deny=$var_accounts_passwords_pam_faillock_deny" \
                          "fail_interval=$var_accounts_passwords_pam_faillock_fail_interval" \
                          "unlock_time=$var_accounts_passwords_pam_faillock_unlock_time" \
                          "even_deny_root"; do
                if [[ "$option" == "even_deny_root" ]]; then
                    grep -q "^\s*even_deny_root" "$faillock_conf" || \
                        echo "even_deny_root" >> "$faillock_conf" || \
                        { restore_backup "$faillock_conf" "$backup"; exit 1; }
                else
                    local key=${option%%=*}
                    local value=${option#*=}
                    if grep -q "^\s*$key\s*=" "$faillock_conf"; then
                        sed -i --follow-symlinks "s/^\s*\($key\s*\)=.*$/\1 = $value/g" "$faillock_conf" || \
                            { restore_backup "$faillock_conf" "$backup"; exit 1; }
                    else
                        echo "$option" >> "$faillock_conf" || \
                            { restore_backup "$faillock_conf" "$backup"; exit 1; }
                    fi
                fi
            done
            rm -f "$backup"
        else
            for pam_file in "${pam_files[@]}"; do
                if validate_pam_file "$pam_file"; then
                    backup=$(backup_file "$pam_file")
                    for option in "deny=$var_accounts_passwords_pam_faillock_deny" \
                                  "fail_interval=$var_accounts_passwords_pam_faillock_fail_interval" \
                                  "unlock_time=$var_accounts_passwords_pam_faillock_unlock_time" \
                                  "even_deny_root"; do
                        if ! grep -q "^auth.*pam_faillock.so \(preauth silent\|authfail\).*${option%%=*}" "$pam_file"; then
                            sed -i --follow-symlinks "/^auth.*pam_faillock.so \(preauth silent\|authfail\).*/ s/$/ $option/" "$pam_file" || \
                                { restore_backup "$pam_file" "$backup"; exit 1; }
                        fi
                    done
                    if ! grep -qE '^\s*account\s+required\s+pam_faillock\.so.*$' "$pam_file"; then
                        sed -E -i --follow-symlinks '/^\s*account\s*required\s*pam_unix.so/i account     required      pam_faillock.so' "$pam_file" || \
                            { restore_backup "$pam_file" "$backup"; exit 1; }
                    fi
                    rm -f "$backup"
                fi
            done
        fi
    else
        log "Remediation not applicable: pam not installed"
    fi
}

remediate_umask_settings() {
    for file in "/etc/bashrc" "/etc/csh.cshrc" "/etc/profile"; do
        log "Remediating: UMASK in $file"
        [[ -f "$file" ]] || touch "$file"
        check_permissions "$file" "644"
        backup=$(backup_file "$file")
        if grep -q "umask" "$file"; then
            sed -i --follow-symlinks "s/umask.*/umask 077/g" "$file" || \
                { restore_backup "$file" "$backup"; exit 1; }
        else
            echo "umask 077" >> "$file" || \
                { restore_backup "$file" "$backup"; exit 1; }
        fi
        rm -f "$backup"
    done

    if check_package "shadow-utils"; then
        log "Remediating: xccdf_org.ssgproject.content_rule_accounts_umask_etc_login_defs"
        replace_or_append '/etc/login.defs' '^UMASK' '077' 'CCE-82888-9' '%s %s'
    else
        log "Remediation not applicable: shadow-utils not installed"
    fi
}

remediate_banner_etc_issue() {
    log "Remediating: xccdf_org.ssgproject.content_rule_banner_etc_issue"
    local banner_text="You are accessing a Super Cool Container!"
    local issue_file="/etc/issue"
    backup=$(backup_file "$issue_file")
    echo "$banner_text" | fold -sw 80 > "$issue_file" || \
        { restore_backup "$issue_file" "$backup"; exit 1; }
    printf '\n' >> "$issue_file"
    rm -f "$backup"
}

remediate_configure_usbguard_auditbackend() {
    log "Remediating: xccdf_org.ssgproject.content_rule_configure_usbguard_auditbackend"
    local usbguard_conf="/etc/usbguard/usbguard-daemon.conf"
    [[ -f "$usbguard_conf" ]] || touch "$usbguard_conf"
    check_permissions "$usbguard_conf" "644"
    backup=$(backup_file "$usbguard_conf")
    sed -i --follow-symlinks "/^\s*AuditBackend=/d" "$usbguard_conf"
    printf 'AuditBackend=LinuxAudit\n' >> "$usbguard_conf" || \
        { restore_backup "$usbguard_conf" "$backup"; exit 1; }
    rm -f "$backup"
    reload_service "usbguard"
}

remediate_coredump_settings() {
    for option in "ProcessSizeMax=0" "Storage=none"; do
        log "Remediating: Core dump $option"
        local coredump_conf="/etc/systemd/coredump.conf"
        [[ -f "$coredump_conf" ]] || touch "$coredump_conf"
        check_permissions "$coredump_conf" "644"
        backup=$(backup_file "$coredump_conf")
        local key=${option%%=*}
        sed -i --follow-symlinks "/^\s*$key\s*=/Id" "$coredump_conf"
        printf '%s\n' "$option" >> "$coredump_conf" || \
            { restore_backup "$coredump_conf" "$backup"; exit 1; }
        rm -f "$backup"
    done
    reload_service "systemd-coredump"
}

remediate_disable_ctrlaltdel_burstaction() {
    if check_package "systemd"; then
        log "Remediating: xccdf_org.ssgproject.content_rule_disable_ctrlaltdel_burstaction"
        replace_or_append '/etc/systemd/system.conf' '^CtrlAltDelBurstAction=' 'none' 'CCE-80784-2' '%s=%s'
        systemctl daemon-reload || log "Failed to reload systemd"
    else
        log "Remediation not applicable: systemd not installed"
    fi
}

remediate_disable_users_coredumps() {
    if check_package "pam"; then
        log "Remediating: xccdf_org.ssgproject.content_rule_disable_users_coredumps"
        local limits_conf="/etc/security/limits.conf"
        check_permissions "$limits_conf" "644"
        backup=$(backup_file "$limits_conf")
        if grep -qE '^\s*\*\s+hard\s+core' "$limits_conf"; then
            sed -ri --follow-symlinks 's/(hard\s+core\s+)[[:digit:]]+/\1 0/' "$limits_conf" || \
                { restore_backup "$limits_conf" "$backup"; exit 1; }
        else
            echo "*     hard   core    0" >> "$limits_conf" || \
                { restore_backup "$limits_conf" "$backup"; exit 1; }
        fi
        if ls /etc/security/limits.d/*.conf > /dev/null 2>&1; then
            sed -ri --follow-symlinks '/^\s*\*\s+hard\s+core/d' /etc/security/limits.d/*.conf || \
                { restore_backup "$limits_conf" "$backup"; exit 1; }
        fi
        rm -f "$backup"
    else
        log "Remediation not applicable: pam not installed"
    fi
}

remediate_display_login_attempts() {
    if check_package "pam"; then
        log "Remediating: xccdf_org.ssgproject.content_rule_display_login_attempts"
        local pam_file="/etc/pam.d/postlogin"
        if validate_pam_file "$pam_file"; then
            backup=$(backup_file "$pam_file")
            if ! grep -qE '^\s*session\s+required\s+pam_lastlog\.so\s+showfailed' "$pam_file"; then
                echo "session required pam_lastlog.so showfailed" >> "$pam_file" || \
                    { restore_backup "$pam_file" "$backup"; exit 1; }
            fi
            sed -i --follow-symlinks -E 's/^([^#]+pam_lastlog\.so[^#]*)\ssilent/\1/' "$pam_file" || \
                { restore_backup "$pam_file" "$backup"; exit 1; }
            rm -f "$backup"
        fi
    else
        log "Remediation not applicable: pam not installed"
    fi
}

remediate_ensure_gpgcheck_local_packages() {
    if check_package "dnf"; then
        log "Remediating: xccdf_org.ssgproject.content_rule_ensure_gpgcheck_local_packages"
        replace_or_append '/etc/dnf/dnf.conf' '^localpkg_gpgcheck' '1' 'CCE-80791-7' '%s = %s'
    else
        log "Remediation not applicable: dnf not installed"
    fi
}

remediate_harden_sshd_crypto_policy() {
    for conf_file in "/etc/crypto-policies/back-ends/openssh.config" "/etc/crypto-policies/back-ends/opensshserver.config"; do
        log "Remediating: SSHD crypto policy for $conf_file"
        [[ -f "$conf_file" ]] || touch "$conf_file"
        check_permissions "$conf_file" "644"
        backup=$(backup_file "$conf_file")
        if [[ "$conf_file" == *"openssh.config" ]]; then
            sed -i --follow-symlinks "/^\s*Ciphers\s\+/d" "$conf_file"
            printf 'Ciphers aes256-ctr,aes192-ctr,aes128-ctr\n' >> "$conf_file"
            sed -i --follow-symlinks "/^\s*MACs\s\+/d" "$conf_file"
            printf 'MACs hmac-sha2-512,hmac-sha2-256\n' >> "$conf_file"
        else
            local ciphers_value="-oCiphers=aes256-ctr,aes192-ctr,aes128-ctr"
            local macs_value="-oMACs=hmac-sha2-512,hmac-sha2-256"
            sed -i --follow-symlinks 's/#CRYPTO_POLICY=/CRYPTO_POLICY=/' "$conf_file"
            if ! grep -q "'$ciphers_value'" "$conf_file"; then
                sed -i --follow-symlinks "s/-oCiphers=\S\+/$ciphers_value/g" "$conf_file" || \
                    echo "CRYPTO_POLICY='$ciphers_value'" >> "$conf_file" || \
                    { restore_backup "$conf_file" "$backup"; exit 1; }
            fi
            if ! grep -q "'$macs_value'" "$conf_file"; then
                sed -i --follow-symlinks "s/-oMACs=\S\+/$macs_value/g" "$conf_file" || \
                    echo "CRYPTO_POLICY='$macs_value'" >> "$conf_file" || \
                    { restore_backup "$conf_file" "$backup"; exit 1; }
            fi
        fi
        rm -f "$backup"
        reload_service "sshd"
    done
}

remediate_kernel_module_blacklisting() {
    log "Remediating: Kernel module blacklisting"
    local blacklist_conf="/etc/modprobe.d/blacklist.conf"
    [[ -f "$blacklist_conf" ]] || touch "$blacklist_conf"
    check_permissions "$blacklist_conf" "644"
    backup=$(backup_file "$blacklist_conf")
    for module in atm can cramfs firewire-core sctp tipc; do
        if ! grep -q "^install $module /bin/true" "$blacklist_conf"; then
            echo "install $module /bin/true" >> "$blacklist_conf" || \
                { restore_backup "$blacklist_conf" "$backup"; exit 1; }
        fi
        if ! grep -q "^blacklist $module" "$blacklist_conf"; then
            echo "blacklist $module" >> "$blacklist_conf" || \
                { restore_backup "$blacklist_conf" "$backup"; exit 1; }
        fi
    done
    rm -f "$backup"
}

remediate_no_empty_passwords() {
    log "Remediating: xccdf_org.ssgproject.content_rule_no_empty_passwords"
    for pam_file in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
        if validate_pam_file "$pam_file"; then
            backup=$(backup_file "$pam_file")
            sed -i --follow-symlinks 's/\<nullok\>//g' "$pam_file" || \
                { restore_backup "$pam_file" "$backup"; exit 1; }
            rm -f "$backup"
        fi
    done
}

remediate_openssl_use_strong_entropy() {
    log "Remediating: xccdf_org.ssgproject.content_rule_openssl_use_strong_entropy"
    local openssl_sh="/etc/profile.d/openssl-rand.sh"
    backup=$(backup_file "$openssl_sh")
    cat <<'EOF' > "$openssl_sh"
# Provide a default -rand /dev/random option to openssl commands that support it
openssl() (
    openssl_bin=/usr/bin/openssl
    case "$*" in
        *\ -rand\ *|*\ -help*) exec $openssl_bin "$@" ;;
    esac
    cmds=$($openssl_bin list -digest-commands -cipher-commands | tr '\n' ' ')
    for i in $($openssl_bin list -commands); do
        if $openssl_bin list -options "$i" | grep -q '^rand '; then
            cmds=" $i $cmds"
        fi
    done
    case "$cmds" in
        *\ "$1"\ *)
            cmd="$1"; shift
            exec $openssl_bin "$cmd" -rand /dev/random "$@"
            ;;
        *)
            exec $openssl_bin "$@"
            ;;
    esac
)
EOF
    check_permissions "$openssl_sh" "644"
    rm -f "$backup"
}

remediate_package_installations() {
    for package in crypto-policies iptables rng-tools sudo usbguard; do
        log "Remediating: Installing $package"
        if ! rpm -q --quiet "$package"; then
            dnf install -y "$package" || log "Failed to install $package"
        fi
    done
}

remediate_sudo_require_reauthentication() {
    log "Remediating: xccdf_org.ssgproject.content_rule_sudo_require_reauthentication"
    local sudoers_file="/etc/sudoers"
    if /usr/sbin/visudo -qcf "$sudoers_file"; then
        backup=$(backup_file "$sudoers_file")
        if ! grep -P '^[\s]*Defaults.*\btimestamp_timeout=[-]?\w+\b\b.*$' "$sudoers_file"; then
            echo "Defaults timestamp_timeout=0" >> "$sudoers_file" || \
                { restore_backup "$sudoers_file" "$backup"; exit 1; }
        else
            sed -Ei --follow-symlinks "s/(^[\s]*Defaults.*\btimestamp_timeout=)[-]?\w+(\b.*$)/\10\2/" "$sudoers_file" || \
                { restore_backup "$sudoers_file" "$backup"; exit 1; }
        fi
        if /usr/sbin/visudo -qcf "$sudoers_file"; then
            rm -f "$backup"
        else
            restore_backup "$sudoers_file" "$backup"
            log "Failed to validate remediated $sudoers_file"
            exit 1
        fi
    else
        log "Skipping remediation, $sudoers_file failed to validate"
        exit 1
    fi
}

remediate_sudoers_validate_passwd() {
    log "Remediating: xccdf_org.ssgproject.content_rule_sudoers_validate_passwd"
    local sudoers_file="/etc/sudoers"
    for option in "!targetpw" "!rootpw" "!runaspw"; do
        [[ -f "$sudoers_file" ]] || touch "$sudoers_file"
        check_permissions "$sudoers_file" "440"
        backup=$(backup_file "$sudoers_file")
        sed -i --follow-symlinks "/Defaults $option/d" "$sudoers_file"
        printf 'Defaults %s\n' "$option" >> "$sudoers_file" || \
            { restore_backup "$sudoers_file" "$backup"; exit 1; }
        if /usr/sbin/visudo -qcf "$sudoers_file"; then
            rm -f "$backup"
        else
            restore_backup "$sudoers_file" "$backup"
            log "Failed to validate remediated $sudoers_file"
            exit 1
        fi
    done
}

remediate_selinux_enforcing() {
    log "Remediating: Ensure SELinux is in enforcing mode"
    if check_package "selinux-policy"; then
        local selinux_conf="/etc/selinux/config"
        [[ -f "$selinux_conf" ]] || { log "SELinux configuration file $selinux_conf not found"; exit 1; }
        check_permissions "$selinux_conf" "644"
        backup=$(backup_file "$selinux_conf")
        if grep -q "^SELINUX=" "$selinux_conf"; then
            sed -i --follow-symlinks "s/^SELINUX=.*/SELINUX=enforcing/" "$selinux_conf" || \
                { restore_backup "$selinux_conf" "$backup"; exit 1; }
        else
            echo "SELINUX=enforcing" >> "$selinux_conf" || \
                { restore_backup "$selinux_conf" "$backup"; exit 1; }
        fi
        setenforce 1 || log "Failed to set SELinux to enforcing mode"
        rm -f "$backup"
    else
        log "Remediation not applicable: selinux-policy not installed"
    fi
}

# Run all remediations
remediate_account_disable_post_pw_expiration
remediate_accounts_logon_fail_delay
remediate_accounts_max_concurrent_login_sessions
remediate_accounts_maximum_age_login_defs
remediate_accounts_minimum_age_login_defs
remediate_accounts_password_minlen_login_defs
remediate_password_complexity
remediate_pam_password_history
remediate_pam_faillock
remediate_umask_settings
remediate_banner_etc_issue
remediate_configure_usbguard_auditbackend
remediate_coredump_settings
remediate_disable_ctrlaltdel_burstaction
remediate_disable_users_coredumps
remediate_display_login_attempts
remediate_ensure_gpgcheck_local_packages
remediate_harden_sshd_crypto_policy
remediate_kernel_module_blacklisting
remediate_no_empty_passwords
remediate_openssl_use_strong_entropy
remediate_package_installations
remediate_sudo_require_reauthentication
remediate_sudoers_validate_passwd
remediate_selinux_enforcing

log "Hardening script completed successfully. Backups stored in $BACKUP_DIR for rollback if needed."