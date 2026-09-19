<#
    Uncomplicated Windows Firewall Pwsh Script
    Configure ports, whether tcp or udp, and from what subnet or IP to allow/deny.
    Granular, so if you want to allow all outbound, comment out outbound rules and deny-by-default rule as well.
#>

$rules = @(
    # Allow HTTP (port 80) If this host has http services.
    @("00_FW_HTTP_INBOUND_ALLOW", "Inbound", 80, "TCP", "192.168.100.0/24", "Allow"),

    # Allow HTTPS (port 443) If this host has http services.
    @("01_FW_HTTPS_INBOUND_ALLOW", "Inbound", 443, "TCP", "192.168.100.0/24", "Allow"),

    # Allow SSH (port 22) Secure Shell for remote management.
    @("02_FW_FTP_INBOUND_ALLOW", "Inbound", 22, "TCP", "192.168.100.0/24", "Allow"),

    # Allow RDP (port 3389) Subnet to allow remote desktop to connect.
    @("03_FW_FTPS_INBOUND_ALLOW", "Inbound", 3389, "TCP", "192.168.100.0/24", "Allow"),

    # Allow SMTP (port 25) IP of Exchange/Postfix email server.
    @("04_FW_SMTP_INBOUND_ALLOW", "Inbound", 25, "TCP", "192.168.100.25", "Allow"),

    # Allow SMTPS (port 587) IP of TLS enabled Exchange/Postfix email server.
    @("05_FW_SMTPS_INBOUND_ALLOW", "Inbound", 587, "TCP", "192.168.100.25", "Allow"),

    # Allow DNS (port 53) IP From DC or DNS server.
    @("06_FW_DNS_INBOUND_ALLOW", "Inbound", 53, "TCP", "192.168.100.4", "Allow"),


  # ------------ Outbound | Allow ------------
    # Allow HTTP (port 80)
    @("10_FW_HTTP_OUTBOUND_ALLOW", "Outbound", 80, "TCP", "192.168.100.0/24", "Allow"),

    # Allow HTTPS (port 443)
    @("11_FW_HTTPS_OUTBOUND_ALLOW", "Outbound", 443, "TCP", "192.168.100.0/24", "Allow"),

    # Allow SSH (port 22)
    @("12_FW_SSH_OUTBOUND_ALLOW", "Outbound", 22, "TCP", "192.168.100.0/24", "Allow"),

    # Allow SMTP (port 25)
    @("13_FW_SMTP_OUTBOUND_ALLOW", "Outbound", 25, "TCP", "192.168.100.0/24", "Allow")
)

foreach ($rule in $rules) {
  New-NetFirewallRule -DisplayName $rule[0] -Direction $rule[1] -LocalPort $rule[2] -Protocol $rule[3] -RemoteAddress $rule[4] -Action $rule[5]
  Write-Host "[" $rule[5] "]" "DisplayName="$rule[0] "Direction="$rule[1] "LocalPort="$rule[2] "Protocol="$rule[3] "RemoteAddress="$rule[4]
}

Write-Host "Setting Deny-by-Default Inbound Rule."
New-NetFirewallRule -DisplayName "Deny All Inbound (Place at the bottom of Active Rules)" -Direction Inbound -Action Block

Write-Host "Setting Deny-by-Default Outbound Rule."
New-NetFirewallRule -DisplayName "Deny All Outbound (Place at the bottom of Active Rules)" -Direction Outbound -Action Block