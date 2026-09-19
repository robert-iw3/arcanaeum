<#
    Optimized Monitor Network Connections for Firewall Rule CSV
    Skips localhost (127.0.0.0/8, ::1/128) and logs only Established TCP/UDP with external IPs.
    Enhancements: Process caching, partial exports, adaptive interval, file logging.
#>

param (
    [int]$Duration = 60,      # Seconds (e.g., 1209600 for 2 weeks)
    [int]$Interval = 5,       # Initial seconds
    [string]$OutputCsv = "monitored_rules.csv",
    [string]$LogFile = "monitor_log.txt",
    [int]$MaxRules = 10000,   # Cap to prevent memory bloat
    [switch]$VerboseLocalhost  # Log skipped localhost connections
)

# Requires admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Please run as Administrator." -ForegroundColor Red
    exit
}

function Log-Message {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -Append -FilePath $LogFile
    Write-Host $Message
}

# Localhost filter (IPv4: 127.0.0.0/8, IPv6: ::1/128)
function Is-Localhost {
    param ([string]$Address)
    return ($Address -match '^127\.(\d{1,3}\.){2}\d{1,3}$' -or $Address -eq '::1')
}

$uniqueRules = @{}
$startTime = Get-Date
$loopCount = 0
$partialExportInterval = 600 / $Interval  # Every ~10 min
$minInterval = 5
$maxInterval = 60

Log-Message "Starting monitoring for $Duration seconds (initial interval: $Interval s)..."

while (((Get-Date) - $startTime).TotalSeconds -lt $Duration -and $uniqueRules.Count -lt $MaxRules) {
    $loopStart = Get-Date
    $newRulesThisLoop = 0
    $processCache = @{}  # PID to process name cache

    try {
        # TCP Listen (Inbound, only non-localhost bindings)
        $tcpListen = Get-NetTCPConnection -State Listen -ErrorAction Stop
        foreach ($conn in $tcpListen) {
            if (Is-Localhost -Address $conn.LocalAddress) {
                if ($VerboseLocalhost) { Log-Message "Skipped TCP Listen (localhost): LocalPort $($conn.LocalPort)" }
                continue
            }
            if (-not $processCache.ContainsKey($conn.OwningProcess)) {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name -First 1
                $processCache[$conn.OwningProcess] = if ($proc) { $proc } else { "Unknown" }
            }
            $process = $processCache[$conn.OwningProcess]
            $key = "TCP_IN_$($conn.LocalPort)_$process"
            if (-not $uniqueRules.ContainsKey($key)) {
                $uniqueRules[$key] = @{
                    rule_name     = "AUTO_TCP_IN_$($conn.LocalPort)_$process"
                    direction     = "Inbound"
                    port          = $conn.LocalPort
                    protocol      = "TCP"
                    remote_address= "Any"
                    action        = "Allow"
                    profile       = "Any"
                }
                $newRulesThisLoop++
                Log-Message "Logged Inbound TCP Listen: LocalPort $($conn.LocalPort) (Process: $process)"
            }
        }

        # TCP Established (Inbound/Outbound, only external IPs)
        $tcpEstablished = Get-NetTCPConnection -State Established -ErrorAction Stop
        $listeningPorts = $tcpListen | Where-Object { -not (Is-Localhost -Address $_.LocalAddress) } | Select-Object -ExpandProperty LocalPort -Unique
        foreach ($conn in $tcpEstablished) {
            # Skip if both LocalAddress and RemoteAddress are localhost
            if ((Is-Localhost -Address $conn.LocalAddress) -and (Is-Localhost -Address $conn.RemoteAddress)) {
                if ($VerboseLocalhost) { Log-Message "Skipped TCP Established (localhost): LocalPort $($conn.LocalPort) -> Remote $($conn.RemoteAddress):$($conn.RemotePort)" }
                continue
            }
            if (-not $processCache.ContainsKey($conn.OwningProcess)) {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name -First 1
                $processCache[$conn.OwningProcess] = if ($proc) { $proc } else { "Unknown" }
            }
            $process = $processCache[$conn.OwningProcess]

            if ($conn.LocalPort -in $listeningPorts -and -not (Is-Localhost -Address $conn.LocalAddress)) {
                # Inbound Established (to a listening port, non-localhost LocalAddress)
                $key = "TCP_IN_$($conn.LocalPort)_$process"
                if (-not $uniqueRules.ContainsKey($key)) {
                    $uniqueRules[$key] = @{
                        rule_name     = "AUTO_TCP_IN_$($conn.LocalPort)_$process"
                        direction     = "Inbound"
                        port          = $conn.LocalPort
                        protocol      = "TCP"
                        remote_address= "Any"
                        action        = "Allow"
                        profile       = "Any"
                    }
                    $newRulesThisLoop++
                    Log-Message "Logged Inbound TCP Established: LocalPort $($conn.LocalPort) (Process: $process)"
                }
            } elseif (-not (Is-Localhost -Address $conn.RemoteAddress)) {
                # Outbound Established (non-localhost RemoteAddress)
                $key = "TCP_OUT_$($conn.RemotePort)_$($conn.RemoteAddress)_$process"
                if (-not $uniqueRules.ContainsKey($key)) {
                    $uniqueRules[$key] = @{
                        rule_name     = "AUTO_TCP_OUT_$($conn.RemotePort)_$process"
                        direction     = "Outbound"
                        port          = $conn.RemotePort
                        protocol      = "TCP"
                        remote_address= $conn.RemoteAddress
                        action        = "Allow"
                        profile       = "Any"
                    }
                    $newRulesThisLoop++
                    Log-Message "Logged Outbound TCP: RemotePort $($conn.RemotePort) to $($conn.RemoteAddress) (Process: $process)"
                }
            }
        }

        # UDP Endpoints (Inbound, only non-localhost bindings)
        $udpEndpoints = Get-NetUDPEndpoint -ErrorAction Stop
        foreach ($end in $udpEndpoints) {
            if (Is-Localhost -Address $end.LocalAddress) {
                if ($VerboseLocalhost) { Log-Message "Skipped UDP Endpoint (localhost): LocalPort $($end.LocalPort)" }
                continue
            }
            if (-not $processCache.ContainsKey($end.OwningProcess)) {
                $proc = Get-Process -Id $end.OwningProcess -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name -First 1
                $processCache[$end.OwningProcess] = if ($proc) { $proc } else { "Unknown" }
            }
            $process = $processCache[$end.OwningProcess]
            $key = "UDP_IN_$($end.LocalPort)_$process"
            if (-not $uniqueRules.ContainsKey($key)) {
                $uniqueRules[$key] = @{
                    rule_name     = "AUTO_UDP_IN_$($end.LocalPort)_$process"
                    direction     = "Inbound"
                    port          = $end.LocalPort
                    protocol      = "UDP"
                    remote_address= "Any"
                    action        = "Allow"
                    profile       = "Any"
                }
                $newRulesThisLoop++
                Log-Message "Logged Inbound UDP: LocalPort $($end.LocalPort) (Process: $process)"
            }
        }
    } catch {
        Log-Message "Error in loop: $_" -ForegroundColor Red
    }

    # Adaptive interval
    if ($newRulesThisLoop -lt 5) {
        $Interval = [math]::Min($Interval + 5, $maxInterval)
    } else {
        $Interval = [math]::Max($Interval - 5, $minInterval)
    }

    # Partial export
    $loopCount++
    if ($loopCount % $partialExportInterval -eq 0) {
        $rulesList = $uniqueRules.Values | ForEach-Object { [pscustomobject]$_ }
        $rulesList | Export-Csv -Path $OutputCsv -NoTypeInformation -Append
        $uniqueRules.Clear()  # Clear to free memory
        Log-Message "Partial export done. Cleared in-memory rules."
    }

    $loopTime = ((Get-Date) - $loopStart).TotalMilliseconds
    Log-Message "Loop $loopCount complete. Time: $loopTime ms. New rules: $newRulesThisLoop. Next interval: $Interval s"

    Start-Sleep -Seconds $Interval
}

# Final export
$rulesList = $uniqueRules.Values | ForEach-Object { [pscustomobject]$_ }
$rulesList | Export-Csv -Path $OutputCsv -NoTypeInformation -Append

Log-Message "Monitoring complete. Generated $OutputCsv with $($rulesList.Count) unique rules (total may vary due to partial exports). Max rules cap: $MaxRules."