<#
.SYNOPSIS
    Windows Kernel IDPS Sensor (Native FFI Architecture)
.DESCRIPTION
    A high-performance, real-time Bidirectional Volumetric IDPS detection and response engine.
    It injects Microsoft.Diagnostics.Tracing.TraceEvent directly into RAM via embedded C#
    to monitor live kernel ETW events, bypassing heavy telemetry trace files.

    Architecture Flow:
      1. Dynamic Pre-Loader: Fetches the correct TraceEvent library based on the host's .NET runtime.
      2. C# Engine: Parses the high-volume ETW firehose at lightning speed, aggressively pre-filtering
         benign noise and routing flows by Ingress, Egress, or Lateral direction.
      3. Server-Side AppGuard: Monitors process lineages to instantly intercept web shells
         and database RCEs (IIS, SQL, Tomcat, Node) spawning command interpreters.
      4. Cryptographic DPI: Subscribes to raw Layer 2 NDIS frames, using an unmanaged byte-scanner
         to extract TLS Client Hello signatures and map JA3 hashes to Ring-3 processes.
      5. Native FFI Pipeline: Replaces legacy Python IPC pipes. PowerShell passes memory pointers
         directly into the C-compiled Rust DLL (`idpssensor_ml.dll`) for zero-latency ML clustering.
      6. SQLite WAL State Manager: The Rust engine handles all volumetric tracking natively, logging
         bidirectional flow states to a secure database in `C:\ProgramData\IDPSSensor\Data`.
      7. Thread-Level Tracking (TID): Extracts Native Thread IDs to isolate anomalous network pipelines.
.AUTHOR
    Robert Weber
#>
#Requires -RunAsAdministrator

# ====================== CONFIGURATION & PARAMETERS ======================
param (
    [int]$BatchAnalysisIntervalSeconds = 15,
    [int]$MinSamplesForML = 8,
    [switch]$EnableDiagnostics,
    [switch]$TestMode,
    [switch]$ArmedMode,
    [int]$ConfidenceThreshold = 95
)

# ====================== GLOBAL VARIABLES ======================

$global:IsArmed = $ArmedMode
# Wire the -EnableDiagnostics switch to the global that Write-Diag gates on (line ~812).
# Without this the switch is dead and C#-ENGINE/INFO diagnostics are always dropped.
$global:EnableDiagnostics = [bool]$EnableDiagnostics
$ScriptDir = Split-Path $PSCommandPath -Parent
$now = Get-Date

# Alert Metadata
$activeRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
if ($activeRoute) {
    $global:HostIP = (Get-NetIPAddress -InterfaceIndex $activeRoute.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
}
if (-not $global:HostIP) { $global:HostIP = "Unknown" }
$global:SensorUser = "$env:USERDOMAIN\$env:USERNAME".Replace("\", "\\")
$global:ComputerName = $env:COMPUTERNAME

# Directory Structure
$DataDir = "C:\ProgramData\IDPSSensor\Data"
$LogDir  = "C:\ProgramData\IDPSSensor\Logs"
$StagingDir = "C:\ProgramData\IDPSSensor\Staging"

if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Force -Path $DataDir | Out-Null }
if (-not (Test-Path $LogDir))  { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }
if (-not (Test-Path $StagingDir)) { New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null }

$OutputPath = "$LogDir\IDPSSensor_Alerts.jsonl"
$UebaLogPath = "$LogDir\IDPSSensor_UEBA.jsonl"
$MonitorLogPath = "$LogDir\Network_Monitor.log"
$DiagLogPath = "$LogDir\IDPSSensor_Diagnostic.log"
$TamperLogPath = "$DataDir\IDPSSensor_TamperGuard.log"
$Ja3CachePath = "$DataDir\IDPSSensor_JA3_Cache.json"

# ====================== RUNTIME STRUCTURES ======================

# Thread-safe Process and Connection Tracking
$ProcessCache      = [System.Collections.Concurrent.ConcurrentDictionary[int, string]]::new()
$connectionHistory = [System.Collections.Concurrent.ConcurrentDictionary[string, System.Collections.Generic.Queue[datetime]]]::new()
$flowMetadata      = [System.Collections.Concurrent.ConcurrentDictionary[string, hashtable]]::new()
$lastPingTime = [System.Collections.Concurrent.ConcurrentDictionary[string, datetime]]::new()
$loggedFlows   = [System.Collections.Concurrent.ConcurrentDictionary[string, int]]::new()
$LateralTrack = [System.Collections.Concurrent.ConcurrentDictionary[string, datetime]]::new()
$EgressTrack  = [System.Collections.Concurrent.ConcurrentDictionary[string, datetime]]::new()

# High-Speed Batching Lists (Globalized for Submit-SensorAlert access)
$global:uebaBatch = [System.Collections.Generic.List[string]]::new()
$global:dataBatch = [System.Collections.Generic.List[PSCustomObject]]::new()

# Unified Deduplication Cache (Globalized to prevent null-expression crash)
$global:cycleAlerts = [System.Collections.Generic.Dictionary[string, object]]::new()

# UEBA Temporal Feedback Cache
$global:UebaLearningCache = [System.Collections.Generic.Dictionary[string, int]]::new()

$global:RecentAlerts = [System.Collections.Generic.List[PSCustomObject]]::new()

$global:StartupLogs = [System.Collections.Generic.List[string]]::new()

# Metrics Consolidation
$global:SensorStats = [PSCustomObject]@{
    MlSent      = 0
    MlRcvd      = 0
    Evaluated   = 0
    Alerts      = 0
    Mitigations = 0
    BootTime    = Get-Date
}

$dashboardDirty = $true
$lastMLRunTime = Get-Date
$lastCleanupTime = Get-Date
$lastLightGC = Get-Date
$lastUebaCleanup = Get-Date
$SensorBlinded = $false
$LastEventReceived = Get-Date
$global:TotalLateralFlows = 0

$global:TotalMitigations = 0
$global:globalMlSent = 0
$global:globalMlRcvd = 0
$global:globalMlAlerts = 0

# ====================== DIAGNOSTICS & LEDGER INITIALIZATION ======================
if (Test-Path $DiagLogPath) { Remove-Item -Path $DiagLogPath -Force -ErrorAction SilentlyContinue }

try {
    # Upgraded to ReadWrite to prevent hard locks from SIEMs or external agents
    $global:DiagStream = [System.IO.File]::Open($DiagLogPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    $global:DiagWriter = New-Object System.IO.StreamWriter($global:DiagStream)
    $global:DiagWriter.AutoFlush = $true
} catch {
    Write-Host "[!] Diagnostic log locked by zombie process. Executing cleanup..." -ForegroundColor Yellow

    Get-Process powershell, pwsh -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $PID } | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    $global:DiagStream = [System.IO.File]::Open($DiagLogPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    $global:DiagWriter = New-Object System.IO.StreamWriter($global:DiagStream)
    $global:DiagWriter.AutoFlush = $true
}

# ====================== CONSOLE UI SETUP ======================

$Host.UI.RawUI.BackgroundColor = 'Black'
$Host.UI.RawUI.ForegroundColor = 'Gray'
Clear-Host

$ESC      = [char]27
$cCyan    = "$ESC[38;2;0;255;255m"
$cGreen   = "$ESC[38;2;57;255;20m"
$cOrange  = "$ESC[38;2;255;103;0m"
$cGold    = "$ESC[38;2;255;215;0m"
$cYellow  = "$ESC[38;2;255;255;51m"
$cRed     = "$ESC[38;2;255;49;49m"
$cWhite   = "$ESC[38;2;255;255;255m"
$cDark    = "$ESC[38;2;80;80;80m"
$cReset   = "$ESC[0m$ESC[40m"

try {
    $ui = $Host.UI.RawUI
    $buffer = $ui.BufferSize; $buffer.Width = 160; $buffer.Height = 3000; $ui.BufferSize = $buffer
    $size = $ui.WindowSize; $size.Width = 160; $size.Height = 58; $ui.WindowSize = $size
} catch {}

[Console]::SetCursorPosition(0, 9)

# ====================== UI RENDERING ======================

function Draw-StartupWindow {
    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
    $UIWidth = 100
    [Console]::SetCursorPosition(0, 37)

    $cGreen = "$([char]27)[38;2;57;255;20m"
    $HeaderPlain = "  [ SENSOR INITIALIZATION ]"
    $PadHeader = " " * [math]::Max(0, ($UIWidth - $HeaderPlain.Length))

    Write-Host "$cCyan╔════════════════════════════════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset$cGreen$HeaderPlain$cReset$PadHeader$cCyan║$cReset"
    Write-Host "$cCyan╠════════════════════════════════════════════════════════════════════════════════════════════════════╣$cReset"

    $recent = if ($global:StartupLogs.Count -gt 10) { $global:StartupLogs.GetRange($global:StartupLogs.Count - 10, 10) } else { $global:StartupLogs }

    for ($i = 0; $i -lt 10; $i++) {
        if ($i -lt $recent.Count) {
            $logLine = "    $($recent[$i])"
            if ($logLine.Length -gt ($UIWidth - 1)) { $logLine = $logLine.Substring(0, $UIWidth - 4) + "..." }
            $pad = " " * [math]::Max(0, ($UIWidth - $logLine.Length))
            Write-Host "$cCyan║$cReset$logLine$pad$cCyan║$cReset"
        } else {
            $pad = " " * $UIWidth
            Write-Host "$cCyan║$cReset$pad$cCyan║$cReset"
        }
    }
    Write-Host "$cCyan╚════════════════════════════════════════════════════════════════════════════════════════════════════╝$cReset"

    [Console]::SetCursorPosition($curLeft, $curTop)
}

function Add-AlertMessage([string]$Message, [string]$ColorCode) {
    $ts = (Get-Date).ToString("HH:mm:ss")
    $prefix = "[$ts] "
    $maxLen = 98 - $prefix.Length

    # Safely strip ANSI color codes before calculating length
    $cleanText = $Message -replace "`e\[[0-9;]*m", ""
    if ($cleanText.Length -gt $maxLen) { $Message = $Message.Substring(0, $maxLen - 3) + "..." }

    $global:RecentAlerts.Add([PSCustomObject]@{ Text = "$prefix$Message"; Color = $ColorCode })

    if ($global:RecentAlerts.Count -gt 20) { $global:RecentAlerts.RemoveAt(0) }
    Draw-AlertWindow
}

function Draw-AlertWindow {
    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
    [Console]::SetCursorPosition(0, 10) # Slot perfectly under the 9-line Dashboard

    $logTrunc = if ($OutputPath.Length -gt 60) { "..." + $OutputPath.Substring($OutputPath.Length - 57) } else { $OutputPath }
    $headerPlain = "  [ LIVE THREAT TELEMETRY ] | Log: $logTrunc"
    $padHeader = " " * [math]::Max(0, (100 - $headerPlain.Length))

    Write-Host "$cCyan╔════════════════════════════════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset  $cGreen[ LIVE THREAT TELEMETRY ]$cReset | Log: $cDark$logTrunc$cReset$padHeader$cCyan║$cReset"
    Write-Host "$cCyan╠════════════════════════════════════════════════════════════════════════════════════════════════════╣$cReset"

    for ($i = 0; $i -lt 20; $i++) {
        if ($i -lt $global:RecentAlerts.Count) {
            $item = $global:RecentAlerts[$i]
            $cleanText = $item.Text -replace "`e\[[0-9;]*m", ""
            $pad = " " * [math]::Max(0, (98 - $cleanText.Length))
            Write-Host "$cCyan║$cReset  $($item.Color)$($item.Text)$cReset$pad$cCyan║$cReset"
        } else {
            Write-Host "$cCyan║$cReset                                                                                                    $cCyan║$cReset"
        }
    }
    Write-Host "$cCyan╚════════════════════════════════════════════════════════════════════════════════════════════════════╝$cReset"

    # Anchor the cursor out of the way
    [Console]::SetCursorPosition(0, 36)
    [Console]::SetCursorPosition($curLeft, $curTop)
}

function Draw-MonitorDashboard([int]$Events, [int]$Flows, [int]$Lateral, [int]$MlSent, [int]$Alerts, [string]$Tamper, [string]$MlHealth, [string]$SysGuard, [int]$Mitigations) {
    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
    [Console]::SetCursorPosition(0, 0)

    $evPad     = $Events.ToString().PadRight(9)
    $egressPad = $Flows.ToString().PadRight(5)
    $latPad    = $Lateral.ToString().PadRight(6)
    $mlPad     = "$MlSent / $MlSent".PadRight(9)
    $tamperPad = $Tamper.PadRight(9)
    $sysguardPad = $SysGuard.PadRight(9)
    $defFired  = $Mitigations.ToString().PadRight(9)

    $TitlePlain  = "  [ IDPS Sensor ] NetFlow Observability Dashboard"
    $StatusStr   = "  [ LIVE TELEMETRY ]"
    $Stats1Str   = "  Events Processed : $evPad | Active Flows   : $egressPad | Lateral P2P : $latPad"
    $Stats2Str   = "  ML Sent/Eval     : $mlPad | Active Alerts  : $Alerts"
    $TamperStr   = "  ETW Sensor       : $tamperPad | ML Math Engine : $MlHealth"
    $SysGuardStr = "  Sys Guard State  : $sysguardPad | Defenses Fired : $defFired"

    $PadTitle  = " " * [math]::Max(0, (98 - $TitlePlain.Length + 2))
    $PadStatus = " " * [math]::Max(0, (98 - $StatusStr.Length + 2))
    $PadStats1 = " " * [math]::Max(0, (98 - $Stats1Str.Length + 2))
    $PadStats2 = " " * [math]::Max(0, (98 - $Stats2Str.Length + 2))
    $PadTamper = " " * [math]::Max(0, (98 - $TamperStr.Length + 2))
    $PadSysGuard = " " * [math]::Max(0, (98 - $SysGuardStr.Length + 2))

    $TamperColor = if ($Tamper -eq "Good") { $cGreen } else { $cGold }
    $MlColor     = if ($MlHealth -eq "Native FFI") { $cGreen } else { $cGold }
    $GuardColor  = if ($SysGuard -eq "Secure") { $cGreen } else { $cRed }

    Write-Host "$cCyan╔════════════════════════════════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset$cGold$TitlePlain$cReset$PadTitle$cCyan║$cReset"
    Write-Host "$cCyan╠════════════════════════════════════════════════════════════════════════════════════════════════════╣$cReset"
    Write-Host "$cCyan║$cReset$cOrange$StatusStr$cReset$PadStatus$cCyan║$cReset"
    Write-Host "$cCyan║$cReset  Events Processed : $cCyan$evPad$cReset | Active Flows   : $cRed$egressPad$cReset | Lateral P2P : $cOrange$latPad$cReset$PadStats1$cCyan║$cReset"
    Write-Host "$cCyan║$cReset  ML Sent/Eval     : $cYellow$mlPad$cReset | Active Alerts  : $cGold$Alerts$cReset$PadStats2$cCyan║$cReset"
    Write-Host "$cCyan║$cReset  ETW Sensor       : $TamperColor$tamperPad$cReset | ML Math Engine : $MlColor$MlHealth$cReset$PadTamper$cCyan║$cReset"
    Write-Host "$cCyan║$cReset  Sys Guard State  : $GuardColor$sysguardPad$cReset | Defenses Fired : $cYellow$defFired$cReset$PadSysGuard$cCyan║$cReset"
    Write-Host "$cCyan╚════════════════════════════════════════════════════════════════════════════════════════════════════╝$cReset"

    if ($curTop -lt 9) { $curTop = 9 }
    [Console]::SetCursorPosition($curLeft, $curTop)
}

function Start-IDPSSensorHUD {
    param(
        [bool]$Background = $false,
        [string]$EvtPath,
        [string]$UbaPath
    )

    Write-Diag "    [*] Initializing Live Browser HUD Bridge..." "STARTUP"

    $HtmlPayload = @'
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self';">
        <title>IDPS Sensor | Alert Monitoring Workbench</title>
        <style>
            :root { --bg-main: #0a0e14; --bg-card: #0d1117; --bg-hover: #161b22; --text-main: #c9d1d9; --text-muted: #8b949e; --neon-green: #39FF14; --neon-orange: #FF5F1F; --red: #ff4b4b; --blue: #58a6ff; --border: #30363d; }
            * { box-sizing: border-box; font-family: 'Segoe UI', system-ui, sans-serif; }
            body { background: var(--bg-main); color: var(--text-main); margin: 0; padding: 20px; display: flex; flex-direction: column; height: 100vh; overflow: hidden; }

            .header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 15px; border-bottom: 1px solid var(--border); }
            .header h1 { margin: 0; font-size: 1.5rem; color: #fff; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; }
            .header h1 span { color: var(--blue); }

            .btn-group { display: flex; gap: 10px; align-items: center; }
            input[type="file"] { display: none; }
            .custom-file-upload { background: var(--bg-card); color: var(--neon-green); border: 1px solid var(--neon-green); padding: 8px 16px; border-radius: 4px; cursor: pointer; font-size: 0.85rem; font-weight: 600; text-transform: uppercase; transition: all 0.2s; }
            .custom-file-upload:hover { background: rgba(57, 255, 20, 0.1); }
            .btn { background: var(--bg-card); color: var(--text-main); border: 1px solid var(--border); padding: 8px 16px; border-radius: 4px; cursor: pointer; font-size: 0.85rem; font-weight: 600; text-transform: uppercase; transition: all 0.2s; }
            .btn:hover { border-color: var(--neon-orange); color: var(--neon-orange); }

            .live-indicator { display: flex; align-items: center; gap: 8px; color: var(--neon-green); font-weight: bold; font-family: 'Consolas', monospace; text-transform: uppercase; border: 1px solid var(--neon-green); padding: 5px 12px; border-radius: 4px; background: rgba(57, 255, 20, 0.05); }
            .pulse { width: 8px; height: 8px; background-color: var(--neon-green); border-radius: 50%; box-shadow: 0 0 8px var(--neon-green); animation: throb 1.5s infinite; }
            @keyframes throb { 0% { transform: scale(0.8); opacity: 1; } 50% { transform: scale(1.3); opacity: 0.5; } 100% { transform: scale(0.8); opacity: 1; } }

            .toolbar { display: flex; justify-content: space-between; align-items: center; margin: 15px 0; }
            .search-box { width: 400px; padding: 10px 15px; background: var(--bg-card); border: 1px solid var(--border); border-radius: 4px; color: var(--blue); outline: none; font-family: 'Consolas', monospace; }
            .search-box:focus { border-color: var(--blue); box-shadow: 0 0 5px rgba(88, 166, 255, 0.2); }

            .tabs { display: flex; gap: 5px; }
            .tab { padding: 8px 20px; background: transparent; border: none; color: var(--text-muted); cursor: pointer; font-weight: 600; border-bottom: 2px solid transparent; text-transform: uppercase; }
            .tab.active { color: var(--blue); border-bottom: 2px solid var(--blue); }

            .workspace { display: flex; flex: 1; overflow: hidden; position: relative; gap: 15px; }
            .table-container { flex: 1; overflow: auto; background: var(--bg-card); border: 1px solid var(--border); }
            table { width: 100%; border-collapse: collapse; font-size: 0.85rem; text-align: left; }
            th { background: #161b22; padding: 12px 15px; position: sticky; top: 0; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid var(--border); z-index: 10; text-transform: uppercase; }
            td { padding: 12px 15px; border-bottom: 1px solid var(--border); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 300px; }
            tr { cursor: pointer; transition: background 0.1s; }
            tr:hover { background: var(--bg-hover); }
            tr.selected { background: rgba(88, 166, 255, 0.05); box-shadow: inset 3px 0 0 var(--blue); }

            .tag { padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; text-transform: uppercase; }
            .tag-crit { background: rgba(255, 75, 75, 0.1); color: var(--red); border: 1px solid rgba(255, 75, 75, 0.3); }
            .tag-high { background: rgba(255, 95, 31, 0.1); color: var(--neon-orange); border: 1px solid rgba(255, 95, 31, 0.3); }
            .tag-info { background: rgba(57, 255, 20, 0.1); color: var(--neon-green); border: 1px solid rgba(57, 255, 20, 0.3); }
            .tag-suppressed { background: rgba(255, 95, 31, 0.1); color: var(--neon-orange); border: 1px solid rgba(255, 95, 31, 0.3); font-style: italic; }
            .mono { font-family: 'Consolas', monospace; color: var(--text-muted); }

            .inspector { width: 450px; background: var(--bg-card); border: 1px solid var(--blue); display: flex; flex-direction: column; transform: translateX(120%); transition: transform 0.3s ease; position: absolute; right: 0; top: 0; bottom: 0; z-index: 20; box-shadow: -5px 0 25px rgba(0,0,0,0.8); }
            .inspector.open { transform: translateX(0); }
            .ins-header { padding: 15px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: #161b22; }
            .ins-header h3 { margin: 0; font-size: 1rem; color: var(--blue); text-transform: uppercase; }
            .close-btn { background: transparent; border: none; color: var(--text-muted); cursor: pointer; font-size: 1.5rem; font-weight: bold; }
            .close-btn:hover { color: var(--red); }
            .ins-body { padding: 15px; overflow-y: auto; flex: 1; }
            .kv-pair { margin-bottom: 15px; border-bottom: 1px solid #161b22; padding-bottom: 5px; }
            .kv-key { display: block; font-size: 0.75rem; color: var(--neon-orange); text-transform: uppercase; font-weight: 600; margin-bottom: 4px; }
            .kv-val { font-family: 'Consolas', monospace; font-size: 0.85rem; color: var(--text-main); word-break: break-all; white-space: pre-wrap; }
        </style>
    </head>
    <body>
        <div id="app-container" style="display:flex; flex-direction:column; height:100%;">
            <div class="header">
                <h1>IDPS Sensor <span>HUD</span></h1>
                <div class="btn-group">
                    <div class="live-indicator" id="apiStatus"><div class="pulse"></div> Auto-Tailing API</div>
                    <label class="custom-file-upload">
                        <input type="file" id="fileUploader" accept=".jsonl" multiple />
                        Manual Load
                    </label>
                    <button class="btn" onclick="exportCSV()">Export CSV</button>
                </div>
            </div>

            <div class="toolbar">
                <div class="tabs">
                    <button class="tab active" id="tab-core" onclick="setTab('core')">Network Events (<span id="count-core">0</span>)</button>
                    <button class="tab" id="tab-ueba" onclick="setTab('ueba')">UEBA Baselines (<span id="count-ueba">0</span>)</button>
                </div>
                <input type="text" class="search-box" id="search" placeholder="Search IPs, domains, tags, or behavior...">
            </div>

            <div class="workspace">
                <div class="table-container">
                    <table>
                        <thead id="table-head"></thead>
                        <tbody id="table-body"></tbody>
                    </table>
                </div>
                <div class="inspector" id="inspector">
                    <div class="ins-header">
                        <h3>Event Detail Inspector</h3>
                        <button class="close-btn" onclick="closeInspector()">&times;</button>
                    </div>
                    <div class="ins-body" id="inspector-content"></div>
                </div>
            </div>
        </div>

        <script>
            let coreData = [];
            let uebaData = [];
            let currentTab = 'core';
            let totalCount = 0;
            let isManualMode = false;
            let failCount = 0;

            document.getElementById('fileUploader').addEventListener('change', function(e) {
                const files = e.target.files;
                if (files.length === 0) return;

                isManualMode = true;
                document.getElementById('apiStatus').innerHTML = "<span style='color:var(--neon-orange)'>Manual Mode Active</span>";

                let filesProcessed = 0;
                coreData = []; uebaData = [];

                for (let i = 0; i < files.length; i++) {
                    const reader = new FileReader();
                    reader.onload = function(event) {
                        const lines = event.target.result.split('\n');
                        lines.forEach(line => {
                            if (line.trim().startsWith('{')) {
                                try {
                                    const parsed = JSON.parse(line);
                                    if (parsed.LearningHit !== undefined || parsed.BaselineContext) {
                                        uebaData.push(parsed);
                                    } else {
                                        coreData.push(parsed);
                                    }
                                } catch (err) { }
                            }
                        });

                        filesProcessed++;
                        if (filesProcessed === files.length) {
                            document.getElementById('count-core').innerText = coreData.length;
                            document.getElementById('count-ueba').innerText = uebaData.length;
                            renderTable();
                        }
                    };
                    reader.readAsText(files[i]);
                }
            });

            function setTab(tab) {
                currentTab = tab;
                document.getElementById('tab-core').classList.toggle('active', tab === 'core');
                document.getElementById('tab-ueba').classList.toggle('active', tab === 'ueba');
                closeInspector();
                renderTable();
            }

            function closeInspector() {
                document.getElementById('inspector').classList.remove('open');
                document.querySelectorAll('tr').forEach(r => r.classList.remove('selected'));
            }

            function openInspector(dataItem, rowElement) {
                document.querySelectorAll('tr').forEach(r => r.classList.remove('selected'));
                rowElement.classList.add('selected');
                const content = document.getElementById('inspector-content');
                content.innerHTML = '';
                for (const [key, value] of Object.entries(dataItem)) {
                    if (value === "" || value === null || value === undefined) continue;
                    const valStr = typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value);

                    const pairDiv = document.createElement('div');
                    pairDiv.className = 'kv-pair';

                    const keySpan = document.createElement('span');
                    keySpan.className = 'kv-key';
                    keySpan.textContent = key.replace(/_/g, ' ');

                    const valDiv = document.createElement('div');
                    valDiv.className = 'kv-val';
                    valDiv.textContent = valStr;

                    pairDiv.appendChild(keySpan);
                    pairDiv.appendChild(valDiv);
                    content.appendChild(pairDiv);
                }
                document.getElementById('inspector').classList.add('open');
            }

            function renderTable() {
                const term = document.getElementById('search').value.toLowerCase();
                const data = currentTab === 'core' ? coreData : uebaData;
                const thead = document.getElementById('table-head');
                const tbody = document.getElementById('table-body');

                tbody.innerHTML = '';
                thead.innerHTML = currentTab === 'core'
                    ? '<tr><th>Timestamp</th><th>Direction</th><th>Confidence</th><th>Process</th><th>Source IP</th><th>Destination</th><th>Flags</th><th>Cmd Context</th></tr>'
                    : '<tr><th>Timestamp</th><th>Direction</th><th>Process</th><th>Source IP</th><th>Destination</th><th>Learning Detail</th></tr>';

                for (let i = data.length - 1; i >= 0; i--) {
                    const item = data[i];
                    if (JSON.stringify(item).toLowerCase().indexOf(term) === -1) continue;

                    const tr = document.createElement('tr');

                    const sanitize = (val) => {
                        if (val === null || val === undefined || val === '') return 'N/A';
                        const div = document.createElement('div');
                        div.textContent = String(val);
                        return div.innerHTML || 'N/A';
                    };

                    if (currentTab === 'core') {
                        const conf = parseInt(item.Confidence) || 0;
                        const tagClass = conf >= 95 ? 'tag-crit' : (conf >= 85 ? 'tag-high' : 'tag-info');
                        const tstampCore = item.Timestamp_Local || item.TimeStamp || '';

                        tr.innerHTML = `
                            <td>${sanitize(tstampCore ? tstampCore.split('.')[0] : '')}</td>
                            <td style='color:var(--blue); font-weight:bold;'>${sanitize(item.Direction || item.TrafficDirection || 'Unknown')}</td>
                            <td><span class='tag ${tagClass}'>${sanitize(item.Confidence)}</span></td>
                            <td style='font-weight:600; color:var(--neon-green)'>${sanitize(item.Image)}</td>
                            <td class='mono' style='color:var(--neon-orange)'>${sanitize(item.SourceIp || item.SrcIp || 'Unknown')}</td>
                            <td class='mono'>${sanitize(item.Destination || item.DestIp || 'Unknown')}</td>
                            <td>${sanitize(item.SuspiciousFlags)}</td>
                            <td class='mono'>${sanitize(item.CommandLine || '')}</td>`;
                    } else {
                        const baselineContext = item.BaselineContext || (item.LearningHit !== undefined ? `Learning Hits: ${item.LearningHit}` : "Secured");
                        const tstamp = item.Timestamp_Local || item.TimeStamp || item.Timestamp || item.Timestamp_UTC || '';
                        const timeDisplay = tstamp ? tstamp.split('.')[0] : '';
                        const img = item.Image || item.ProcessName || 'Unknown';
                        const dst = item.Destination || item.DestIp || item.Query || 'Unknown';
                        const src = item.SourceIp || item.SrcIp || 'Unknown';
                        const dir = item.Direction || item.TrafficDirection || 'Unknown';
                        const flags = item.SuspiciousFlags || item.ThreatIntel || item.EventName || 'None';

                        tr.innerHTML = `
                            <td>${sanitize(timeDisplay)}</td>
                            <td style='color:var(--blue); font-weight:bold;'>${sanitize(dir)}</td>
                            <td style='font-weight:600; color:var(--neon-green)'>${sanitize(img)}</td>
                            <td class='mono' style='color:var(--neon-orange)'>${sanitize(src)}</td>
                            <td class='mono'>${sanitize(dst)}</td>
                            <td><span class='tag tag-info'>${sanitize(baselineContext)}</span><br><span style='font-size:0.75rem;color:var(--text-muted)'>${sanitize(flags)}</span></td>`;
                    }
                    tr.onclick = () => openInspector(item, tr);
                    tbody.appendChild(tr);
                }
            }

            function exportCSV() {
                const data = currentTab === 'core' ? coreData : uebaData;
                if (data.length === 0) return alert('No data to export.');
                const headersSet = new Set();
                data.forEach(item => Object.keys(item).forEach(k => headersSet.add(k)));
                const headers = Array.from(headersSet);
                let csv = headers.join(',') + '\n';
                data.forEach(item => {
                    const rowArray = headers.map(h => {
                        let val = item[h];
                        val = (val === null || val === undefined) ? '' : val.toString();
                        return '"' + val.replace(/"/g, '""') + '"';
                    });
                    csv += rowArray.join(',') + '\n';
                });
                const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `IDPSSensor_${currentTab.toUpperCase()}_Export.csv`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
            }

            async function fetchTelemetry() {
                if (isManualMode) return;
                try {
                    const response = await fetch('./api/data');
                    if (!response.ok) throw new Error('API Offline');

                    failCount = 0;
                    const json = await response.json();
                    const newTotal = json.core.length + json.ueba.length;

                    if (newTotal !== totalCount) {
                        coreData = json.core; uebaData = json.ueba; totalCount = newTotal;
                        document.getElementById('count-core').innerText = coreData.length;
                        document.getElementById('count-ueba').innerText = uebaData.length;
                        renderTable();
                    }
                } catch (err) {
                    failCount++;
                    if (failCount >= 15) {
                        document.body.innerHTML = `
                            <div style='display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;background:#0a0e14;color:#c9d1d9;font-family:sans-serif;'>
                                <h1 style='color:#ff4b4b;font-size:2.5rem;margin-bottom:10px;text-transform:uppercase;'>Sensor Offline</h1>
                                <p style='font-size:1.1rem;'>The IDPS Sensor Orchestrator has been terminated.</p>
                                <p style='color:#8b949e; margin-top:20px; font-style:italic;'>Closing tab...</p>
                            </div>
                        `;
                        setTimeout(() => {
                            window.opener = null;
                            window.open('', '_self');
                            window.close();
                        }, 2000);
                    }
                }
            }

            document.getElementById('search').addEventListener('input', renderTable);
            fetchTelemetry();
            setInterval(fetchTelemetry, 2000);
        </script>
    </body>
    </html>
'@

    $RunspaceCode = {
        param($HtmlStr, $EvtLogPath, $UbaLogPath, $RunInBackground, $EphPort, $OtpToken, $HudLogPath)

        # Port + OTP are generated by the caller (main scope) so the URL can be printed to the
        # console as a manual fallback. A [powershell]::BeginInvoke runspace swallows every
        # error, so bind/browser failures are logged to HudLogPath instead of vanishing.
        $BaseUrl = "http://127.0.0.1:$EphPort/"
        $SecureUrl = "$($BaseUrl)$OtpToken/"
        function Write-HudLog([string]$m) { try { "[$(Get-Date -Format o)] $m" | Out-File -FilePath $HudLogPath -Append -Encoding utf8 } catch {} }

        try {
            $Listener = New-Object System.Net.HttpListener
            $Listener.Prefixes.Add($BaseUrl)
            $Listener.Start()
        } catch {
            Write-HudLog "LISTENER BIND FAILED on $BaseUrl : $($_.Exception.GetType().Name): $($_.Exception.Message)"
            return
        }
        Write-HudLog "HUD listening at $SecureUrl"

        if (-not $RunInBackground) {
            # The sensor runs ELEVATED (ETW + anti-tamper ACLs). A plain Start-Process/ShellExecute
            # would launch the browser ELEVATED too, which collides with the user's normal
            # medium-integrity browser session over the Chrome/Edge profile singleton lock and
            # wedges it ("can't navigate until closed/reopened") -- hard-failing under STIG UAC
            # and integrity-level policies. Hand the URL to explorer.exe instead: explorer runs at
            # medium integrity as the interactive user, so the browser opens DE-ELEVATED and fully
            # decoupled from the sensor process.
            try { Start-Process -FilePath "explorer.exe" -ArgumentList $SecureUrl } catch {
                Write-HudLog "Browser launch via explorer.exe FAILED for $SecureUrl : $($_.Exception.Message)"
            }
        }

        $LastHit = Get-Date
        while ($Listener.IsListening) {
            $ContextAsync = $Listener.BeginGetContext($null, $null)
            $WaitResult = $false

            while (-not $WaitResult) {
                $WaitResult = $ContextAsync.AsyncWaitHandle.WaitOne(2000)
                if (-not $WaitResult -and ((Get-Date) - $LastHit).TotalSeconds -gt 300) {
                    $Listener.Stop()
                    return
                }
            }

            $Context = $Listener.EndGetContext($ContextAsync)
            $LastHit = Get-Date

            $Req = $Context.Request
            $Res = $Context.Response

            if (-not $Req.Url.LocalPath.StartsWith("/$OtpToken")) {
                $Res.StatusCode = 403; $Res.Close(); continue
            }

            $ReqPath = $Req.Url.LocalPath.Replace("/$OtpToken", "")
            if ($ReqPath -eq "") { $ReqPath = "/" }

            $Res.Headers.Add("X-Frame-Options", "DENY")
            $Res.Headers.Add("X-Content-Type-Options", "nosniff")
            $Res.Headers.Add("Cache-Control", "no-store, max-age=0")

            if ($ReqPath -eq "/") {
                $Buffer = [System.Text.Encoding]::UTF8.GetBytes($HtmlStr)
                $Res.ContentType = "text/html; charset=utf-8"
                $Res.ContentLength64 = $Buffer.Length
                $Res.OutputStream.Write($Buffer, 0, $Buffer.Length)
            }
            elseif ($ReqPath -eq "/api/data") {
                $Payload = @{
                    Core = [System.Collections.Generic.List[string]]::new()
                    Ueba = [System.Collections.Generic.List[string]]::new()
                }
                foreach ($Log in @{Core=$EvtLogPath; Ueba=$UbaLogPath}.GetEnumerator()) {
                    if (Test-Path $Log.Value) {
                        $fs = $null; $sr = $null
                        try {
                            $fs = New-Object System.IO.FileStream($Log.Value, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)

                            if ($fs.Length -gt 100000) { $fs.Position = $fs.Length - 100000 }

                            $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8)
                            if ($fs.Position -gt 0) { $null = $sr.ReadLine() }

                            while (-not $sr.EndOfStream) {
                                $line = $sr.ReadLine().Trim()
                                if ($line.StartsWith("{") -and $line.EndsWith("}")) {
                                    try {
                                        $null = $line | ConvertFrom-Json -ErrorAction Stop
                                        $Payload[$Log.Key].Add($line)
                                    } catch { }
                                }
                            }

                            if ($Payload[$Log.Key].Count -gt 250) {
                                $startIndex = $Payload[$Log.Key].Count - 250
                                $Payload[$Log.Key] = $Payload[$Log.Key].GetRange($startIndex, 250)
                            }
                        } catch {
                        } finally {
                            if ($null -ne $sr) { $sr.Dispose() }
                            if ($null -ne $fs) { $fs.Dispose() }
                        }
                    }
                }
                $JsonData = "{ `"core`": [" + ($Payload.Core -join ",") + "], `"ueba`": [" + ($Payload.Ueba -join ",") + "] }"
                $Buffer = [System.Text.Encoding]::UTF8.GetBytes($JsonData)
                $Res.ContentType = "application/json"
                $Res.ContentLength64 = $Buffer.Length
                $Res.OutputStream.Write($Buffer, 0, $Buffer.Length)
            }
            else { $Res.StatusCode = 404 }
            $Res.Close()
        }
    }

    # Generate the port + OTP here (main scope) so the URL is known to the console, not buried
    # inside the async runspace. This gives the operator a clickable fallback if the browser
    # auto-launch is blocked (Session 0, AV shim on child pwsh, default-browser race, etc.).
    $EphPort   = Get-Random -Minimum 49152 -Maximum 65535
    $OtpToken  = [guid]::NewGuid().ToString("N")
    $SecureUrl = "http://127.0.0.1:$EphPort/$OtpToken/"
    $HudLogPath = Join-Path $env:ProgramData "IDPSSensor\Logs\HUD.log"
    Write-Diag "    [*] Live Browser HUD: $SecureUrl" "STARTUP"

    $PS = [powershell]::Create().AddScript($RunspaceCode).AddArgument($HtmlPayload).AddArgument($EvtPath).AddArgument($UbaPath).AddArgument($Background).AddArgument($EphPort).AddArgument($OtpToken).AddArgument($HudLogPath)
    $global:HudRunspace = $PS
    $PS.BeginInvoke() | Out-Null

    # BeginInvoke swallows runspace errors; give it a beat and surface any that landed early.
    Start-Sleep -Milliseconds 400
    if ($PS.Streams.Error.Count -gt 0) {
        foreach ($hudErr in $PS.Streams.Error) { Write-Diag "    [!] HUD runspace error: $hudErr" "STARTUP" }
    }
}

function Initialize-Cooldown {
    $ESC = [char]27
    $cGreen     = "$ESC[38;2;57;255;20m"
    $cDarkGreen = "$ESC[38;2;15;90;10m"
    $cReset     = "$ESC[0m"

    $cursor = "█"

    foreach ($char in "Call trans opt: received. 2-19-98 13:24:18 REC:Loc".ToCharArray()) {
        Write-Host "$cGreen$char" -NoNewline
        Write-Host "$cDarkGreen$cursor" -NoNewline
        Start-Sleep -Milliseconds 60
        Write-Host "`b `b" -NoNewline
    }
    Write-Host ""
    Start-Sleep -Milliseconds 1200

    foreach ($char in "Trace program: running".ToCharArray()) {
        Write-Host "$cGreen$char" -NoNewline
        Write-Host "$cDarkGreen$cursor" -NoNewline
        Start-Sleep -Milliseconds 60
        Write-Host "`b `b" -NoNewline
    }
    Write-Host "`n"
    Start-Sleep -Milliseconds 2400

    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()

    $matrixStart = Get-Date
    $width = [Console]::WindowWidth - 2
    $floorY = 35
    $startY = [Console]::CursorTop + 1

    if ($startY -ge $floorY - 5) { $startY = 15 }

    $columns = @(0) * $width
    Write-Host "$ESC[?25l" -NoNewline

    while (((Get-Date) - $matrixStart).TotalSeconds -lt 20) {
        for ($i = 0; $i -lt $width; $i++) {
            if ($columns[$i] -eq 0 -and (Get-Random -Maximum 100) -gt 97) {
                $columns[$i] = 1
            }

            if ($columns[$i] -gt 0) {
                $y = $startY + $columns[$i]

                if ($y -lt $floorY) {
                    [Console]::SetCursorPosition($i, $y)
                    Write-Host "$cGreen$([char](Get-Random -Minimum 33 -Maximum 126))" -NoNewline

                    if ($y -gt $startY + 1) {
                        [Console]::SetCursorPosition($i, $y - 1)
                        Write-Host "$cDarkGreen$([char](Get-Random -Minimum 33 -Maximum 126))" -NoNewline
                    }

                    if ($y -gt $startY + 6) {
                        [Console]::SetCursorPosition($i, $y - 6)
                        Write-Host " " -NoNewline
                    }
                    $columns[$i]++
                } else {
                    for ($t = 0; $t -lt 7; $t++) {
                        $tailY = $y - $t
                        if ($tailY -ge $startY -and $tailY -lt $floorY) {
                            [Console]::SetCursorPosition($i, $tailY)
                            Write-Host " " -NoNewline
                        }
                    }
                    $columns[$i] = 0
                }
            }
        }
        Start-Sleep -Milliseconds 40
    }

    # --- CLEANUP VIEWPORT ---
    for ($y = 0; $y -lt 36; $y++) {
        [Console]::SetCursorPosition(0, $y)
        Write-Host (" " * $width) -NoNewline
    }

    Write-Host "$ESC[?25h$cReset" -NoNewline
    [Console]::SetCursorPosition(0, 0)
}

# ====================== HELPER UTILITIES & DIAGNOSTICS ======================

$log2 = [Math]::Log(2)
$Regex_NonDigit = [regex]::new('[^0-9]', 'Compiled')
$vowels = [System.Collections.Generic.HashSet[char]]::new([char[]]"aeiou")

function Write-Diag {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "FFI-TX", "FFI-RX", "MATH", "STARTUP", "CRITICAL", "C#-ENGINE")]
        [string]$Level = "INFO"
    )
    if (-not $global:EnableDiagnostics -and $Level -notin @("ERROR", "WARN", "CRITICAL", "STARTUP")) { return }

    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    # Flush each write: diagnostics are sparse, and an unflushed StreamWriter loses event-loop
    # entries (incl. ETW hotpath errors) on crash and hides them from live tailing.
    try { $global:DiagWriter.WriteLine("[$ts] [$Level] $Message"); $global:DiagWriter.Flush() } catch {}

    if ($Level -eq "STARTUP") {
        $global:StartupLogs.Add($Message)
        Draw-StartupWindow
    }
}

function Get-Entropy([string]$inputString) {
    if ([string]::IsNullOrEmpty($inputString)) { return 0.0 }
    $charCounts = @{}; foreach ($c in $inputString.ToCharArray()) { $charCounts[$c]++ }
    $entropy = 0.0; $len = $inputString.Length
    foreach ($count in $charCounts.Values) {
        $p = $count / $len; $entropy -= $p * ([Math]::Log($p) / $log2)
    }
    return $entropy
}

function Is-AnomalousDomain([string]$domain) {
    if ([string]::IsNullOrEmpty($domain)) { return $false }
    if ($domain.Length -gt 35) { return $true }
    $digits = $Regex_NonDigit.Replace($domain, "").Length
    if (($digits / $domain.Length) -gt 0.45) { return $true }
    $vowelCount = 0
    foreach ($char in $domain.ToLower().ToCharArray()) { if ($vowels.Contains($char)) { $vowelCount++ } }
    if (($vowelCount / $domain.Length) -lt 0.15) { return $true }
    return (Get-Entropy $domain) -gt 3.8
}

function Invoke-Download([string]$Uri, [string]$OutFile, [string]$FileName) {
    $ESC = [char]27
    $cGreen = "$ESC[38;2;57;255;20m"
    $cDark  = "$ESC[38;2;30;30;30m"
    $cCyan  = "$ESC[38;2;0;255;255m"
    $cYellow = "$ESC[38;2;255;255;51m"
    $cReset = "$ESC[0m"

    $cClear = "$ESC[2K`r"

    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
        $req = [System.Net.WebRequest]::Create($Uri)
        $req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        $res = $req.GetResponse()
        $stream = $res.GetResponseStream()
        $target = [System.IO.File]::Create($OutFile)
        $buffer = New-Object byte[] 8192
        $totalBytes = $res.ContentLength
        $totalRead = 0
        $width = 40

        $padName = $FileName.PadRight(25).Substring(0, 25)

        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $totalRead += $read
            $target.Write($buffer, 0, $read)

            if ($totalBytes -gt 0) {
                $percent = $totalRead / $totalBytes
                $filled = [int][Math]::Floor($percent * $width)
                $empty = $width - $filled
                $bar = ($cGreen + ("█" * $filled)) + ($cDark + ("█" * $empty))
                $pctStr = "{0:N0}%" -f ($percent * 100)

                Write-Host "${cClear}      $cCyan$padName$cReset [$bar$cReset] $cGreen$($pctStr.PadLeft(4))$cReset" -NoNewline
            } else {
                Write-Host "${cClear}      $cCyan$padName$cReset $cYellow$totalRead bytes downloaded...$cReset" -NoNewline
            }
        }

        Start-Sleep -Milliseconds 150

    } catch {
        throw $_
    } finally {
        if ($target) { $target.Dispose() }
        if ($stream) { $stream.Dispose() }
        if ($res) { $res.Dispose() }

        Write-Host $cClear -NoNewline
    }
}

Write-Diag "=== IDPS SENSOR DIAGNOSTIC LOG INITIALIZED ===" "STARTUP"
Write-Diag "Host: $env:COMPUTERNAME | PS Version: $($PSVersionTable.PSVersion.ToString())" "STARTUP"

if ($ArmedMode) {
    Write-Diag "    [*] SENSOR BOOTING IN ARMED MODE: ACTIVE DEFENSE ENABLED" "STARTUP"
} else {
    Write-Diag "    [*] SENSOR BOOTING IN AUDIT MODE: OBSERVATION ONLY" "STARTUP"
}

# ====================== INITIALIZATION & PRE-FLIGHT ======================

if (Test-Path $DiagLogPath) { Remove-Item -Path $DiagLogPath -Force -ErrorAction SilentlyContinue }

try {
    $global:DiagStream = [System.IO.File]::Open($DiagLogPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    $global:DiagWriter = New-Object System.IO.StreamWriter($global:DiagStream)
    $global:DiagWriter.AutoFlush = $true
} catch {
    Get-Process powershell, pwsh -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $PID } | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    $global:DiagStream = [System.IO.File]::Open($DiagLogPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    $global:DiagWriter = New-Object System.IO.StreamWriter($global:DiagStream)
    $global:DiagWriter.AutoFlush = $true
}

function Initialize-TamperGuard {
    try {
        if (-not (Test-Path $TamperLogPath)) { New-Item $TamperLogPath -ItemType File -Force -ErrorAction SilentlyContinue | Out-Null }
        $global:TamperStream = [System.IO.File]::Open($TamperLogPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        $global:TamperWriter = New-Object System.IO.StreamWriter($global:TamperStream)
        $global:TamperWriter.AutoFlush = $true
    } catch {
        Get-Process powershell, pwsh -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $PID } | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        try {
            $global:TamperStream = [System.IO.File]::Open($TamperLogPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
            $global:TamperWriter = New-Object System.IO.StreamWriter($global:TamperStream)
            $global:TamperWriter.AutoFlush = $true
        } catch { $global:TamperWriter = $null }
    }
}

function Lock-SecureDirectory([string]$Path) {
    if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }

    $acl = Get-Acl $Path
    $acl.SetAccessRuleProtection($true, $false)
    $sysRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($sysRule)
    $acl.AddAccessRule($adminRule)
    Set-Acl -Path $Path -AclObject $acl
}

function Lockdown-ProjectDir {
    # Complete Directory Anti-Tamper Lockdown
    $IDPSRootPath = "C:\ProgramData\IDPSSensor"
    Write-Diag "Applying strict Anti-Tamper ACLs to $IDPSRootPath..." "STARTUP"

    try {
        # Ensure the root exists before locking it
        if (-not (Test-Path $IDPSRootPath)) { New-Item -ItemType Directory -Path $IDPSRootPath -Force | Out-Null }

        $acl = Get-Acl -Path $IDPSRootPath

        # Block inheritance and wipe existing inherited rules from the C:\ drive
        $acl.SetAccessRuleProtection($true, $false)

        $inheritParams = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
        $propagationParams = [System.Security.AccessControl.PropagationFlags]::None

        $systemSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
        $adminSid  = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User

        # Re-apply explicit FullControl to authorized accounts only
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid, "FullControl", $inheritParams, $propagationParams, "Allow")))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($adminSid, "FullControl", $inheritParams, $propagationParams, "Allow")))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, "FullControl", $inheritParams, $propagationParams, "Allow")))

        Set-Acl -Path $IDPSRootPath -AclObject $acl
        Write-Diag "    [*] Anti-Tamper vault sealed successfully." "STARTUP"
    } catch {
        Write-Host "`n[!] CRITICAL WARNING: Directory ACL lockdown failed. $($_.Exception.Message)" -ForegroundColor Red
        Write-Diag "Directory ACL lockdown failed: $($_.Exception.Message)" "ERROR"
    }
}

# ====================== NETWORK THREAT INTEL COMPILER ======================

function Initialize-JA3 {
    $global:MaliciousJA3Cache = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $Ja3CacheAgeHours = 24
    $needsJa3Download = $true

    if (Test-Path $Ja3CachePath) {
        $age = ((Get-Date) - (Get-Item $Ja3CachePath).LastWriteTime).TotalHours
        if ($age -lt $Ja3CacheAgeHours) {
            $needsJa3Download = $false
        }
    }

    if ($needsJa3Download) {
        Write-Diag "Fetching latest JA3 Fingerprints from abuse.ch SSLBL..." "STARTUP"
        try {
            $TempCsv = Join-Path $StagingDir "ja3_fingerprints.csv"

            Invoke-Download -Uri "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv" -OutFile $TempCsv -FileName "Abuse.ch JA3"

            $hashes = [System.Collections.Generic.List[string]]::new()

            $csvLines = Get-Content -Path $TempCsv -ErrorAction Stop

            foreach ($line in $csvLines) {
                if ($line -match "^([a-fA-F0-9]{32}),") {
                    $hashes.Add($matches[1].ToLower())
                }
            }

            if ($hashes.Count -gt 0) {
                $hashes | ConvertTo-Json -Compress | Out-File -FilePath $Ja3CachePath -Encoding UTF8 -Force
                Write-Diag "    [*] Successfully synced $($hashes.Count) JA3 signatures from abuse.ch." "STARTUP"
            }

            Remove-Item $TempCsv -Force -ErrorAction SilentlyContinue
        } catch {
            $err = $_.Exception.Message
            Write-Diag "    [!] Failed to pull JA3 from abuse.ch: $err" "WARN"
        }
    }

    # Load the Cache into the O(1) HashSet
    if (Test-Path $Ja3CachePath) {
        try {
            $cachedJa3 = Get-Content $Ja3CachePath -Raw | ConvertFrom-Json
            foreach ($hash in $cachedJa3) { [void]$global:MaliciousJA3Cache.Add($hash) }
            Write-Diag "    [+] Loaded $($global:MaliciousJA3Cache.Count) JA3 signatures from dynamic Threat Intel cache." "STARTUP"
        } catch { Write-Diag "  [!] Failed to parse JA3 JSON cache. Falling back to offline defaults." "WARN" }
    }

    # Fallback to Hardcoded Offline Signatures
    if ($global:MaliciousJA3Cache.Count -eq 0) {
        $offlineDefaults = @(
            "a0e9f5d64349fb13191bc781f81f42e1", # Metasploit / MSFVenom
            "b32309a26951912be7dba376398abc3b", # Cobalt Strike (Common Profile 1)
            "eb88d0b3e1961a0562f006e5ce2a0b87", # Cobalt Strike (Malleable C2 Default)
            "1ce21ed04b6d4128f7fb6b22b0c36cb1", # Cobalt Strike (Common Profile 3)
            "ee031b874122d97ab269e0d8740be31a", # Metasploit HeartBleed/TLS Scanner
            "51c64c77e60f3980eea90869b68c58a8", # Sliver / Standard Go HTTP/TLS Client
            "e0a786fa0d151121d51f2249e49195b0", # Merlin C2
            "d891b0c034919cb44f128e4e97aeb7e6", # Havoc C2 Default
            "771c93a02bb801fbdbb13b73bcba0d6b", # Empire / Python Requests Default
            "cd08e31494f9531f560d64c695473da9", # Mythic / Generic Python Default
            "3b5074b1b5d032e5620f69f9f700ff0e", # Pupy RAT
            "8f199859f1f0e4b7ba29e3ddc6ee9b71", # Covenant Grunt / Standard .NET WebClient
            "6d89b37a488e0b6dfde0c59828e8331b", # Remcos RAT
            "08ef1bdcbdbba6ce64daec0ab2ea0bc1", # NanoCore RAT
            "2707bb320ebbb6d0c64d8a5decc81b53", # Trickbot
            "4d7a28d6f2263ed61de88ca66eb011e3", # Emotet
            "18f152d0b50302ffab23fc47545de999", # IcedID
            "3f4b4ce6edbc8537fc2ea22a009fb74d", # Qakbot
            "c45d36e2fde376eec6a382b6c31e67b2", # Brute Ratel C4 (Default Config)
            "518b7eb09de4e10173bc51c1ff76b2c2", # Dridex
            "e7d705a3286e19ea42f587b344ee6865", # Malicious C2 Profile
            "4d7a28d5f652494751259342149a1222", # Malicious C2 Profile
            "6734f37431670b3ab4292b8f60f29984", # Malicious C2 Profile
            "6268c6b7a55651e83568134465714412", # Malicious C2 Profile
            "e20c5952f6424433577a639ab2459f83"  # Malicious C2 Profile
        )
        foreach ($hash in $offlineDefaults) { [void]$global:MaliciousJA3Cache.Add($hash) }
        Write-Diag "    [+] Loaded $($global:MaliciousJA3Cache.Count) default offline JA3 signatures." "STARTUP"
    }
}

function Initialize-NetworkThreatIntel {
    Write-Diag "Initializing Network Threat Intelligence (Suricata)..." "STARTUP"

    $MaliciousIps = [System.Collections.Generic.List[uint32]]::new()
    $MaliciousDomains = [System.Collections.Generic.List[uint64]]::new()
    $TiContext = [System.Collections.Generic.Dictionary[string, string]]::new()

    # Cache marker file – if it exists and is < 24h old, skip the download
    $CacheMarker = Join-Path $ScriptDir "threatintel.cache"
    $CacheAgeHours = 24
    $needsDownload = $true

    if (Test-Path $CacheMarker) {
        $age = ((Get-Date) - (Get-Item $CacheMarker).LastWriteTime).TotalHours
        if ($age -lt $CacheAgeHours) {
            $needsDownload = $false
            Write-Diag "    [*] Using cached Threat Intel (rules < $CacheAgeHours hours old)" "STARTUP"
        }
    }

    $SuricataBaseDir = Join-Path $ScriptDir "suricata"
    $SuricataUpstreamDir = Join-Path $SuricataBaseDir "upstream"

    if ($needsDownload -or -not (Test-Path $SuricataUpstreamDir)) {
        if (-not (Test-Path $SuricataUpstreamDir)) {
            New-Item -ItemType Directory -Path $SuricataUpstreamDir -Force | Out-Null
        }

        $SuricataUrls = @(
            # These files contain high-density lists of malicious subnets and C2 nodes.
            @{ Name = "ET_BotCC"; Url = "https://rules.emergingthreats.net/blockrules/emerging-botcc.rules" },
            @{ Name = "ET_Compromised"; Url = "https://rules.emergingthreats.net/blockrules/emerging-compromised.rules" },
            @{ Name = "ET_Drop"; Url = "https://rules.emergingthreats.net/blockrules/emerging-drop.rules" },
            @{ Name = "ET_DShield"; Url = "https://rules.emergingthreats.net/blockrules/emerging-dshield.rules" },
            @{ Name = "ET_Tor"; Url = "https://rules.emergingthreats.net/blockrules/emerging-tor.rules" },
            # Essential for intercepting machine-generated domains and C2 tunneling.
            @{ Name = "ET_DNS"; Url = "https://rules.emergingthreats.net/open/suricata-8.0/rules/emerging-dns.rules" },
            # --- Specialized Adversary Infrastructure ---
            @{ Name = "AbuseCH_FeodoTracker"; Url = "https://feodotracker.abuse.ch/downloads/feodotracker.rules" },
            @{ Name = "AbuseCH_ThreatFox"; Url = "https://threatfox.abuse.ch/downloads/threatfox_suricata.rules" }
        )

        foreach ($src in $SuricataUrls) {
            $OutPath = Join-Path $SuricataUpstreamDir "$($src.Name).rules"
            try {
                Invoke-Download -Uri $src.Url -OutFile $OutPath -FileName $src.Name
            } catch {
                $err = $_.Exception.Message
                Write-Diag "  [!] Failed to sync $($src.Name): $err" "WARN"
            }
        }
    }

    $SuricataFiles = Get-ChildItem -Path $SuricataBaseDir -Filter "*.rules" -Recurse
    $suricataCount = 0

    foreach ($file in $SuricataFiles) {
        try {
            $rules = Get-Content $file.FullName
            foreach ($line in $rules) {
                if ($line -match '^alert' -and $line -match 'msg:\s*"([^"]+)"') {
                    $msg = $matches[1]
                    $NoisyIps = @("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9")

                    # --- SURICATA HEADER IP EXTRACTION ---
                    if ($line -match '->\s+\[?([0-9\.,]+)\]?\s+') {
                        $destIps = $matches[1] -split ','
                        foreach ($ip in $destIps) {
                             if ($ip -match "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$" -and $ip -notin $NoisyIps) {
                                 $ipInt = [PSMathHelpers]::IpToUint($ip)
                                 if ($ipInt -ne 0 -and -not $MaliciousIps.Contains($ipInt)) {
                                     $MaliciousIps.Add($ipInt)
                                     $TiContext[$ip] = "Suricata: $msg"
                                     $suricataCount++
                                 }
                             }
                        }
                    }

                    # --- SURICATA STRICT CONTENT PARSING ---
                    $contents = [regex]::Matches($line, 'content:\s*"([^"]+)"')
                    foreach ($c in $contents) {
                        $val = $c.Groups[1].Value.ToLower()
                        $val = ($val -replace '\|[0-9a-fA-F]{2}\|', '.') -replace '^\.+|\.+$', ''

                        if ($val -in $NoisyIps) { continue }

                        # IGNORE SAFE DOMAINS (Prevents DPI rules from banning legitimate tech infra)
                        $SafeDomains = @(
                            "google.com", "bing.com", "yahoo.com", "microsoft.com", "windows.com",
                            "adobe.com", "github.com", "apple.com", "ubuntu.com", "mozilla.org",
                            "cloudflare.com", "amazon.com", "aws.amazon.com", "office.com",
                            "localhost", "localdomain", "example.com"
                        )
                        $isSafe = $false
                        foreach ($safe in $SafeDomains) {
                            if ($val -eq $safe -or $val.EndsWith(".$safe")) { $isSafe = $true; break }
                        }
                        if ($isSafe) { continue }

                        # STRICT VALIDATION: Only allow valid IPv4 or FQDNs.
                        $isIp = $val -match "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
                        $isDomain = $val -match "^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$"

                        if ($isIp) {
                            $ipInt = [PSMathHelpers]::IpToUint($val)
                            if ($ipInt -ne 0 -and -not $MaliciousIps.Contains($ipInt)) {
                                $MaliciousIps.Add($ipInt)
                                $TiContext[$val] = "Suricata: $msg"
                                $suricataCount++
                            }
                        } elseif ($isDomain) {
                            $cleanVal = $val
                            if (-not $cleanVal.StartsWith(".")) { $cleanVal = ".$cleanVal" }
                            $domHash = [PSMathHelpers]::HashDomain($cleanVal)
                            if ($domHash -ne 0 -and -not $MaliciousDomains.Contains($domHash)) {
                                $MaliciousDomains.Add($domHash)
                                $TiContext[$cleanVal] = "Suricata: $msg"
                                $suricataCount++
                            }
                        }
                    }
                }
            }
        } catch { Write-Diag "  [!] Failed to parse custom rule file: $($file.Name)" "WARN" }
    }
    Write-Diag "    [*] Gatekeeper Compilation: Parsed $suricataCount signatures from Suricata." "STARTUP"

    $FlatFiles = Get-ChildItem -Path $SuricataBaseDir -Include "*.txt", "*.list" -Recurse
    $flatCount = 0

    foreach ($file in $FlatFiles) {
        try {
            $lines = Get-Content $file.FullName
            foreach ($line in $lines) {
                # Strip inline comments and trim whitespace
                $entry = ($line -split '#')[0].Trim()
                if ([string]::IsNullOrWhiteSpace($entry)) { continue }

                # Gatekeeper check: Only inject valid IPv4 or Domains
                $isIp = $entry -match "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
                $isDomain = $entry -match "^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$"

                if ($isIp) {
                    $ipInt = [PSMathHelpers]::IpToUint($entry)
                    if ($ipInt -ne 0 -and -not $MaliciousIps.Contains($ipInt)) {
                        $MaliciousIps.Add($ipInt)
                        $TiContext[$entry] = "Flat-File Intel: $($file.Name)"
                        $flatCount++
                    }
                } elseif ($isDomain) {
                    $cleanVal = $entry
                    if (-not $cleanVal.StartsWith(".")) { $cleanVal = ".$cleanVal" }
                    $domHash = [PSMathHelpers]::HashDomain($cleanVal)
                    if ($domHash -ne 0 -and -not $MaliciousDomains.Contains($domHash)) {
                        $MaliciousDomains.Add($domHash)
                        $TiContext[$cleanVal] = "Flat-File Intel: $($file.Name)"
                        $flatCount++
                    }
                }
            }
        } catch { Write-Diag "  [!] Failed to parse flat file: $($file.Name)" "WARN" }
    }
    Write-Diag "    [+] Flat-File Compilation: Injected $flatCount raw indicators into memory." "STARTUP"
    New-Item -Path $CacheMarker -ItemType File -Force | Out-Null
    Write-Diag "    [*] Threat Intel Compilation Complete. Passing $(($MaliciousIps.Count + $MaliciousDomains.Count)) signatures to Memory." "STARTUP"

    # Sort arrays to enable O(log N) Binary Search in C#
    $MaliciousIps.Sort()
    $MaliciousDomains.Sort()

    # Output the compiled signatures to disk for auditing
    $TiContext.Keys | Out-File "$LogDir\Compiled_ThreatIntel.txt"

    return @{
        CompiledIps = $MaliciousIps.ToArray()
        CompiledDomains = $MaliciousDomains.ToArray()
        TiContext = $TiContext
    }
}

# ====================== ACTIVE DEFENSE ENGINE ======================
# A single Suricata/TI rule hit can be a false positive (broad ET rules, noisy signatures).
# Require either an unambiguous high-confidence signal (exact hash/JA3/TI match) or a second
# corroborating alert for the same actor (PID) within the window before a block/kill fires.
$global:ActiveDefenseActorTally = @{}
$ActiveDefenseWindowSec = 300
$ActiveDefenseAutoActConfidence = 100

function Test-RepeatActor([string]$ActorKey) {
    if (-not $ActorKey) { return $false }
    $now = Get-Date
    $hadPrior = $false
    if ($global:ActiveDefenseActorTally.ContainsKey($ActorKey)) {
        $tally = $global:ActiveDefenseActorTally[$ActorKey]
        if (($now - $tally.FirstSeen).TotalSeconds -le $ActiveDefenseWindowSec) {
            $hadPrior = $true
            $tally.Count++
        } else {
            $global:ActiveDefenseActorTally[$ActorKey] = [pscustomobject]@{ Count = 1; FirstSeen = $now }
        }
    } else {
        $global:ActiveDefenseActorTally[$ActorKey] = [pscustomobject]@{ Count = 1; FirstSeen = $now }
    }
    return $hadPrior
}

# PowerShell-native artifact correlation (no Rust FFI dependency -- idps isn't hitting the
# AMSI heuristics that forced EDR's native_defense.rs migration, so WMI/Authenticode is fine).
function Get-OnDiskArtifacts([int]$ProcId) {
    $a = [ordered]@{
        ImagePath = "Unknown"; ImageSHA256 = ""; ImageSignature = "Unknown"
        CommandLine = ""; ParentPID = 0; ParentImage = ""
        LoadedModules = @(); Persistence = @()
    }
    if ($ProcId -le 0) { return $a }

    try {
        $wmi = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcId" -ErrorAction Stop
        if ($wmi) {
            $a.CommandLine = "$($wmi.CommandLine)"
            $a.ImagePath   = "$($wmi.ExecutablePath)"
            $a.ParentPID   = [int]$wmi.ParentProcessId
            try {
                $parentWmi = Get-CimInstance Win32_Process -Filter "ProcessId = $($wmi.ParentProcessId)" -ErrorAction Stop
                if ($parentWmi) { $a.ParentImage = "$($parentWmi.ExecutablePath)" }
            } catch {}
        }
    } catch {}

    try { $a.LoadedModules = @((Get-Process -Id $ProcId -ErrorAction Stop).Modules | ForEach-Object { $_.ModuleName }) } catch {}

    if ($a.ImagePath -and $a.ImagePath -ne "Unknown" -and (Test-Path $a.ImagePath -ErrorAction SilentlyContinue)) {
        try { $a.ImageSignature = "$((Get-AuthenticodeSignature -FilePath $a.ImagePath -ErrorAction Stop).Status)" } catch {}
        try { $a.ImageSHA256 = (Get-FileHash -Path $a.ImagePath -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}

        $procFileName = [System.IO.Path]::GetFileName($a.ImagePath)
        $persistHits = [System.Collections.Generic.List[string]]::new()
        foreach ($runKey in @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        )) {
            try {
                $props = Get-ItemProperty -Path $runKey -ErrorAction Stop
                foreach ($p in $props.PSObject.Properties) {
                    if ($p.Value -is [string] -and $p.Value -match [regex]::Escape($procFileName)) {
                        $persistHits.Add("Run:$runKey\$($p.Name)")
                    }
                }
            } catch {}
        }
        try {
            Get-CimInstance Win32_Service -Filter "PathName like '%$procFileName%'" -ErrorAction Stop |
                ForEach-Object { $persistHits.Add("Service:$($_.Name)") }
        } catch {}
        $a.Persistence = @($persistHits)
    }
    return $a
}

function Write-ForensicLedgerEntry {
    param(
        [string]$ReportId, [string]$ProcName, [int]$PidId, [string]$DestIp,
        [int]$Confidence, [string]$Reason, [string]$Action, $Artifacts
    )
    try {
        $ReportDir = "C:\ProgramData\IDPSSensor\Data\Reports"
        if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }
        $IncidentReport = [ordered]@{
            IncidentID = $ReportId
            Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Process = $ProcName; PID = $PidId; Destination = $DestIp
            Confidence = $Confidence; TriggerReason = $Reason; ActionTaken = $Action
            OnDiskArtifacts = $Artifacts
        }
        $IncidentReport | ConvertTo-Json -Depth 6 | Out-File "$ReportDir\Incident_${ReportId}.json"

        $LedgerPath = "C:\ProgramData\IDPSSensor\Data\ArmedMode_ForensicLedger.jsonl"
        $ledgerEntry = [ordered]@{
            Timestamp      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            IncidentID     = $ReportId
            Process        = $ProcName
            PID            = $PidId
            Destination    = $DestIp
            Confidence     = $Confidence
            ActionTaken    = $Action
            TriggerReason  = $Reason
            ImagePath      = $Artifacts.ImagePath
            ImageSHA256    = $Artifacts.ImageSHA256
            ImageSignature = $Artifacts.ImageSignature
            ParentPID      = $Artifacts.ParentPID
            ParentImage    = $Artifacts.ParentImage
            LoadedModules  = $Artifacts.LoadedModules
            Persistence    = $Artifacts.Persistence
        }
        ($ledgerEntry | ConvertTo-Json -Depth 6 -Compress) | Add-Content -Path $LedgerPath -Encoding utf8
    } catch { Write-Diag -Message "[ACTIVE DEFENSE] Failed to append forensic ledger: $($_.Exception.Message)" -Level "WARN" }
}

function Invoke-ActiveDefense($ProcName, $DestIp, $Confidence, $Reason, [int]$PID_Id = 0) {
    if (-not $global:IsArmed -or $Confidence -lt $ConfidenceThreshold) { return }

    $actorKey = if ($PID_Id -gt 0) { "$PID_Id" } else { $ProcName }
    $hadPriorAlert = Test-RepeatActor $actorKey
    $justified = ($Confidence -ge $ActiveDefenseAutoActConfidence) -or $hadPriorAlert

    $onDiskArtifacts = Get-OnDiskArtifacts $PID_Id
    $ReportId = [guid]::NewGuid().ToString().Substring(0, 8)

    if (-not $justified) {
        Write-Diag -Message "[ACTIVE DEFENSE] $ProcName (PID $PID_Id) held pending corroboration -- single alert, Confidence=$Confidence, no prior actor activity in window." -Level "WARN"
        Write-ForensicLedgerEntry -ReportId $ReportId -ProcName $ProcName -PidId $PID_Id -DestIp $DestIp -Confidence $Confidence -Reason $Reason -Action "Held_PendingCorroboration" -Artifacts $onDiskArtifacts
        return
    }

    $mitigationStatus = "Failed"
    if ($ProcName -and $ProcName -notmatch "Unknown|System|Idle|Terminated") {
        Get-Process -Name $ProcName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        if (-not (Get-Process -Name $ProcName -ErrorAction SilentlyContinue)) {
            $mitigationStatus = "Terminated"
            $global:TotalMitigations++
        }
    }

    $blockStatus = ""
    if ($DestIp -match '^\d+\.\d+\.\d+\.\d+$') {
        $ruleName = "IDPS_Defend_Block_$DestIp"

        # Check if rule already exists (prevents bloat)
        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if (-not $existingRule) {
            netsh advfirewall firewall add rule `
                name=$ruleName `
                dir=out `
                action=block `
                remoteip=$DestIp `
                protocol=any `
                description="IDPSSensor Auto-Block - Confidence $Confidence - $Reason" | Out-Null

            $blockStatus = " | IP Blocked (new rule)"
            $global:TotalMitigations++
        }
        else {
            $blockStatus = " | IP Already Blocked"
        }
    }

    # PID-scoped process block -- stops this specific binary from further network activity in
    # BOTH directions. Unlike C2 (outbound-only beaconing), IDPS watches bi-directional traffic,
    # so an attacker reaching IN to a listening service needs an inbound block too.
    $procBlockStatus = ""
    if ($onDiskArtifacts.ImagePath -and $onDiskArtifacts.ImagePath -ne "Unknown" -and (Test-Path $onDiskArtifacts.ImagePath -ErrorAction SilentlyContinue)) {
        try {
            $tag = [guid]::NewGuid().ToString("N").Substring(0, 8)
            New-NetFirewallRule -DisplayName "IDPS_Defend_PID_${PID_Id}_${tag}_Out" -Direction Outbound -Action Block -Program $onDiskArtifacts.ImagePath -ErrorAction Stop | Out-Null
            New-NetFirewallRule -DisplayName "IDPS_Defend_PID_${PID_Id}_${tag}_In"  -Direction Inbound  -Action Block -Program $onDiskArtifacts.ImagePath -ErrorAction Stop | Out-Null
            $procBlockStatus = " | Process Network-Blocked Both Directions ($($onDiskArtifacts.ImagePath))"
            $global:TotalMitigations++
        } catch { Write-Diag -Message "[ACTIVE DEFENSE ERROR] Failed to create process-scoped firewall rule: $($_.Exception.Message)" -Level "WARN" }
    }

    Write-ForensicLedgerEntry -ReportId $ReportId -ProcName $ProcName -PidId $PID_Id -DestIp $DestIp -Confidence $Confidence -Reason $Reason -Action "$mitigationStatus$blockStatus$procBlockStatus" -Artifacts $onDiskArtifacts

    $targetStr = if ($DestIp) { "$ProcName -> $DestIp" } else { "$ProcName" }
    Add-AlertMessage "DEFENSE: $mitigationStatus$blockStatus$procBlockStatus ($targetStr)" $cYellow
}

# --- UEBA BASELINING ENGINE ---
function Log-UebaBaseline([string]$RawJson, [string]$Context, [string]$Direction = "Local") {
    if ([string]::IsNullOrEmpty($RawJson) -or $RawJson -eq "{}") { return }
    try {
        $eventId = [guid]::NewGuid().ToString()
        # Inject a resolved Direction so DNS/host-origin baselines don't render as "Unknown" in the
        # HUD (raw ETW JSON has an empty TrafficDirection and no Direction field for those events).
        $injectStr = "`"EventID`":`"$eventId`", `"ComputerName`":`"$global:ComputerName`", `"HostIP`":`"$global:HostIP`", `"SensorUser`":`"$global:SensorUser`", `"Direction`":`"$Direction`", `"LearningHit`":0, `"BaselineContext`":`"$Context`", "
        $enrichedJson = $RawJson.Insert(1, $injectStr)
        $global:uebaBatch.Add($enrichedJson)
    } catch {}
}

# --- STRUCTURED ALERTS ---
function Submit-SensorAlert {
    param(
        [string]$Type, [string]$SourceIp = "Unknown", [string]$Destination, [string]$Direction = "Unknown",
        [string]$Image, [string]$Flags, [int]$Confidence, [string]$AttckMapping = "N/A",
        [string]$EventId = ([guid]::NewGuid().ToString()), [string]$RawJson = $null,
        [int]$LearningHit = 0, [string]$CommandLine = "Unknown", [switch]$IsSuppressed, [int]$PID_Id = 0
    )

    $dedupKey = "$($Type)_$($SourceIp)_$($Destination)_$($Direction)_$($Flags)_$($Image)"
    $isNewAlert = -not $global:cycleAlerts.ContainsKey($dedupKey)

    if (-not $isNewAlert) {
        $global:cycleAlerts[$dedupKey].Count++
        return
    }

    if ($RawJson -and ($Type -eq "ThreatIntel_Match" -or $Type -eq "ML_IDPS" -or $Type -eq "Static_Detection")) {
        try {
            $injectStr = "`"EventID`":`"$EventId`", `"ComputerName`":`"$global:ComputerName`", `"HostIP`":`"$global:HostIP`", `"SensorUser`":`"$global:SensorUser`", `"LearningHit`":$LearningHit, "
            $enrichedJson = $RawJson.Insert(1, $injectStr)
            $global:uebaBatch.Add($enrichedJson)
        } catch {}
    }

    $alertObj = [PSCustomObject][ordered]@{
        EventID = $EventId; Count = 1
        Timestamp_Local = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
        Timestamp_UTC   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        ComputerName = $global:ComputerName; HostIP = $global:HostIP; SensorUser = $global:SensorUser
        EventType = $Type; Direction = $Direction; SourceIp = $SourceIp; Destination = $Destination;
        Image = $Image; CommandLine = $CommandLine; SuspiciousFlags = $Flags;
        ATTCKMappings = $AttckMapping; Confidence = $Confidence
        Action = if ($IsSuppressed) { "Suppressed" } elseif ($global:IsArmed -and $Confidence -ge $ConfidenceThreshold) { "Mitigated" } else { "Logged" }
    }

    $global:cycleAlerts[$dedupKey] = $alertObj

    # Route every curated alert to the transmission layer (SQLite WAL -> Parquet -> gateway) via FFI.
    # Enrich with raw telemetry fields (Provider/Port/Query/Size/PID/ThreatIntel) for the full bi-directional schema.
    try {
        $tele = if ($RawJson) { try { $RawJson | ConvertFrom-Json -ErrorAction Stop } catch { $null } } else { $null }
        $GatewayPayload = [ordered]@{
            EventID         = $alertObj.EventID
            Timestamp_UTC   = $alertObj.Timestamp_UTC
            ComputerName    = $alertObj.ComputerName
            SensorUser      = $alertObj.SensorUser
            HostIP          = $alertObj.HostIP
            EventType       = $alertObj.EventType
            Direction       = $alertObj.Direction
            SourceIp        = $alertObj.SourceIp
            Destination     = $alertObj.Destination
            Image           = $alertObj.Image
            CommandLine     = $alertObj.CommandLine
            SuspiciousFlags = $alertObj.SuspiciousFlags
            ATTCKMappings   = $alertObj.ATTCKMappings
            Confidence      = $alertObj.Confidence
            Action          = $alertObj.Action
            Provider        = if ($tele) { "$($tele.Provider)" } else { "" }
            EventName       = if ($tele) { "$($tele.EventName)" } else { "" }
            Port            = if ($tele) { "$($tele.Port)" } else { "" }
            Query           = if ($tele) { "$($tele.Query)" } else { "" }
            Size            = if ($tele) { "$($tele.Size)" } else { "0" }
            PID             = if ($tele) { "$($tele.PID)" } else { "" }
            ThreatIntel     = if ($tele) { "$($tele.ThreatIntel)" } else { "" }
        } | ConvertTo-Json -Compress
        [RealTimeIDPSSensor]::TransmitAlertToGateway($GatewayPayload)
    } catch {}

    # If the UEBA engine learned this is normal noise, skip HUD rendering to prevent console fatigue
    if ($IsSuppressed) { return }

    if ($alertObj.Action -eq "Mitigated" -or $Confidence -ge 100) {
        $prefix = if ($Type -eq "ThreatIntel_Match") { "CRITICAL TI" } else { "CRITICAL BEHAVIOR" }
        Add-AlertMessage "$($prefix): $Flags ($Image)" "$([char]27)[38;2;255;49;49m" # Red
    }
    elseif ($Confidence -ge 90) {
        # Confirmed Anomaly, but deferring to UEBA/Analyst for chronological conviction
        Add-AlertMessage "ANOMALY: $Flags ($Image) [Conf:$Confidence]" "$([char]27)[38;2;255;103;0m" # Orange
    }
    elseif ($LearningHit -gt 0 -or $Type -match "ML_IDPS|ThreatIntel_Match") {
        # Actively baselining normal vs abnormal
        $hitStr = if ($LearningHit -gt 0) { " [Pkt:$LearningHit]" } else { "" }
        Add-AlertMessage "LEARNING: $Flags ($Image)$hitStr" "$([char]27)[38;2;255;215;0m" # Gold
    }
    else {
        Add-AlertMessage "STATIC: $Flags ($Image)" "$([char]27)[38;2;255;255;255m" # White
    }

    # 6. Immediate Active Defense
    if ($alertObj.Action -eq "Mitigated") {
        Invoke-ActiveDefense -ProcName $Image -DestIp $Destination -Confidence $Confidence -Reason $Flags -PID_Id $PID_Id
    }
}

# =================================================================================
# C# DEPENDENCY RESOLUTION & ENGINE COMPILATION
# =================================================================================

# ====================== C# TYPE DEFINITIONS & MATH COMPILATION ======================

# Disable Windows QuickEdit Mode to prevent accidental process freezing
$QuickEditCode = @"
using System;
using System.Runtime.InteropServices;
public class ConsoleConfig {
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetStdHandle(int nStdHandle);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

    public static void DisableQuickEdit() {
        IntPtr consoleHandle = GetStdHandle(-10); // STD_INPUT_HANDLE
        if (GetConsoleMode(consoleHandle, out uint consoleMode)) {
            consoleMode &= ~0x0040U; // Strip ENABLE_QUICK_EDIT_MODE
            SetConsoleMode(consoleHandle, consoleMode);
        }
    }
}
"@
Add-Type -TypeDefinition $QuickEditCode
[ConsoleConfig]::DisableQuickEdit()

# 0-Alloc
$MathHelpersCode = @"
using System;
public class PSMathHelpers {
    public static ulong HashDomain(string domain) {
        if (string.IsNullOrEmpty(domain)) return 0;
        ulong hash = 14695981039346656037;
        for (int i = 0; i < domain.Length; i++) {
            hash ^= char.ToLowerInvariant(domain[i]);
            hash *= 1099511628211;
        }
        return hash;
    }
    public static uint IpToUint(string ipAddress) {
        if (System.Net.IPAddress.TryParse(ipAddress, out var address)) {
            byte[] bytes = address.GetAddressBytes();
            if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
            return BitConverter.ToUInt32(bytes, 0);
        }
        return 0;
    }
}
"@
Add-Type -TypeDefinition $MathHelpersCode

# Trace Event Library Dependencies
Write-Diag "Initializing C# TraceEvent Engine..." "STARTUP"

$DependenciesDir = "C:\ProgramData\IDPSSensor\Dependencies"
$StagingDir      = "C:\ProgramData\IDPSSensor\Staging"

if (-not (Test-Path $StagingDir))      { New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null }
if (-not (Test-Path $DependenciesDir)) { New-Item -ItemType Directory -Path $DependenciesDir -Force | Out-Null }

$ExtractPath = Join-Path $DependenciesDir "TE"
$DotNetTarget = if ($PSVersionTable.PSVersion.Major -ge 7) { "netstandard2.0" } else { "net45" }
$ManagedDllPath = "$ExtractPath\lib\$DotNetTarget\Microsoft.Diagnostics.Tracing.TraceEvent.dll"

if (-not (Test-Path $ManagedDllPath)) {
    Write-Diag "Downloading Microsoft.Diagnostics.Tracing.TraceEvent..." "STARTUP"
    New-Item -Path $ExtractPath -ItemType Directory -Force | Out-Null
    $ZipPath = Join-Path $StagingDir "TraceEvent.zip"
    try {
        Invoke-Download -Uri "https://www.nuget.org/api/v2/package/Microsoft.Diagnostics.Tracing.TraceEvent/3.0.2" -OutFile $ZipPath -UseBasicParsing -ErrorAction Stop
        Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force -ErrorAction Stop
        Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
    } catch {
        $realError = $_.Exception.Message
        Write-Diag "[!] FATAL: TraceEvent download failed: $realError" "CRITICAL"
        Write-Host "`n[!] Startup Failed: Unable to fetch TraceEvent library." -ForegroundColor Red
        Write-Host "    Reason: $realError" -ForegroundColor Red
        Write-Host "    Please check your network filter/firewall, or download it manually." -ForegroundColor Yellow
        exit
    }
}

Get-ChildItem -Path $ExtractPath -Recurse | Unblock-File
[System.Reflection.Assembly]::LoadFrom($ManagedDllPath) | Out-Null
Write-Diag "    [*] TraceEvent Library Loaded ($DotNetTarget)." "STARTUP"

# C# Compilation Assemblies
$RefAssemblies = @(
    $ManagedDllPath,
    "System",
    "System.Core"
)

if ($PSVersionTable.PSVersion.Major -ge 7) {
    $RefAssemblies += @(
        "System.Runtime",
        "System.Collections",
        "System.Collections.Concurrent",
        "System.ObjectModel",
        "System.Security.Cryptography",
        "System.Security.Cryptography.Algorithms",
        "System.Security.Cryptography.Primitives",
        "System.Net.Primitives",
        "System.Linq.Expressions",
        "System.Private.CoreLib",
        "netstandard",
        "System.Text.RegularExpressions",
        "System.Diagnostics.Process",
        "System.ComponentModel.Primitives"
    )
}

# ====================== CROSS-PLATFORM COMPILER ======================

$CSharpFilePath = Join-Path $ScriptDir "IDPSSensor.cs"
if (-not (Test-Path $CSharpFilePath)) {
    Write-Diag "[!] FATAL: Missing C# Engine Source: $CSharpFilePath" "CRITICAL"
    exit
}

Add-Type -Path $CSharpFilePath -ReferencedAssemblies $RefAssemblies
Write-Diag "C# Engine Compiled Natively into runspace." "STARTUP"

Write-Diag "Starting Real-Time ETW Session | Trace initiated... Follow the white rabbit. The Matrix has you, Neo...." "STARTUP"

$ConfigPath = Join-Path $ScriptDir "IDPSSensor_Config.ini"
$IniConfig = @{}

if (Test-Path $ConfigPath) {
    Write-Diag "    [+] Loading IDPSSensor_Config.ini..." "STARTUP"
    switch -Regex -File $ConfigPath {
        "^([^#;\[][^=]+)=(.*)$" {
            $key = $matches[1].Trim()
            $values = $matches[2] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            $IniConfig[$key] = [string[]]$values
        }
    }
} else {
    Write-Diag "[!] CRITICAL: IDPSSensor_Config.ini missing. Proceeding with empty exclusion arrays." "ERROR"
}

$FinalIpExclusions = $IniConfig["IpExclusions"] -as [string[]]
if ($TestMode) {
    $CdnPrefixes = @("^52\.", "^142\.25[0-9]\.", "^13\.", "^20\.", "^23\.", "^74\.125\.")
    $FinalIpExclusions = $FinalIpExclusions | Where-Object { $_ -notin $CdnPrefixes }
}

# =================================================================================
#                             BOOTSTRAP SEQUENCE
# =================================================================================

# --- FFI BOOTSTRAP ---
Initialize-TamperGuard
Initialize-JA3
$NetworkTI = Initialize-NetworkThreatIntel

# 1. Create and lock the secure execution paths
$BinPath  = "C:\ProgramData\IDPSSensor\Bin"
$DataPath = "C:\ProgramData\IDPSSensor\Data"
Lock-SecureDirectory $BinPath
Lock-SecureDirectory $DataPath
Lockdown-ProjectDir

# 2. FFI Integrity Check and Relocation
$dllSrc = Join-Path $ScriptDir "idpssensor_ml.dll"
$hashSrc = Join-Path $ScriptDir "idpssensor_ml.sha256"
$dllDest = Join-Path $BinPath "idpssensor_ml.dll"

if ((Test-Path $dllSrc) -and (Test-Path $hashSrc)) {
    Write-Diag "Verifying FFI Engine cryptographic integrity..." "STARTUP"
    $expectedHash = (Get-Content $hashSrc -Raw).Trim()
    $actualHash = (Get-FileHash $dllSrc -Algorithm SHA256).Hash

    if ($expectedHash -ne $actualHash) {
        Write-Diag "[!] FATAL PIPELINE ERROR: idpssensor_ml.dll SHA256 Integrity Check Failed!" "CRITICAL"
        throw "[!] FATAL: idpssensor_ml.dll has been tampered with."
    }

    Move-Item -Path $dllSrc -Destination $dllDest -Force
    Move-Item -Path $hashSrc -Destination (Join-Path $BinPath "idpssensor_ml.sha256") -Force
    Write-Diag "    [*] FFI DLL (SHA256: $actualHash) integrity verified and locked in \Bin." "STARTUP"
} elseif (-not (Test-Path $dllDest)) {
    Write-Diag "[!] FATAL: idpssensor_ml.dll not found in project root or secure \Bin." "CRITICAL"
    throw "FATAL: idpssensor_ml.dll missing."
}

# 3. Boot the C# Engine (which now securely pulls from \Bin)
[RealTimeIDPSSensor]::InitializeEngine(
    $ScriptDir,
    ($IniConfig["DnsExclusions"] -as [string[]]),
    ($IniConfig["ProcessExclusions"] -as [string[]]),
    $FinalIpExclusions,
    $NetworkTI.CompiledIps,
    $NetworkTI.CompiledDomains,
    $NetworkTI.TiContext,
    ($IniConfig["WebDaemons"] -as [string[]]),
    ($IniConfig["DbDaemons"] -as [string[]]),
    ($IniConfig["ShellInterpreters"] -as [string[]]),
    ($IniConfig["SuspiciousPaths"] -as [string[]])
)

[RealTimeIDPSSensor]::StartSession()

Write-Diag "Native FFI Bridge successfully initialized." "STARTUP"

Write-Diag "Initiating 20-second JIT compilation and RAM stabilization phase..." "STARTUP"
Write-Diag "    [*] Initializing Math Engine and pre-compiling native FFI pointers..." "STARTUP"
Write-Diag "    [*] Stabilizing memory footprint (20-second cooldown)..." "STARTUP"

Initialize-Cooldown

Write-Diag "Stabilization complete. Memory optimized. Starting event loop." "STARTUP"

Draw-AlertWindow

Write-Diag "Booting IDPS Live Browser HUD..." "STARTUP"
Start-IDPSSensorHUD -Background $false -EvtPath $OutputPath -UbaPath $UebaLogPath

# Resolve a human-meaningful traffic direction for the analyst-facing alert. The C# engine only
# computes TrafficDirection for TCPIP/NDIS network-flow events; DNS-Client queries and host-origin
# (process/file) detections arrive without one, which otherwise renders as "Unknown" in the HUD.
# A DNS query is an outbound resolution request (Egress); other host-origin detections are Local.
# Used only at alert-submission sites -- the raw $evt.TrafficDirection still drives the network-flow
# EgressTrack/proxy-node correlation so DNS is never mistaken for a real egress flow.
function Resolve-Direction($evtObj) {
    if (-not [string]::IsNullOrWhiteSpace($evtObj.TrafficDirection)) { return $evtObj.TrafficDirection }
    if ($evtObj.Provider -eq "Microsoft-Windows-DNS-Client" -or $evtObj.Query) { return "Egress" }
    return "Local"
}

# ====================== MAIN EVENT LOOP ======================

try {
    Write-Diag "    [*] Press 'Ctrl+C' or 'Q' to gracefully terminate the sensor." "STARTUP"
    while ($true) {
            $now = Get-Date
            $evtRef = $null
            $SysGuardState = "Secure"
            $eventCount = 0
            # Drain at full speed so the consumer keeps pace with the ETW producer -- no artificial
            # throttle means no dropped egress events under normal load (full visibility). A time
            # budget only *yields* to render the dashboard if a sustained burst keeps the queue
            # non-empty, so the UI never starves. The C# MaxQueueDepth cap is the last-resort
            # memory guard; it should only shed load if the consumer genuinely cannot keep up.
            $drainStart = Get-Date
            $drainN = 0

            while ([RealTimeIDPSSensor]::EventQueue.TryDequeue([ref]$evtRef)) {
                $evt = $evtRef
                $jsonStr = $evt.RawJson

                if (-not $evt) { continue }

                # Cheap periodic check (every 2048 events): yield to the UI after ~750ms of
                # continuous draining, then resume on the next outer iteration.
                $drainN++
                if ((($drainN -band 2047) -eq 0) -and (((Get-Date) - $drainStart).TotalMilliseconds -gt 750)) { break }

                if ($evt.Provider -eq "DiagLog") {
                    if ($evt.Message -match "SENSOR_BLINDING_DETECTED:(\d+)") {
                        $dropped = $matches[1]
                        $blindJson = "{`"ThreatIntel`":`"CRITICAL: SENSOR BLINDING (ETW Buffer Exhaustion). Dropped $dropped Events.`"}"

                        Submit-SensorAlert -Type "ML_IDPS" `
                            -Destination "Localhost" `
                            -Image "Windows_Kernel" `
                            -Flags "ETW Buffer Exhaustion Attack Detected ($dropped events lost)" `
                            -Confidence 100 `
                            -RawJson $blindJson

                        Draw-AlertWindow
                    } else {
                        Write-Diag $evt.Message "C#-ENGINE"
                    }
                    continue
                }

                $eventCount++
            if ($evt.Error) {
                Write-Diag "FATAL ETW CRASH: $($evt.Error)" "ERROR"
                Add-AlertMessage "FATAL ERROR: C# ETW THREAD CRASHED" $cRed
                continue
            }

            # --- NAMED PIPE DETECTION ---
            if ($evt.Provider -eq "P2P_Guard") {
                Submit-SensorAlert -Type "Lateral_Movement" -Destination "Local_Pipe" -Image $evt.Image -Flags "Malicious Named Pipe: $($evt.CommandLine)" -Confidence 95 -AttckMapping "T1570"
                continue
            }

            # --- TRAFFIC STATE TRACKING & PROXY NODE CORRELATION ---
            if ($evt.TrafficDirection) {
                $procKey = "$($evt.Image)_$($evt.PID)"

                if ($evt.TrafficDirection -eq "Lateral") {
                    $LateralTrack[$procKey] = $now
                    $global:TotalLateralFlows++
                } elseif ($evt.TrafficDirection -eq "Egress" -and $evt.DestIp) {
                    $EgressTrack[$procKey] = $now
                }

                # --- PROXY NODE CORRELATION ---
                if ($EgressTrack.ContainsKey($procKey) -and $LateralTrack.ContainsKey($procKey)) {
                    $timeDelta = [Math]::Abs(($EgressTrack[$procKey] - $LateralTrack[$procKey]).TotalSeconds)
                    if ($timeDelta -lt 60) {
                        Submit-SensorAlert -Type "Proxy_Node_Behavior" -Destination "Network_Bridge" -Image $evt.Image -Flags "Simultaneous Internal SMB/RPC and External Egress Routing" -Confidence 85 -AttckMapping "T1090.001"
                    }
                }
            }

            # --- TLS JA3 FINGERPRINT DETECTION ---
            if ($evt.Provider -eq "NDIS" -and $evt.EventName -eq "TLS_JA3_FINGERPRINT") {
                Write-Diag "JA3 HASH EXTRACTED: $($evt.DestIp) -> $($evt.JA3)" "INFO"

                if ($global:MaliciousJA3Cache.Contains($evt.JA3)) {
                    $owningProcess = "Unknown"
                    foreach ($k in $flowMetadata.Keys) {
                        if ($k -match "IP_$($evt.DestIp)") {
                            if ($flowMetadata[$k].image -ne "Unknown") {
                                $owningProcess = [System.IO.Path]::GetFileNameWithoutExtension($flowMetadata[$k].image)
                            }
                            break
                        }
                    }
                    Submit-SensorAlert -Type "JA3_C2_FINGERPRINT" -Destination $evt.DestIp -Image $owningProcess -Flags "Matched Abuse.ch JA3 Profile: $($evt.JA3)" -Confidence 100 -AttckMapping "T1071.001"
                }
                continue
            }

            # --- APPGUARD DETECTION ---
            if ($evt.Provider -eq "AppGuard") {
                Write-Diag "APPGUARD HIT: $($evt.Parent) spawned $($evt.Child) | CMD: $($evt.CommandLine)" "WARN"

                $MitreTags = if ($evt.EventName -eq "WEB_SHELL_DETECTED") { "T1505.003; T1190; T1059" } else { "T1190; T1569.002; T1059" }

                # Target the child process (shell) for mitigation to stop execution while logging the parent context
                Submit-SensorAlert -Type $evt.EventName -Destination "Local_Privilege_Escalation" -Image $evt.Child -Flags "Server App ($($evt.Parent)) Spawned Shell | Cmd: $($evt.CommandLine)" -Confidence 100 -AttckMapping $MitreTags
                continue
            }

            # --- NOISE REDUCTION FILTERS ---
            $procName = "Unknown"
            if (-not [string]::IsNullOrEmpty($evt.Image) -and $evt.Image -ne "Unknown") {
                $procName = [System.IO.Path]::GetFileNameWithoutExtension($evt.Image).ToLower()
            }
            elseif ($evt.PID -match '^\d+$' -and $evt.PID -ne "0" -and $evt.PID -ne "4") {
                $pidInt = [int]$evt.PID
                if (-not $ProcessCache.ContainsKey($pidInt)) {
                    try {
                        $ProcessCache[$pidInt] = [System.Diagnostics.Process]::GetProcessById($pidInt).ProcessName.ToLower()
                    } catch {
                        $ProcessCache[$pidInt] = "terminated"
                    }
                }
                $procName = $ProcessCache[$pidInt]
            }

            if ($procName -ne "Unknown" -and $procName -ne "terminated" -and $jsonStr -match '"Image":"Unknown"') {
                $jsonStr = $jsonStr -replace '"Image":"Unknown"', "`"Image`":`"$procName`""
                $evt.RawJson = $jsonStr
            }

            # --- SURICATA -> UEBA-DRIVEN ALERT ---
            if (-not [string]::IsNullOrEmpty($evt.ThreatIntel)) {
                $learningKey = "$procName|$($evt.ThreatIntel)"

                # Increment UEBA counter
                if (-not $global:UebaLearningCache.ContainsKey($learningKey)) {
                    $global:UebaLearningCache[$learningKey] = 0
                }
                $global:UebaLearningCache[$learningKey]++
                $tiHitCount = $global:UebaLearningCache[$learningKey]

                # Determine anomaly status and confidence
                $isAnomaly = $tiHitCount -ge 3
                $confidence = if ($isAnomaly) { 95 } else { 75 }

                $uebaContext = if ($tiHitCount -eq 1) { "NEW LEARNING" } elseif ($isAnomaly) { "CONFIRMED ANOMALY" } else { "LEARNING" }
                $enrichedFlags = "[$uebaContext] $($evt.ThreatIntel)"

                # Pre-evaluate the destination to prevent PowerShell parsing exceptions
                $targetDest = if ($evt.DestIp) { $evt.DestIp } else { $evt.Query }

                # Submit via centralized function.
                Submit-SensorAlert -Type "ThreatIntel_Match" `
                    -SourceIp $evt.SrcIp `
                    -Destination $targetDest `
                    -Direction (Resolve-Direction $evt) `
                    -Image $procName `
                    -Flags $enrichedFlags `
                    -Confidence $confidence `
                    -AttckMapping "T1071" `
                    -RawJson $jsonStr `
                    -LearningHit $tiHitCount `
                    -PID_Id $pidInt
            }

            # Behavioral Property Logic (Static Rules)
            $props = [ordered]@{
                EventType = $evt.EventName
                Timestamp = [datetime]$evt.TimeStamp
                Image = $evt.Image
                SuspiciousFlags = [System.Collections.Generic.List[string]]::new()
                ATTCKMappings = [System.Collections.Generic.List[string]]::new()
                DestinationHostname = $evt.Query
                ThreatIntel = $evt.ThreatIntel
                Confidence = 85
            }

            if ($evt.Provider -eq "Microsoft-Windows-Kernel-Process" -and $evt.CommandLine -match '-EncodedCommand|-enc|IEX') {
                $props.SuspiciousFlags.Add("Anomalous CommandLine")
                $props.ATTCKMappings.Add("TA0002: T1059.001")
            }
            if ($evt.Provider -eq "Microsoft-Windows-Kernel-File" -and $evt.Image -match '\.ps1$|\.exe$') {
                $props.SuspiciousFlags.Add("Executable File Created")
                $props.ATTCKMappings.Add("TA0002: T1059")
            }
            if ($evt.Provider -eq "Microsoft-Windows-DNS-Client" -and $evt.Query) {
                $domain = $evt.Query.TrimEnd('.')
                $dLow = $domain.ToLower()

                if ($dLow -notmatch "otel|telemetry|api|prod-") {

                    if (Is-AnomalousDomain $domain) {
                        $entropy = Get-Entropy $domain
                        $props.SuspiciousFlags.Add("DGA DNS Query Detected (Entropy: $([math]::Round($entropy, 2)))")
                        $props.ATTCKMappings.Add("TA0011: T1568.002")
                    }
                }

                if ($props.SuspiciousFlags.Count -eq 0 -and [string]::IsNullOrEmpty($evt.ThreatIntel)) {
                    Log-UebaBaseline -RawJson $jsonStr -Context "Normal_DNS" -Direction (Resolve-Direction $evt)
                }
            }

            if ($evt.Provider -match "TCPIP|Network" -and
                -not [string]::IsNullOrEmpty($evt.DestIp) -and
                $evt.DestIp -notmatch '^192\.168\.|^10\.|^127\.|^172\.') {

                $safePort = if ([string]::IsNullOrWhiteSpace($evt.Port) -or $evt.Port -eq "0") { "IP_$($evt.DestIp)" } else { $evt.Port }
                $dir = $evt.TrafficDirection
                $key = if ($evt.PID -eq "4" -or $evt.PID -eq "0") {
                    "PID_$($evt.PID)_TID_$($evt.TID)_DIR_${dir}_IP_$($evt.DestIp)_Port_$safePort"
                } else {
                    "PID_$($evt.PID)_TID_$($evt.TID)_DIR_${dir}_Port_$safePort"
                }

                $isFirstPacket = $false
                if (-not $connectionHistory.ContainsKey($key)) {
                    $isFirstPacket = $true
                    $connectionHistory[$key] = [System.Collections.Generic.Queue[datetime]]::new()
                    $flowMetadata[$key] = @{
                        src_ip = $evt.SrcIp
                        direction = $evt.TrafficDirection
                        dst_ips = [System.Collections.Generic.Queue[string]]::new()
                        packet_sizes = [System.Collections.Generic.Queue[int]]::new()
                        domain = if ($evt.Query) { $evt.Query } else { $evt.DestIp }
                        image = $evt.Image
                        commandline = $evt.CommandLine
                        total_out = 0
                        total_in = 0
                    }
                }

                $isNewPing = $true
                $evtTime = [datetime]$evt.TimeStamp

                if ($lastPingTime.ContainsKey($key) -and ($evtTime - $lastPingTime[$key]).TotalMilliseconds -lt 100) {
                    $isNewPing = $false
                }

                if ($isNewPing) {
                    $connectionHistory[$key].Enqueue($evtTime)
                    $lastPingTime[$key] = $evtTime
                    $flowMetadata[$key].dst_ips.Enqueue($evt.DestIp)
                    $flowMetadata[$key].raw_json = $evt.RawJson

                    if ($isFirstPacket -and [string]::IsNullOrEmpty($evt.ThreatIntel)) {
                        Log-UebaBaseline -RawJson $jsonStr -Context "New_Network_Flow" -Direction (Resolve-Direction $evt)
                    }

                    if ($evt.Size -match '^\d+$' -and $evt.Size -ne "0") {
                        $flowMetadata[$key].packet_sizes.Enqueue([int]$evt.Size)
                        if ($evt.EventName -match "Send") { $flowMetadata[$key].total_out += [int]$evt.Size }
                        elseif ($evt.EventName -match "Recv") { $flowMetadata[$key].total_in += [int]$evt.Size }
                    } else {
                        $flowMetadata[$key].packet_sizes.Enqueue(0)
                    }

                    # STRICT SLIDING WINDOW
                    while ($connectionHistory[$key].Count -gt 100) {
                        [void]$connectionHistory[$key].Dequeue()
                    }
                    while ($flowMetadata[$key].dst_ips.Count -gt $connectionHistory[$key].Count) {
                        [void]$flowMetadata[$key].dst_ips.Dequeue()
                    }
                    while ($flowMetadata[$key].packet_sizes.Count -gt $connectionHistory[$key].Count) {
                        [void]$flowMetadata[$key].packet_sizes.Dequeue()
                    }
                }
            }

            # --- STATIC BEHAVIORAL FLUSH ---
            if ($props.SuspiciousFlags.Count -gt 0) {
                $safeDestStatic = if ($evt.DestIp) { $evt.DestIp } elseif ($evt.Query) { $evt.Query } else { "Unknown" }

                $staticCmd = $evt.CommandLine
                if ([string]::IsNullOrWhiteSpace($staticCmd) -and $evt.PID -match '^\d+$' -and $evt.PID -ne "0" -and $evt.PID -ne "4") {
                    $wmi = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($evt.PID)" -ErrorAction SilentlyContinue
                    if ($wmi) { $staticCmd = $wmi.CommandLine }
                }

                $enrichedJson = $jsonStr
                if ($staticCmd) {
                    $cleanCmd = $staticCmd.Replace('\', '\\').Replace('"', '\"')
                    $enrichedJson = $enrichedJson.Replace('"CommandLine":""', "`"CommandLine`":`"$cleanCmd`"")
                }

                $staticPidInt = 0; if ($evt.PID -match '^\d+$') { $staticPidInt = [int]$evt.PID }
                Submit-SensorAlert -Type "Static_Detection" `
                    -SourceIp $evt.SrcIp `
                    -Destination $safeDestStatic `
                    -Direction (Resolve-Direction $evt) `
                    -Image $procName `
                    -Flags ($props.SuspiciousFlags -join '; ') `
                    -Confidence 90 `
                    -AttckMapping ($props.ATTCKMappings -join '; ') `
                    -RawJson $enrichedJson `
                    -CommandLine $staticCmd `
                    -PID_Id $staticPidInt
            }
        }

        # ---------------- NATIVE FFI ML HANDOFF PIPELINE ----------------
        if (($now - $lastMLRunTime).TotalSeconds -ge $BatchAnalysisIntervalSeconds) {
            $payloadArray = [System.Collections.Generic.List[object]]::new()

            foreach ($key in $connectionHistory.Keys) {
                $count = $connectionHistory[$key].Count
                if ($count -ge $MinSamplesForML) {

                    if (-not $loggedFlows.ContainsKey($key) -or $loggedFlows[$key] -ne $count) {
                        $loggedFlows[$key] = $count
                        $arr = $connectionHistory[$key].ToArray()

                        $duration = [Math]::Round(($arr[-1] - $arr[0]).TotalSeconds, 2)
                        $firstPing = $arr[0].ToString("yyyy-MM-dd HH:mm:ss")

                        $ipArr = $flowMetadata[$key].dst_ips.ToArray()
                        $sizeArr = $flowMetadata[$key].packet_sizes.ToArray()

                        $destIp = $ipArr[-1]
                        $domain = $flowMetadata[$key].domain
                        $portVal = if (($key -split "_Port_").Count -gt 1) { ($key -split "_Port_")[1] } else { "Unknown" }

                        $pidVal = "Unknown"
                        if ($key -match "PID_(\d+)") { $pidVal = $matches[1] }

                        $procName = "Unknown"
                        $resolvedImage = "Unknown"
                        $resolvedCmdLine = "Unknown"

                        if ($flowMetadata[$key].image -and $flowMetadata[$key].image -ne "Unknown") {
                            $procName = [System.IO.Path]::GetFileNameWithoutExtension($flowMetadata[$key].image)
                            $resolvedCmdLine = $flowMetadata[$key].commandline
                        } elseif ($pidVal -match '^\d+$') {
                            try {
                                $proc = Get-Process -Id $pidVal -ErrorAction Stop
                                $resolvedImage = $proc.Name

                                $wmi = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $pidVal" -ErrorAction SilentlyContinue
                                if ($wmi) { $resolvedCmdLine = $wmi.CommandLine }
                            } catch {
                                $resolvedImage = "Terminated"
                            }

                            $procName = $resolvedImage

                            $flowMetadata[$key].image = $resolvedImage
                            $flowMetadata[$key].commandline = $resolvedCmdLine
                        }

                        $srcIpVal = $flowMetadata[$key].src_ip
                        $dirVal = $flowMetadata[$key].direction
                        $logEntry = "Timestamp: $firstPing, Direction: $dirVal, Source IP: $srcIpVal, Destination IP: $destIp, Destination Domain: $domain, Port: $portVal, PID: $pidVal, Process Name: $procName, Flow Volume: $count packets over ${duration}s"
                        Add-Content -Path $MonitorLogPath -Value $logEntry -Encoding UTF8

                        $intervals = [System.Collections.Generic.List[double]]::new()
                        $aligned_ips = [System.Collections.Generic.List[string]]::new()
                        $aligned_sizes = [System.Collections.Generic.List[int]]::new()

                        for ($i = 1; $i -lt $arr.Count; $i++) {
                            $intervals.Add([Math]::Round(($arr[$i] - $arr[$i-1]).TotalSeconds, 2))
                            if ($i -lt $ipArr.Length) { $aligned_ips.Add($ipArr[$i]) }
                            if ($i -lt $sizeArr.Length) { $aligned_sizes.Add($sizeArr[$i]) }
                        }

                        $asymmetry = if ($flowMetadata[$key].total_in -gt 0) { $flowMetadata[$key].total_out / $flowMetadata[$key].total_in } else { $flowMetadata[$key].total_out }
                        $sparsity = if ($count -gt 0) { $duration / $count } else { 0 }

                        $payloadArray.Add(@{
                            key = $key
                            src_ip = $flowMetadata[$key].src_ip
                            direction = $flowMetadata[$key].direction
                            intervals = $intervals
                            domain = $flowMetadata[$key].domain
                            dst_ips = $aligned_ips
                            packet_sizes = $aligned_sizes
                            asymmetry_ratio = $asymmetry
                            sparsity_index = $sparsity
                        })
                    }
                }
            }

            if ($payloadArray.Count -gt 0) {
                $globalMlSent++
                $jsonPayload = $payloadArray | ConvertTo-Json -Depth 6 -Compress

                if (-not $jsonPayload.StartsWith("[")) { $jsonPayload = "[$jsonPayload]" }

                Write-Diag "Executing Native FFI Memory Map. Arrays: $($payloadArray.Count) | Payload Size: $($jsonPayload.Length)" "FFI-TX"

                $mlResponseString = [RealTimeIDPSSensor]::EvaluateBatch($jsonPayload)

                if ($mlResponseString -ne "{}" -and $mlResponseString -ne "") {
                    $globalMlRcvd++
                    Write-Diag "FFI-RX: Received response from Rust engine" "FFI-RX"

                    try {
                        $mlResults = $mlResponseString | ConvertFrom-Json -ErrorAction Stop

                        if ($mlResults.daemon_error) {
                            Write-Diag "RUST ML ENGINE ERROR: $($mlResults.daemon_error)" "ERROR"
                            Add-AlertMessage "ML ENGINE ERROR: $($mlResults.daemon_error)" $cRed
                        } elseif ($mlResults.alerts) {
                            foreach ($alert in $mlResults.alerts) {
                                $globalMlAlerts++
                                $alertKey = $alert.key
                                $pidVal = "Unknown"; if ($alertKey -match "PID_(\d+)") { $pidVal = $matches[1] }

                                $resolvedImage = "Unknown"
                                $resolvedCmdLine = "Unknown"

                                if ($flowMetadata.ContainsKey($alertKey)) {
                                    if ($flowMetadata[$alertKey].image -ne "Unknown") {
                                        $resolvedImage = [System.IO.Path]::GetFileNameWithoutExtension($flowMetadata[$alertKey].image)
                                    }
                                    if ($flowMetadata[$alertKey].commandline) {
                                        $resolvedCmdLine = $flowMetadata[$alertKey].commandline
                                    }
                                }

                                if ($pidVal -match '^\d+$' -and ([string]::IsNullOrWhiteSpace($resolvedCmdLine) -or $resolvedCmdLine -eq "Unknown")) {
                                    try {
                                        if ($resolvedImage -eq "Unknown") { $resolvedImage = (Get-Process -Id $pidVal -ErrorAction Stop).Name }
                                        $wmi = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $pidVal" -ErrorAction SilentlyContinue
                                        if ($wmi) { $resolvedCmdLine = $wmi.CommandLine }
                                    } catch {
                                        if ($resolvedImage -eq "Unknown") { $resolvedImage = "Terminated" }
                                    }
                                }

                                $targetIp = "Unknown"; if ($alertKey -match "IP_([0-9\.]+)") { $targetIp = $matches[1] }
                                $portVal = "Unknown"; if ($alertKey -match "_Port_([0-9a-zA-Z_]+)") { $portVal = $matches[1] }

                                $srcIpVal = "Unknown"
                                $dirVal = "Unknown"
                                if ($flowMetadata.ContainsKey($alertKey)) {
                                    $srcIpVal = $flowMetadata[$alertKey].src_ip
                                    $dirVal = $flowMetadata[$alertKey].direction
                                }
                                # This flow was gated on an external (non-RFC1918) destination, so a
                                # beaconing detection here is outbound by definition -- never "Unknown".
                                if ([string]::IsNullOrWhiteSpace($dirVal) -or $dirVal -eq "Unknown") { $dirVal = "Egress" }

                                $mlLearnKey = "ML_SUPPRESS|$resolvedImage|$targetIp|$portVal|$dirVal"

                                if (-not $global:UebaLearningCache.ContainsKey($mlLearnKey)) {
                                    $global:UebaLearningCache[$mlLearnKey] = 0
                                }
                                $global:UebaLearningCache[$mlLearnKey]++
                                $suppressHit = $global:UebaLearningCache[$mlLearnKey]

                                $suppressFlag = $false
                                if ($suppressHit -gt 5) {
                                    $suppressFlag = $true
                                    $alert.alert_reason = "[SUPPRESSED by UEBA Baseline] $($alert.alert_reason)"
                                }

                                $baseJson = "{}"
                                if ($flowMetadata.ContainsKey($alertKey) -and $flowMetadata[$alertKey].raw_json) {
                                    $baseJson = $flowMetadata[$alertKey].raw_json
                                }

                                $cleanReason = $alert.alert_reason -replace '"', '\"'
                                $alertJson = $baseJson.Replace('"ThreatIntel":""', "`"ThreatIntel`":`"ML_IDPS: $cleanReason`"")

                                if ($resolvedCmdLine -and $resolvedCmdLine -ne "Unknown") {
                                    $cleanCmd = $resolvedCmdLine.Replace('\', '\\').Replace('"', '\"')
                                    $alertJson = $alertJson.Replace('"CommandLine":""', "`"CommandLine`":`"$cleanCmd`"")
                                }

                                $beaconPidInt = 0; if ($pidVal -match '^\d+$') { $beaconPidInt = [int]$pidVal }
                                Submit-SensorAlert -Type "ML_IDPS" `
                                    -SourceIp $srcIpVal `
                                    -Destination $targetIp `
                                    -Direction $dirVal `
                                    -Image $resolvedImage `
                                    -Flags $alert.alert_reason `
                                    -Confidence $alert.confidence `
                                    -AttckMapping "T1071; T1105" `
                                    -RawJson $alertJson `
                                    -CommandLine $resolvedCmdLine `
                                    -IsSuppressed:$suppressFlag `
                                    -PID_Id $beaconPidInt
                            }
                        }
                    } catch {
                        Write-Diag "JSON Parse Failure from Rust Engine: $mlResponseString" "ERROR"
                    }
                }
            }

            # === STALE FLOW CLEANUP ===
            if (($now - $lastCleanupTime).TotalSeconds -ge 60) {
                $staleKeys = [System.Collections.Generic.List[string]]::new()

                # Check GetEnumerator to grab Keys and Values simultaneously (O(1) memory, Zero double-lookups)
                foreach ($kvp in $lastPingTime.GetEnumerator()) {
                    # TUNE: 12-Hour APT Memory Window
                    if (($now - $kvp.Value).TotalHours -gt 12) {
                        $staleKeys.Add($kvp.Key)
                    }
                }

                foreach ($k in $staleKeys) {
                    ([System.Collections.IDictionary]$connectionHistory).Remove($k)
                    ([System.Collections.IDictionary]$flowMetadata).Remove($k)
                    ([System.Collections.IDictionary]$loggedFlows).Remove($k)
                    ([System.Collections.IDictionary]$lastPingTime).Remove($k)
                }
                $lastCleanupTime = $now
            }

            # FLUSH DEDUPLICATED ALERTS TO JSONL (HUD is now instant)
            foreach ($alert in $global:cycleAlerts.Values) {
                $global:dataBatch.Add($alert)
            }
            $global:cycleAlerts.Clear() # Empty the cache for the next 15-second SIEM cycle

            $lastMLRunTime = $now
        }

        # --- LOG ROTATION & GROOMING ENGINE ---
        if ($dataBatch.Count -gt 0) {
            if (Test-Path $OutputPath) {
                if ((Get-Item $OutputPath).Length -gt 50MB) {
                    $archiveName = $OutputPath.Replace(".jsonl", "_$($now.ToString('yyyyMMdd_HHmm')).jsonl")
                    try { Move-Item -Path $OutputPath -Destination $archiveName -Force -ErrorAction Stop; Write-Diag "Alert log rotated." "INFO" } catch { Write-Diag "Alert log rotation failed: $($_.Exception.Message)" "WARN" }
                }
            }
            $batchOutput = ($dataBatch | ForEach-Object { $_ | ConvertTo-Json -Compress }) -join "`r`n"
            try { [System.IO.File]::AppendAllText($OutputPath, $batchOutput + "`r`n") } catch { }
            $dataBatch.Clear()
        }

        if ($uebaBatch.Count -gt 0) {
            if (Test-Path $UebaLogPath) {
                if ((Get-Item $UebaLogPath).Length -gt 50MB) {
                    $archiveName = $UebaLogPath.Replace(".jsonl", "_$($now.ToString('yyyyMMdd_HHmm')).jsonl")
                    try { Move-Item -Path $UebaLogPath -Destination $archiveName -Force -ErrorAction Stop; Write-Diag "UEBA log rotated." "INFO" } catch { Write-Diag "UEBA log rotation failed: $($_.Exception.Message)" "WARN" }
                }
            }
            $uebaOutput = $uebaBatch -join "`r`n"
            try { [System.IO.File]::AppendAllText($UebaLogPath, $uebaOutput + "`r`n") } catch { }
            $uebaBatch.Clear()
        }

        # === DISK & MEMORY PROTECTION: GARBAGE COLLECTION ===
        if ($now.Minute -eq 0 -and $now.Second -lt 15) {
            # 1. Prune Stale Logs
            $RetentionDays = 3
            $staleLogs = Get-ChildItem -Path $LogDir -Filter "*.jsonl" | Where-Object { $_.LastWriteTime -lt $now.AddDays(-$RetentionDays) }
            foreach ($stale in $staleLogs) {
                Remove-Item -Path $stale.FullName -Force -ErrorAction SilentlyContinue
                Write-Diag "Disk Protection: Groomed stale log file -> $($stale.Name)" "INFO"
            }
        }

        # === LIGHT MEMORY PROTECTION: GARBAGE COLLECTION (every 60 seconds) ===
        if (($now - $lastLightGC).TotalSeconds -ge 60) {
            [System.GC]::Collect(1, [System.GCCollectionMode]::Optimized)
            $lastLightGC = $now
        }

        # === DEEP MEMORY PROTECTION: GARBAGE COLLECTION (every 30 minutes) ===
        if (($now - $lastUebaCleanup).TotalMinutes -ge 30 -or $global:UebaLearningCache.Count -gt 30000) {

            $staleUebaKeys = [System.Collections.Generic.List[string]]::new()
            foreach ($k in $global:UebaLearningCache.Keys) {
                if ($global:UebaLearningCache[$k] -lt 5) { $staleUebaKeys.Add($k) }
            }
            foreach ($k in $staleUebaKeys) { [void]$global:UebaLearningCache.Remove($k) }

            # Clear unbounded correlation trackers to prevent infinite growth
            $LateralTrack.Clear()
            $EgressTrack.Clear()
            $ProcessCache.Clear()

            # Instruct the .NET Garbage Collector to aggressively reclaim memory
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()

            $lastUebaCleanup = $now
            Write-Diag "Deep Memory protection executed. Caches flushed and GC forced." "INFO"
        }

        $activeFlows = $connectionHistory.Keys.Count

        if ($eventCount -gt 0) {
            $LastEventReceived = $now
        }

        $tamperStatus = "Good"

        # 1. C# session is still alive?
        if (-not [RealTimeIDPSSensor]::IsSessionHealthy()) {
            $tamperStatus = "BAD"
        }

        # 2. No events received for more than 3 minutes?
        if (($now - $LastEventReceived).TotalMinutes -gt 3) {
            $tamperStatus = "BAD"
        }

        if ($dashboardDirty -or $eventCount -gt 0) {
            Draw-MonitorDashboard -Events $eventCount -Flows $activeFlows -Lateral $global:TotalLateralFlows -MlSent $globalMlSent -Alerts $globalMlAlerts -Tamper $tamperStatus -MlHealth "Native FFI" -SysGuard $SysGuardState -Mitigations $global:TotalMitigations
            $dashboardDirty = $false
        }

        if ($tamperStatus -eq "BAD") {
            if (-not $SensorBlinded) {
                $SensorBlinded = $true
                Add-AlertMessage "CRITICAL ALARM: SENSOR BLINDED. INITIATING AUTO-RECOVERY..." $cRed
                Write-Diag "SENSOR BLINDED: ETW thread unresponsive. Initiating auto-recovery." "ERROR"
            }

            # --- ACTIVE AUTO-RECOVERY ENGINE ---
            try {
                Write-Diag "Auto-Recovery: Tearing down dead ETW session..." "INFO"
                [RealTimeIDPSSensor]::StopSession()

                # OS-LEVEL FAILSAFE: Force terminate the trace via logman to prevent Zombie lockups
                logman stop "IDPSRealTimeSession" -ets -ErrorAction SilentlyContinue

                Start-Sleep -Seconds 2

                Write-Diag "Auto-Recovery: Re-initializing native ETW session..." "INFO"
                [RealTimeIDPSSensor]::StartSession()

                $LastEventReceived = $now # Reset the starvation timer
                $SensorBlinded = $false
                Add-AlertMessage "SENSOR RECOVERED: ETW SESSION RESTORED" $cGreen
            } catch {
                Write-Diag "Auto-Recovery failed: $($_.Exception.Message). Retrying next cycle." "ERROR"
            }
        }
        # Only idle when caught up. If a backlog remains (sustained burst), loop immediately
        # and keep draining at full speed so we don't fall behind and start shedding events.
        if ([RealTimeIDPSSensor]::EventQueue.IsEmpty) { Start-Sleep -Milliseconds 200 }
    }

} catch {
    $errMsg = $_.Exception.Message
    $fullErr = $_.Exception | Format-List -Force | Out-String
    Write-Host "`n[!] ORCHESTRATOR FATAL CRASH: $errMsg" -ForegroundColor Red
    Write-Diag "ORCHESTRATOR FATAL CRASH: $errMsg`n$fullErr" "CRITICAL"
} finally {
    Clear-Host
    Write-Host "`n[*] Initiating Graceful Shutdown..." -ForegroundColor Cyan

    Write-Diag "Initiating Teardown Sequence..." "INFO"

    Write-Host "    [*] Terminating Web HUD Runspace..." -ForegroundColor Gray
    try {
        if ($global:HudRunspace) {
            $global:HudRunspace.BeginStop($null, $null) | Out-Null
            $global:HudRunspace.Dispose()
        }
    } catch {}

    Write-Host "    [*] Finalizing Kernel Telemetry & ML Database..." -ForegroundColor Gray
    try { [RealTimeIDPSSensor]::StopSession() } catch {}
    Write-Diag "C# TraceEvent Session Halted." "INFO"

    Write-Host "    [*] Cleaning up centralized library artifacts..." -ForegroundColor Gray
    $StagingPath = "C:\ProgramData\IDPSSensor\Staging"
    if (Test-Path $StagingPath) {
        Remove-Item -Path "$StagingPath\*.zip" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$StagingPath\TraceEventPackage" -Recurse -Force -ErrorAction SilentlyContinue
    }

$TempLibPath = Join-Path "C:\ProgramData\IDPSSensor\Dependencies" "TraceEvent"
    if (Test-Path $TempLibPath) { Remove-Item -Path $TempLibPath -Recurse -Force -ErrorAction SilentlyContinue }

    Write-Diag "=== DIAGNOSTIC LOG CLOSED ===" "INFO"

    if ($global:DiagWriter) { $global:DiagWriter.Close(); $global:DiagStream.Dispose() }
    if ($global:TamperWriter) { $global:TamperWriter.Close(); $global:TamperStream.Dispose() }

    Write-Host "`n[+] Teardown Complete." -ForegroundColor Green
}