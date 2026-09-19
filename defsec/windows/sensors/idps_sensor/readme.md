### Deployment Guide: IDPS Sensor

Follow these instructions to deploy the standalone IDPS Sensor prototype. The deployment sequence is managed by the PowerShell orchestrator to ensure cryptographic integrity and environment security.

#### 1. Prerequisites
* **Operating System**: Windows 10/11 or Windows Server 2019+.
* **PowerShell**: **7+ (`pwsh`) is required.** The launcher compiles its C# ETW engine (`IDPSSensor.cs`) at runtime via `Add-Type`, using modern C# (string interpolation, inline `out` variables) that the built-in Windows PowerShell 5.1 compiler cannot build. Windows PowerShell 5.1 is not supported.
* **Permissions**: An elevated PowerShell terminal (Run as Administrator) is required to manage ETW sessions and directory ACLs.
* **Network**: Internet access is required for the initial fetch of the `TraceEvent` library and the synchronization of Suricata/abuse.ch threat intelligence.

#### 2. Initial File Placement
Ensure the following files are present in the installation root directory:
* `IDPSSensor_Launcher.ps1`: The primary PowerShell orchestrator.
* `idpssensor_ml.dll`: The compiled Native Rust behavioral engine.
* `idpssensor_ml.sha256`: The SHA256 integrity hash for the Rust engine.
* `IDPSSensor_Config.ini`: Global configuration for exclusions and AppGuard policies.
* `suricata/`: Directory containing `.rules` or `.list` files for signature-based detection.

#### 3. Automated Provisioning Sequence
When you execute the launcher, the sensor performs the following automated setup:
1.  **Vault Establishment**: Creates `C:\ProgramData\IDPSSensor` and subdirectories (`Bin`, `Data`, `Logs`, `Staging`).
2.  **Anti-Tamper Lockdown**: Applies strict ACLs to the vault, restricting access to `SYSTEM` and `Administrators`.
3.  **Integrity Validation**: Verifies the `idpssensor_ml.dll` hash against the `.sha256` file before relocating it to the secure `\Bin` folder.
4.  **Dependency Injection**: Automatically downloads and RAM-loads the `TraceEvent` library for the local .NET runtime environment.
5.  **Intel Compilation**: Compiles Suricata rules and JA3 fingerprints into O(1) binary search arrays for wire-speed matching.

#### 4. Execution Commands
Run the orchestrator from an elevated terminal using one of the following operational modes:

| Mode | Command | Description |
| :--- | :--- | :--- |
| **Audit** | `.\IDPSSensor_Launcher.ps1` | Standard observation mode; logs anomalies without mitigation. |
| **Armed** | `.\IDPSSensor_Launcher.ps1 -ArmedMode` | Active defense; enables process termination and firewall blocking. |
| **Test** | `.\IDPSSensor_Launcher.ps1 -TestMode` | Bypasses common CDN IP exclusions for validation testing. |
| **Verbose** | `.\IDPSSensor_Launcher.ps1 -EnableDiagnostics` | Enables detailed logging of FFI transitions and ETW events. |

#### Optional: Launch the Sensor with a Stealth Footprint
```powershell
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Deployment halted. Administrator privileges are required to configure Session 0 and Symbolic Links."
    return
}

$UsePwshCore = $true  # Toggle to $false for Windows PowerShell 5.1
$TaskName    = "WinTelemetryCache"
$IDPSRoot    = "C:\ProgramData\IDPSSensor"
$BinDir      = "$IDPSRoot\Bin"
$SensorPath  = "C:\Path\to\IDPSSensor_Launcher.ps1" # correct the path
$StealthExe  = "$BinDir\vmmem_svc.exe" # rename here

if (!(Test-Path $BinDir)) { New-Item $BinDir -ItemType Directory -Force | Out-Null }

$rootItem = Get-Item $IDPSRoot
$rootItem.Attributes = $rootItem.Attributes -bor [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System

if ($UsePwshCore) {
    $RealExe = (Get-Command pwsh.exe -ErrorAction SilentlyContinue).Source
    if (!$RealExe) { throw "PowerShell 7+ (pwsh.exe) not found on host." }
} else {
    $RealExe = "$env:Windir\System32\WindowsPowerShell\v1.0\powershell.exe"
}

if (Test-Path $StealthExe) { Remove-Item $StealthExe -Force }
New-Item -ItemType SymbolicLink -Path $StealthExe -Target $RealExe | Out-Null

$Action = New-ScheduledTaskAction -Execute $StealthExe `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$SensorPath`" -ArmedMode" # configure runtime param switches

$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings

Write-Host "[+] Deployment Complete: Sensor active in Session 0 as '$TaskName'." -ForegroundColor Green
```

#### 5. Observability & Monitoring
* **Terminal Dashboard**: Provides real-time metrics on events processed, active flows, and engine health.
* **Live Browser HUD**: A local web interface (automatically launched) provides an interactive workbench to inspect structured JSONL alerts and UEBA baseline logs.
* **Log Files**: All telemetry is recorded in `C:\ProgramData\IDPSSensor\Logs` for SIEM ingestion.

#### 6. Termination
To stop the sensor, press **'Ctrl+C'** or **'Q'** in the terminal. The orchestrator will execute a graceful teardown, flushing the SQLite WAL ledger to disk and closing all kernel ETW sessions.