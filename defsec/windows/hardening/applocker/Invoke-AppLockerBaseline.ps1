<#
.SYNOPSIS
    Deploys an NSA-derived AppLocker application allowlisting baseline to an internet-connected
    Windows 11 endpoint, reducing attack surface and containing user-initiated execution mistakes
    (malicious downloads, email attachments, ClickFix-style scams, LOLBAS abuse) to audit-then-block.

.DESCRIPTION
    Application allowlisting is one of NSA's top mitigation strategies. This script takes the
    NSA AppLocker-Guidance Windows 11 starter policy (nsa\AppLocker Starter Policy\Windows11_AppLocker
    Starter Policy.xml) - which already denies execution from the standard-user-writable Windows
    bypass folders (MachineKeys, spool\drivers\color, Tasks, Temp, Debug, Registration, tracing,
    including their NTFS alternate-data-stream forms) and denies known LOLBAS/Microsoft-recommended
    abuse binaries - merges in any wired-in modules\ rule additions, and deploys the result as
    local AppLocker policy.

    Flow, mirroring the assess/remediate pattern used elsewhere in this repo:
        1. ASSESS (default, no changes): report Application Identity service state, current local
           AppLocker policy (rule counts + enforcement mode per collection), AppLocker event log
           health, block-notification task registration, and each wired-in module's own status.
        2. REMEDIATE (-Remediate): merge module rule additions into the baseline, import it.
           Ships in AuditOnly mode for every rule collection by design - nothing is blocked yet,
           only logged - so the policy can be tuned against real usage before anything actually
           breaks for the user. Each module's complementary (non-AppLocker) hardening also runs
           in this phase. The popup-on-block task is deliberately NOT registered yet here - audit
           hits are expected to be frequent while tuning, and popping up a message for each one
           would be noise, not signal. Use -ShowAuditHits instead to review them.
        3. ENFORCE (-Remediate -Enforce): once the audit log (see -ShowAuditHits) is clean, flip
           Exe/Msi/Script/Appx to Enabled. The Dll collection stays in AuditOnly unless
           -EnableDllRules is also passed, since DLL rules carry real compatibility/performance
           risk and Microsoft recommends enabling them only after the rest of the policy is stable.
           This is also when the popup-on-block task gets registered, since blocks should now be
           rare, real, and worth surfacing immediately.

    Modules: modules\*.psm1 extend the baseline without editing this orchestrator. See
    modules\README.md for the contract. -Modules controls which ones are wired into a given run
    (default: ClickFix, PhishingAttachmentGuard, RemovableMediaGuard, ExplorerVisibilityHardening,
    BrowserScamGuard, DefenderCompatibility - a curated set picked for low collateral damage to a
    normal user's workflow. DefenderCompatibility is a correctness fix, not a threat-targeted
    module - it allow-lists Defender's own ProgramData platform binaries, which the base policy
    would otherwise audit/block continuously. RemoteAccessToolGuard and OfficeMacroGuard are
    opt-in since they depend on environment-specific judgment calls; RunDialogLockdown is opt-in
    since it has a real usability trade-off).

    This script only manages local AppLocker policy + Application Identity service + AppLocker
    event log visibility + whatever its wired-in modules do. It does not touch kiosk/Assigned
    Access, UWF, browser GPOs, or BIOS/boot settings - those are separate OS-hardening concerns
    outside this module's scope.

.PARAMETER Remediate
    Apply changes (start/enable the Application Identity service, import the policy, run module
    hardening). Without it, the script only assesses and reports current state - a safe dry run.

.PARAMETER Enforce
    Only meaningful with -Remediate. Flips the Exe, Msi, Script, and Appx rule collections from
    AuditOnly to Enabled after import. Without this switch the policy is imported but left in
    AuditOnly (the safe first-deployment state).

.PARAMETER EnableDllRules
    Only meaningful with -Remediate -Enforce. Also flips the Dll rule collection to Enabled.
    Off by default: DLL allowlisting is the highest-risk AppLocker collection for breaking
    legitimate software and should only be enabled after the rest of the policy has been
    running clean in Enforce mode for a while.

.PARAMETER PolicyPath
    Path to the AppLockerPolicy XML to deploy. Defaults to this repo's NSA Windows 11 starter
    policy under nsa\AppLocker Starter Policy\.

.PARAMETER Modules
    Names of modules\*.psm1 (without extension) to wire into this run. Defaults to a curated set
    (ClickFix, PhishingAttachmentGuard, RemovableMediaGuard, ExplorerVisibilityHardening,
    BrowserScamGuard, DefenderCompatibility). Pass 'All' to wire in every module under modules\
    (including the opt-in RemoteAccessToolGuard, OfficeMacroGuard, RunDialogLockdown), or an empty
    array (-Modules @()) to wire in none. Comma-joined values (-Modules Foo,Bar) are also accepted
    even when invoked via `powershell.exe -File`, which doesn't split them on its own.

.PARAMETER Merge
    Merge the baseline into whatever AppLocker policy is already configured locally instead of
    replacing it outright. Use this if the machine already has hand-written local rules worth
    keeping.

.PARAMETER SkipVisibility
    Skip the visibility/alerting steps (AppLocker event log sizing + registering the NSA
    popup-on-block scheduled task). By default these are applied alongside the policy so blocked
    execution attempts are both logged with enough retention and surfaced to the user/admin.

.PARAMETER EventLogMaxSizeMB
    Max size, in MB, for each of the four AppLocker event log channels. Default 64.

.PARAMETER ShowAuditHits
    Read-only. Summarizes what the AuditOnly policy would have blocked (grouped by file path,
    most-frequent first) so the policy can be tuned before switching to -Enforce. Does not require
    -Remediate and makes no changes.

.PARAMETER OutputPath
    Folder for the pre-change policy backup and audit-hit report. Default:
    .\AppLockerReports\<HOSTNAME>-<timestamp>\

.PARAMETER Force
    Bypass the Windows 11 / non-Home-edition pre-flight check.

.EXAMPLE
    # Safe dry run - report current AppLocker + module state, no changes
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-AppLockerBaseline.ps1

.EXAMPLE
    # First deployment: baseline + default modules in AuditOnly, log sizing, alert task
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-AppLockerBaseline.ps1 -Remediate

.EXAMPLE
    # Wire in every available module, including the opt-in ones
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-AppLockerBaseline.ps1 -Remediate -Modules All

.EXAMPLE
    # Check what the audited policy would have blocked before going to Enforce
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-AppLockerBaseline.ps1 -ShowAuditHits

.EXAMPLE
    # After reviewing audit hits and confirming no false positives, turn on enforcement
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-AppLockerBaseline.ps1 -Remediate -Enforce

.EXAMPLE
    # Full rollback: remove the local AppLocker policy and undo every wired-in module's hardening
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-AppLockerBaseline.ps1 -Rollback

.NOTES
    Author: Robert Weber
    Run from an elevated PowerShell session. Requires Windows 11 Pro/Enterprise/Education
    (AppLocker is not available on Windows 11 Home).
#>

[CmdletBinding()]
param(
    [switch]$Remediate,
    [switch]$Enforce,
    [switch]$EnableDllRules,
    [string]$PolicyPath,
    [string[]]$Modules,
    [switch]$Merge,
    [switch]$SkipVisibility,
    [int]$EventLogMaxSizeMB = 64,
    [switch]$Rollback,
    [switch]$ShowAuditHits,
    [int]$TopAuditHits = 25,
    [string]$OutputPath,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $root 'Invoke-AppLockerBaseline.Functions.ps1')

if (-not $PolicyPath) { $PolicyPath = Join-Path $root 'nsa\AppLocker Starter Policy\Windows11_AppLocker Starter Policy.xml' }

$ModulesRoot = Join-Path $root 'modules'
$DefaultModules = @('ClickFix', 'PhishingAttachmentGuard', 'RemovableMediaGuard', 'ExplorerVisibilityHardening', 'BrowserScamGuard', 'DefenderCompatibility', 'WindowsAppRepository')

$AppLockerLogs = @(
    'Microsoft-Windows-AppLocker/EXE and DLL',
    'Microsoft-Windows-AppLocker/MSI and Script',
    'Microsoft-Windows-AppLocker/Packaged app-Deployment',
    'Microsoft-Windows-AppLocker/Packaged app-Execution'
)
$PopupTaskName = 'AppLocker Popup Alert'
$PopupTaskXmlPath = Join-Path $root 'nsa\Create AppLocker Popup Task\AppLocker Popup Alert Task.xml'

# =============================================================================
# 0. PRE-FLIGHT
# =============================================================================
if (-not (Test-Admin)) {
    Write-Warning "Not running elevated. Remediation and service/policy changes require Administrator."
    if ($Remediate -and -not $Force) { throw "Re-run from an elevated PowerShell session (or pass -Force to override)." }
}

$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
if ($os -and $os.Caption -notmatch 'Windows 11') {
    Write-Warning "This baseline targets Windows 11; detected: $($os.Caption)."
    if ($Remediate -and -not $Force) { throw "Re-run with -Force to apply anyway." }
}
if ($os -and $os.Caption -match 'Home') {
    Write-Warning "AppLocker is not available on Windows 11 Home edition."
    if ($Remediate -and -not $Force) { throw "AppLocker cmdlets will fail on Home edition. Re-run with -Force to attempt anyway." }
}

if ($Enforce -and -not $Remediate) {
    throw "-Enforce has no effect without -Remediate. To turn on blocking, run: .\Invoke-AppLockerBaseline.ps1 -Remediate -Enforce"
}
if ($EnableDllRules -and -not $Enforce) {
    Write-Warning "-EnableDllRules has no effect without -Enforce (which also requires -Remediate)."
}

if (-not $OutputPath) {
    $OutputPath = Join-Path $root "AppLockerReports\$($env:COMPUTERNAME)-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
}

$ResolvedModules = Resolve-AppLockerModule -RequestedModules $Modules -BoundModules $PSBoundParameters.ContainsKey('Modules') `
    -DefaultModules $DefaultModules -ModulesRoot $ModulesRoot
foreach ($name in $ResolvedModules) {
    Import-Module (Join-Path $ModulesRoot "$name.psm1") -Force
}

# =============================================================================
# 1. STATUS / ASSESSMENT
# =============================================================================
function Get-AppLockerBaselineStatus {
    $svc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
    Write-Host "`n== Application Identity service ==" -ForegroundColor Cyan
    if ($svc) {
        Write-Host "  Status: $($svc.Status)   StartType: $($svc.StartType)"
    } else {
        Write-Host "  Not found." -ForegroundColor Yellow
    }

    Write-Host "`n== Local AppLocker policy ==" -ForegroundColor Cyan
    try {
        $policy = Get-AppLockerPolicy -Local
        foreach ($rc in $policy.RuleCollections) {
            Write-Host ("  {0,-8} {1,-12} {2} rule(s)" -f $rc.RuleCollectionType, $rc.EnforcementMode, $rc.Count)
        }
    } catch {
        Write-Host "  Unable to read local policy: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    Write-Host "`n== AppLocker event logs ==" -ForegroundColor Cyan
    foreach ($log in $AppLockerLogs) {
        try {
            $cfg = Get-WinEvent -ListLog $log -ErrorAction Stop
            Write-Host ("  {0,-55} enabled={1,-5} maxSizeMB={2}" -f $log, $cfg.IsEnabled, [math]::Round($cfg.MaximumSizeInBytes / 1MB))
        } catch {
            Write-Host "  $log : not available" -ForegroundColor Yellow
        }
    }

    Write-Host "`n== Block-notification task ==" -ForegroundColor Cyan
    $task = Get-ScheduledTask -TaskName $PopupTaskName -ErrorAction SilentlyContinue
    if ($task) {
        Write-Host "  '$PopupTaskName' registered, state: $($task.State)"
    } else {
        Write-Host "  Not registered." -ForegroundColor Yellow
    }

    foreach ($name in $ResolvedModules) {
        Write-Host "`n== Module: $name ==" -ForegroundColor Cyan
        $status = Invoke-AppLockerModulePhase -ModuleName $name -Phase Status
        if ($null -eq $status) {
            Write-Host "  (no status reported)"
        } else {
            $status | ForEach-Object { Write-Host "  $_" }
        }
    }
}

Get-AppLockerBaselineStatus

if ($ShowAuditHits) {
    # --- Exe / MSI / Script collection audit hits (standard default-deny misses) ---
    Write-Host "`n== Top audited (would-be-blocked) Exe/Script/MSI execution attempts ==" -ForegroundColor Cyan
    $hits = Get-AppLockerFileInformation -EventLog -EventType Audit -Statistics -ErrorAction SilentlyContinue |
        Sort-Object Count -Descending |
        Select-Object -First $TopAuditHits Count, PolicyDecision, @{N = 'Path'; E = { $_.TargetFilePath } }
    if ($hits) {
        $hits | Format-Table -AutoSize
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        $reportFile = Join-Path $OutputPath 'AppLockerAuditHits.csv'
        $hits | Export-Csv -Path $reportFile -NoTypeInformation
        Write-Host "Full report: $reportFile"
    } else {
        Write-Host "  No audit events found yet (policy may not be deployed, or no AuditOnly hits logged so far)."
    }

    # --- Dll collection audit hits (Event ID 8003: would block when -EnableDllRules is on) ---
    # Dll audit hits are separate from the Exe/Script hits above because the Dll collection
    # is held in AuditOnly even after -Enforce. These represent what WOULD break if
    # -EnableDllRules were added. They are grouped by parent directory because you write
    # allow rules at the directory/publisher level, not one rule per DLL filename.
    Write-Host "`n== Dll collection audit hits (what would break if -EnableDllRules were turned on) ==" -ForegroundColor Cyan
    Write-Host "  For each path cluster below: run Get-AppLockerDllPublisherInfo on a sample DLL" -ForegroundColor DarkCyan
    Write-Host "  to get a publisher rule suggestion (publisher rules prevent DLL sideloading)." -ForegroundColor DarkCyan

    $dllEvents = Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL' -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -eq 8003 }

    if ($dllEvents) {
        $dllHits = $dllEvents | ForEach-Object {
            if ($_.Message -match '^(.+?) was allowed to run but would have been prevented') { $Matches[1] }
        } | Where-Object { $_ } |
            Group-Object { $_ -replace '\\[^\\]+$' } |
            Sort-Object Count -Descending |
            Select-Object -First $TopAuditHits Count, @{N = 'DirectoryPattern'; E = { $_.Name } }

        $dllHits | Format-Table -AutoSize

        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        $dllReportFile = Join-Path $OutputPath 'AppLockerDllAuditHits.csv'
        $dllHits | Export-Csv -Path $dllReportFile -NoTypeInformation
        Write-Host "Full Dll report: $dllReportFile"
        Write-Host "Use Get-AppLockerDllPublisherInfo on a file from each cluster - publisher rules are required for Dll collection; path rules create sideloading risk." -ForegroundColor Yellow
    } else {
        Write-Host "  No Dll audit events found (Id 8003). Either the Dll collection has no gaps yet, or the event log has been cleared."
    }
}

if ($Rollback) {
    if (-not (Test-Admin)) {
        throw "Rollback requires an elevated (Administrator) PowerShell session."
    }
    # Only clear the AppLocker policy on a full rollback (no specific -Modules given).
    # A targeted rollback (-Modules RunDialogLockdown) only undoes that module's registry
    # changes - it should not nuke the policy that all other modules contributed to.
    $isFullRollback = -not $PSBoundParameters.ContainsKey('Modules')
    if ($isFullRollback) {
        Write-Host "`n== ROLLBACK: removing local AppLocker policy ==" -ForegroundColor Yellow
        try {
            $emptyPolicy = '<AppLockerPolicy Version="1" />'
            $rollbackPolicyFile = Join-Path $env:TEMP 'AppLockerEmptyPolicy.xml'
            $emptyPolicy | Set-Content -Path $rollbackPolicyFile -Encoding UTF8
            Set-AppLockerPolicy -XmlPolicy $rollbackPolicyFile
            Remove-Item $rollbackPolicyFile -Force -ErrorAction SilentlyContinue
            Write-Host "  Local AppLocker policy cleared." -ForegroundColor Yellow
        } catch {
            Write-Warning "Could not clear AppLocker policy: $($_.Exception.Message)"
        }
        Write-Host "`n== ROLLBACK: disabling popup-alert task (if registered) ==" -ForegroundColor Yellow
        if (Get-ScheduledTask -TaskName $PopupTaskName -ErrorAction SilentlyContinue) {
            Disable-ScheduledTask -TaskName $PopupTaskName -ErrorAction SilentlyContinue | Out-Null
            Write-Host "  '$PopupTaskName' disabled." -ForegroundColor Yellow
        }
    }
    Write-Host "`n== ROLLBACK: undoing module hardening ==" -ForegroundColor Yellow
    foreach ($name in $ResolvedModules) {
        $result = Invoke-AppLockerModulePhase -ModuleName $name -Phase Rollback -Remediate
        if ($null -ne $result) {
            Write-Host "  ${name}:" -ForegroundColor Yellow
            $result | ForEach-Object { Write-Host "    $_" }
        }
    }
    Write-Host "`nRollback complete." -ForegroundColor Green
    return
}

if (-not $Remediate) {
    Write-Host "`nDry run only. Re-run with -Remediate to deploy the baseline (AuditOnly), or add -Enforce once the audit log is clean." -ForegroundColor Green
    return
}

# =============================================================================
# 2. REMEDIATE: SERVICE + POLICY IMPORT (baseline + wired-in modules)
# =============================================================================
if (-not (Test-Path -LiteralPath $PolicyPath)) {
    throw "Policy file not found: $PolicyPath"
}

$policyDoc = New-Object System.Xml.XmlDocument
$policyDoc.Load($PolicyPath)
if ($policyDoc.DocumentElement.Name -ne 'AppLockerPolicy') {
    throw "$PolicyPath does not look like an AppLockerPolicy XML file (root element is '$($policyDoc.DocumentElement.Name)')."
}

foreach ($name in $ResolvedModules) {
    $fragments = Invoke-AppLockerModulePhase -ModuleName $name -Phase PolicyFragment
    foreach ($fragment in $fragments) {
        Write-Host "Merging rule '$($fragment.Name)' from module '$name' into the $($fragment.CollectionType) collection..." -ForegroundColor Cyan
        Add-AppLockerPolicyFragment -PolicyDoc $policyDoc -CollectionType $fragment.CollectionType -RuleXml $fragment.Xml | Out-Null
    }
}

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
try {
    Get-AppLockerPolicy -Local -Xml | Set-Content -Path (Join-Path $OutputPath 'PreChange-LocalPolicy.xml') -Encoding UTF8
} catch {
    Write-Host "No existing local policy to back up."
}

Write-Host "`nEnabling Application Identity service..." -ForegroundColor Cyan
$appIdSvc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
if ($appIdSvc -and $appIdSvc.StartType -ne 'Automatic') {
    try {
        Set-Service -Name AppIDSvc -StartupType Automatic -ErrorAction Stop
    } catch {
        Write-Warning "Could not set AppIDSvc startup type to Automatic ($($_.Exception.Message)). Not fatal: AppIDSvc ships with its own trigger-start configuration (it starts automatically when AppLocker policy is evaluated) independent of this setting."
    }
}
Start-Service -Name AppIDSvc -ErrorAction SilentlyContinue

if ($Enforce) {
    Set-AppLockerRuleCollectionEnforcement -PolicyDoc $policyDoc -EnableDllRules:$EnableDllRules
    Write-Host "Enforcement mode set to Enabled for $(if ($EnableDllRules) {'all'} else {'all non-Dll'}) rule collections." -ForegroundColor Cyan
} else {
    Write-Host "Importing policy in AuditOnly (as shipped) - nothing will be blocked yet." -ForegroundColor Cyan
}

Write-Host "Importing AppLocker policy from: $PolicyPath" -ForegroundColor Cyan
# Set-AppLockerPolicy -XmlPolicy takes a path to a file containing the policy, not inline XML text
# despite the name - passing the XML string directly fails with "The following file cannot be
# resolved: <AppLockerPolicy ...". Write the merged/enforced policy out as a real file instead.
$mergedPolicyFile = Join-Path $OutputPath 'MergedPolicy.xml'
$policyDoc.Save($mergedPolicyFile)
if ($Merge) {
    Set-AppLockerPolicy -XmlPolicy $mergedPolicyFile -Merge
} else {
    Set-AppLockerPolicy -XmlPolicy $mergedPolicyFile
}

Write-Host "`n== Post-import local policy ==" -ForegroundColor Cyan
(Get-AppLockerPolicy -Local).RuleCollections | ForEach-Object {
    Write-Host ("  {0,-8} {1,-12} {2} rule(s)" -f $_.RuleCollectionType, $_.EnforcementMode, $_.Count)
}

# =============================================================================
# 3. REMEDIATE: VISIBILITY
# =============================================================================
if (-not $SkipVisibility) {
    Write-Host "`nSizing AppLocker event logs to ${EventLogMaxSizeMB}MB and enabling them..." -ForegroundColor Cyan
    foreach ($log in $AppLockerLogs) {
        & wevtutil.exe sl $log "/ms:$($EventLogMaxSizeMB * 1MB)" "/e:true" 2>&1 | Out-Null
    }

    if ($Enforce) {
        if (Test-Path -LiteralPath $PopupTaskXmlPath) {
            Write-Host "Registering '$PopupTaskName' scheduled task (notifies the logged-on user when AppLocker blocks something)..." -ForegroundColor Cyan
            $taskXml = Get-Content -LiteralPath $PopupTaskXmlPath -Raw
            Register-ScheduledTask -TaskName $PopupTaskName -Xml $taskXml -Force | Out-Null
        } else {
            Write-Warning "Popup task definition not found at $PopupTaskXmlPath - skipping."
        }
    } else {
        # The task fires on every Audit-level AppLocker event, not just real blocks. AuditOnly is
        # expected to be noisy while the policy is tuned - popping up a message for each hit would
        # be actively disruptive, not informative. Only wire it up once enforcement is real.
        if (Get-ScheduledTask -TaskName $PopupTaskName -ErrorAction SilentlyContinue) {
            Disable-ScheduledTask -TaskName $PopupTaskName -ErrorAction SilentlyContinue | Out-Null
        }
        Write-Host "Skipping popup-alert task while in AuditOnly (every audit hit would otherwise pop up a message). It registers automatically once you run with -Enforce. Use -ShowAuditHits to review audit activity in the meantime." -ForegroundColor Cyan
    }
}

# =============================================================================
# 4. REMEDIATE: MODULE HARDENING
# =============================================================================
foreach ($name in $ResolvedModules) {
    Write-Host "`nRunning '$name' module hardening..." -ForegroundColor Cyan
    Invoke-AppLockerModulePhase -ModuleName $name -Phase Hardening -Remediate | ForEach-Object { Write-Host "  $_" }
}

Write-Host "`nDone. Backup of prior local policy (if any): $OutputPath" -ForegroundColor Green
if (-not $Enforce) {
    Write-Host "Policy is in AuditOnly. Let it run, then check 'Microsoft-Windows-AppLocker/*' event logs (or -ShowAuditHits) before re-running with -Remediate -Enforce." -ForegroundColor Green
}
