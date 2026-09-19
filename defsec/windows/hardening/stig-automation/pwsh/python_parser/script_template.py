"""Renders the full PowerShell engine (param block, helper functions, scope filter,
CheckType switch, output) around a drafted $rules array body - the same shell used by
server2022/server2025/win11. Extracted from the one-off assembly used to build
dns/WindowsServerDNS-STIG-V2R4.ps1 so future STIGs don't need it hand-rolled again.
"""

HEADER = '''<#
.SYNOPSIS
    PowerShell automation for the {title}.

.DESCRIPTION
    Drafted from the official DISA XCCDF via python_parser/runner.py. Of the {total}
    controls in this STIG, {auto} reduce to a single queryable value the engine here
    can check/remediate (Registry={n_registry}, UserRight={n_userright},
    AuditPolicy={n_auditpolicy}) - the rest are zone/role-level configuration,
    firewall/IPsec policy, or organizational/documented-procedure checks that need
    per-deployment parameters or human judgment, not a single registry/secedit/auditpol
    value. Those are left as commented-out TODO blocks with the full check-content, for
    a human to classify and finish - search this file for "# TODO [V-" to find them.

.PARAMETER Remediate
    Automatically fix everything possible (currently: the {auto} classified rule(s)).

.PARAMETER Severity
    Which CRITICALITY levels to evaluate. Default: High, Medium, Low.

.PARAMETER StigId
    Target one or more specific VIDs instead of the whole baseline. When supplied,
    Severity and the RulesFile are ignored - only the listed ID(s) are
    evaluated/remediated. Unknown IDs are reported with a warning and otherwise skipped.

.PARAMETER RulesFile
    Path to an INI file listing one VID per line that toggles which rules are in scope -
    comment out a line (prefix with ; or #) to exclude that control. Defaults to
    "{basename}.ini" next to this script, if present. Only lists the {auto} VID(s) that
    are real $rules array entries - see .DESCRIPTION. Ignored when -StigId is supplied.

.PARAMETER IgnoreRulesFile
    Skip the INI include/exclude file even if it exists, and evaluate every rule that
    the Severity filter allows.

.PARAMETER ListRules
    Print the in-scope rules (after Severity/StigId/RulesFile filtering) and exit. No
    changes made.

.PARAMETER PassThru
    Return the report objects (and stay quiet on the host) so an orchestrator can
    consume them.

.EXAMPLE
    .\\{basename}.ps1 -Remediate

.NOTES
    Author: python_parser/runner.py (auto-drafted)
    Run from an elevated PowerShell session.
#>

[CmdletBinding()]
param(
    [switch]$Remediate,

    [ValidateSet('High','Medium','Low')]
    [string[]]$Severity = @('High','Medium','Low'),

    # One or more specific VIDs. Overrides Severity/RulesFile scoping when supplied.
    [string[]]$StigId,

    # INI include/exclude list. Defaults to <ScriptName>.ini next to this script when present.
    [string]$RulesFile,
    [switch]$IgnoreRulesFile,

    [switch]$ListRules,
    [switch]$PassThru
)

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
function Get-RegValue {{
    param([string]$Path, [string]$Name)
    try {{ (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }}
    catch {{ $null }}
}}

function Set-RegValue {{
    param([string]$Path, [string]$Name, [object]$Value, [string]$Type = "DWord")
    if (!(Test-Path $Path)) {{ New-Item -Path $Path -Force | Out-Null }}
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
}}

function Run-SeceditExport {{
    $temp = [System.IO.Path]::GetTempFileName()
    secedit /export /cfg $temp /areas USER_RIGHTS SECURITYPOLICY /quiet | Out-Null
    $content = Get-Content $temp -Raw
    Remove-Item $temp -Force -ErrorAction SilentlyContinue
    $content
}}

function Get-UserRight {{
    param([string]$RightName)
    $export = Run-SeceditExport
    $line = $export -split "`r`n" | Where-Object {{ $_ -like "*$RightName*" }}
    if ($line) {{
        $sids = ($line -split '=')[1].Trim() -split ','
        $sids | ForEach-Object {{ $_.Trim() }}
    }} else {{ @() }}
}}

function Set-UserRight {{
    param([string]$RightName, [string[]]$AllowedSIDs)
    $temp = [System.IO.Path]::GetTempFileName()
    Run-SeceditExport | Out-File $temp -Encoding ASCII
    (Get-Content $temp) -replace "^$RightName = .*", "$RightName = $($AllowedSIDs -join ',')" | Set-Content $temp -Encoding ASCII
    secedit /configure /db "$env:windir\\security\\database\\secedit.sdb" /cfg $temp /areas USER_RIGHTS /quiet | Out-Null
    Remove-Item $temp -Force -ErrorAction SilentlyContinue
}}

function Run-Auditpol {{
    auditpol /get /category:* /r
}}

# Reads an INI rules file (see {basename}.ini) and returns the VIDs that are still
# active, i.e. NOT commented out with a leading ';' or '#'.
function Get-EnabledStigIdsFromIni {{
    param([string]$Path)
    if (-not (Test-Path $Path)) {{ return $null }}
    $enabled = [System.Collections.Generic.List[string]]::new()
    foreach ($line in Get-Content -Path $Path) {{
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith(';') -or $trimmed.StartsWith('#') -or $trimmed.StartsWith('[')) {{ continue }}
        if ($trimmed -match '^([^=]+?)\\s*=') {{ $enabled.Add($matches[1].Trim()) }}
    }}
    $enabled
}}

# =============================================================================
# STIG RULES ARRAY
#   {auto} of {total} controls classify as a single queryable Registry/UserRight/
#   AuditPolicy check (see .DESCRIPTION). The rest are TODO comments with the full
#   check-content, for a human to classify and finish.
# =============================================================================
$rules = @(
'''

FOOTER = '''
)

# =============================================================================
# SCOPE FILTER (by StigId, else Severity / RulesFile)
# =============================================================================
if ($StigId) {{
    $scoped  = $rules | Where-Object {{ $_.VID -in $StigId }}
    $missing = $StigId | Where-Object {{ $_ -notin $rules.VID }}
    if ($missing) {{
        Write-Warning "No rule found for STIG ID(s): $($missing -join ', ')"
    }}
}} else {{
    $scoped = $rules | Where-Object {{ $_.Severity -in $Severity }}
    if (-not $IgnoreRulesFile) {{
        $iniPath = if ($RulesFile) {{ $RulesFile }} else {{ Join-Path $PSScriptRoot '{basename}.ini' }}
        $enabled = Get-EnabledStigIdsFromIni -Path $iniPath
        if ($null -ne $enabled) {{
            $scoped = $scoped | Where-Object {{ $_.VID -in $enabled }}
            if (-not $PassThru) {{ Write-Host "Rules file   : $iniPath" -ForegroundColor DarkGray }}
        }} elseif ($RulesFile -and -not $PassThru) {{
            Write-Warning "RulesFile '$RulesFile' not found - ignoring."
        }}
    }}
}}

if (-not $scoped) {{
    if (-not $PassThru) {{ Write-Host "No rules match the selected -Severity / -StigId / RulesFile. Nothing to do." -ForegroundColor Yellow }}
    return
}}

if ($ListRules) {{
    if ($PassThru) {{ return $scoped }}
    $scoped | Sort-Object Severity, VID | Format-Table VID, Severity, Title, Description -AutoSize -Wrap
    Write-Host "`n$($scoped.Count) rule(s) in scope." -ForegroundColor Cyan
    return
}}

# =============================================================================
# MAIN EXECUTION
# =============================================================================
$report = @()
$rebootRequired = $false

foreach ($rule in $scoped) {{
    $status = "Non-Compliant"
    $remediated = $false

    switch ($rule.CheckType) {{
        "AccountPolicy" {{
            $export = Run-SeceditExport
            $line = $export -split "`r`n" | Where-Object {{ $_ -like "*$($rule.Policy)*" }}
            $current = if ($line) {{ ($line -split '=')[1].Trim() }} else {{ $null }}
            if ($current -eq $rule.Expected) {{ $status = "Compliant" }}
            elseif ($Remediate) {{ $remediated = $true; $rebootRequired = $true }}
        }}
        "UserRight" {{
            $current = Get-UserRight -RightName $rule.RightName
            if (($current | Sort-Object) -join "," -eq ($rule.Allowed | Sort-Object) -join ",") {{ $status = "Compliant" }}
            elseif ($Remediate) {{ Set-UserRight -RightName $rule.RightName -AllowedSIDs $rule.Allowed; $remediated = $true }}
        }}
        "Registry" {{
            $current = Get-RegValue -Path $rule.Path -Name $rule.Name
            if ($current -eq $rule.Expected) {{ $status = "Compliant" }}
            elseif ($Remediate) {{ Set-RegValue -Path $rule.Path -Name $rule.Name -Value $rule.Expected; $remediated = $true }}
        }}
        "AuditPolicy" {{
            $auditOutput = Run-Auditpol
            $line = $auditOutput | Where-Object {{ $_ -like "*$($rule.SubCategory)*" }}
            $current = if ($line) {{ ($line -split ',')[4].Trim() }} else {{ $null }}
            if ($current -eq $rule.Expected) {{ $status = "Compliant" }}
            elseif ($Remediate) {{ auditpol /set /subcategory:"$($rule.SubCategory)" /success:enable /failure:enable | Out-Null; $remediated = $true }}
        }}
    }}

    $report += [pscustomobject]@{{
        VID         = $rule.VID
        Sev         = $rule.Severity
        Title       = $rule.Title
        Description = $rule.Description
        Status      = $status
        Remediated  = if ($Remediate -and $remediated) {{ "Yes" }} else {{ "No" }}
    }}
}}

# =============================================================================
# OUTPUT
# =============================================================================
if ($PassThru) {{ return $report }}

$report | Sort-Object Sev, VID | Format-Table VID, Sev, Title, Status, Remediated -AutoSize

if ($Remediate) {{
    Write-Host "`nRemediation complete for the in-scope {title} rules." -ForegroundColor Green
    if ($rebootRequired) {{
        Write-Host "A reboot is required for some changes to take effect." -ForegroundColor Yellow
    }}
}} else {{
    Write-Host "`nRun with -Remediate to fix the Non-Compliant items above." -ForegroundColor Cyan
}}

Write-Host "`nNote: only {auto} of {total} controls in this STIG are implemented here. Search this file for '# TODO [V-' for the rest." -ForegroundColor DarkYellow
'''


def render(basename, title, rules_body, counts):
    total = sum(counts.values())
    auto = total - counts.get('Manual', 0)
    ctx = dict(
        basename=basename, title=title, total=total, auto=auto,
        n_registry=counts.get('Registry', 0), n_userright=counts.get('UserRight', 0),
        n_auditpolicy=counts.get('AuditPolicy', 0),
    )
    return HEADER.format(**ctx) + rules_body + FOOTER.format(**ctx)
