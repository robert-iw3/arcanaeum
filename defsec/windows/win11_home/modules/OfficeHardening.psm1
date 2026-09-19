<#
.SYNOPSIS
    Opt-in: hardens Microsoft Office against the document-borne attack chain beyond macros -
    blocks macros from the internet, kills the DDE auto-execute vector, and pins Protected View
    on. Auto-skips if desktop Office isn't installed.

.DESCRIPTION
    OfficeMacroGuard uses Defender ASR to stop a macro spawning processes. This module hardens
    Office's own settings so the malicious document is defanged earlier:

    - blockcontentexecutionfrominternet = 1 (Word/Excel/PowerPoint): macros in files that came
      from the internet are blocked outright, regardless of the "Enable Content" button - this is
      the setting that stops the classic "enable macros to view this document" lure.
    - Protected View kept ON for internet files, unsafe locations, and Outlook attachments
      (DisableInternetFilesInPV/DisableUnsafeLocationsInPV/DisableAttachmentsInPV = 0) - so a
      booby-trapped document opens sandboxed, read-only, with no active content.
    - DDE auto-execute disabled in Word and Excel (the macro-less "update links / run this field"
      code-execution trick).

    Scope: writes HKCU policy under office\16.0 (Office 2016/2019/2021/Microsoft 365). If no
    desktop Office is detected, the module reports that and makes no changes (the Office web apps
    are unaffected and need none of this).

    OPT-IN: harmless where Office is installed, but pointless where it isn't, and
    blockcontentexecutionfrominternet can inconvenience a household that legitimately runs a macro
    workbook downloaded from a trusted portal (they can mark it Trusted, or use a Trusted Location).

    Balance: does NOT disable macros wholesale (a trusted local budgeting/church macro still runs);
    it targets internet-originated content and DDE specifically.
#>

$script:OfficeRoot = 'HKCU:\SOFTWARE\Policies\Microsoft\office\16.0'
$script:MacroApps = @('word', 'excel', 'powerpoint')

function Test-OfficeInstalled {
    foreach ($hive in 'HKLM:\SOFTWARE\Microsoft\Office\16.0', 'HKCU:\SOFTWARE\Microsoft\Office\16.0',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\16.0') {
        if (Test-Path $hive) {
            foreach ($app in $script:MacroApps + @('Outlook')) {
                if (Test-Path (Join-Path $hive $app)) { return $true }
            }
        }
    }
    return $false
}

function Get-OfficeHardeningStatus {
    if (-not (Test-OfficeInstalled)) {
        return @('Desktop Microsoft Office (16.0) not detected - module is a no-op here.')
    }
    $out = @()
    foreach ($app in $script:MacroApps) {
        $v = (Get-ItemProperty -Path "$script:OfficeRoot\$app\security" -Name 'blockcontentexecutionfrominternet' -ErrorAction SilentlyContinue).blockcontentexecutionfrominternet
        $out += "${app}: macros-from-internet $(if ($v -eq 1) { 'blocked' } else { 'not blocked' })."
    }
    $out
}

function Set-OfficeValue {
    param([string]$Path, [string]$Name, $Value)
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -ErrorAction Stop
        $null
    } catch { "SKIPPED ${Path}\${Name}: $($_.Exception.Message)" }
}

function Invoke-OfficeHardeningHardening {
    param([switch]$Remediate)
    if (-not (Test-OfficeInstalled)) {
        if ($Remediate) { return @('Desktop Microsoft Office (16.0) not detected - nothing to harden.') }
        return @('(dry run) Desktop Microsoft Office (16.0) not detected - this module would make no changes on this machine.')
    }
    if (-not $Remediate) {
        return @(
            '(dry run) Would block macros from the internet and keep Protected View on for Word/Excel/PowerPoint.',
            '(dry run) Would disable the DDE auto-execute vector in Word and Excel.'
        )
    }
    $out = @()
    $errs = @()
    foreach ($app in $script:MacroApps) {
        $secKey = "$script:OfficeRoot\$app\security"
        $errs += Set-OfficeValue -Path $secKey -Name 'blockcontentexecutionfrominternet' -Value 1
        $pvKey = "$secKey\protectedview"
        $errs += Set-OfficeValue -Path $pvKey -Name 'DisableInternetFilesInPV' -Value 0
        $errs += Set-OfficeValue -Path $pvKey -Name 'DisableUnsafeLocationsInPV' -Value 0
        $errs += Set-OfficeValue -Path $pvKey -Name 'DisableAttachmentsInPV' -Value 0
    }
    $out += 'Blocked macros from the internet and pinned Protected View on for Word/Excel/PowerPoint.'
    # DDE auto-execute off (Word + Excel).
    $errs += Set-OfficeValue -Path "$script:OfficeRoot\word\options" -Name 'DontUpdateLinks' -Value 1
    $errs += Set-OfficeValue -Path "$script:OfficeRoot\excel\options" -Name 'DontUpdateLinks' -Value 1
    $errs += Set-OfficeValue -Path "$script:OfficeRoot\excel\security" -Name 'WorkbookLinkWarnings' -Value 2
    $out += 'Disabled the DDE auto-execute vector in Word and Excel.'
    $errs = @($errs | Where-Object { $_ })
    if ($errs) { $out += $errs }
    $out
}

function Invoke-OfficeHardeningRollback {
    param([switch]$Remediate)
    if ($Remediate) {
        foreach ($app in $script:MacroApps) {
            Remove-ItemProperty -Path "$script:OfficeRoot\$app\security" -Name 'blockcontentexecutionfrominternet' -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "$script:OfficeRoot\$app\security\protectedview" -Recurse -Force -ErrorAction SilentlyContinue
        }
        Remove-ItemProperty -Path "$script:OfficeRoot\word\options" -Name 'DontUpdateLinks' -Force -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "$script:OfficeRoot\excel\options" -Name 'DontUpdateLinks' -Force -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "$script:OfficeRoot\excel\security" -Name 'WorkbookLinkWarnings' -Force -ErrorAction SilentlyContinue
        @('Removed the Office hardening policy overrides.')
    } else {
        @('(dry run) Would remove the Office hardening policy overrides.')
    }
}

Export-ModuleMember -Function Get-OfficeHardeningStatus, Invoke-OfficeHardeningHardening, Invoke-OfficeHardeningRollback, Test-OfficeInstalled
