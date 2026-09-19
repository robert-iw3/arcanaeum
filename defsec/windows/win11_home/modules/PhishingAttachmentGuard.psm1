<#
.SYNOPSIS
    Forces downloaded files and email attachments to keep their Mark-of-the-Web and be
    AV-scanned + SmartScreen-checked before they run - the registry replacement for the
    applocker baseline's "deny execution from Outlook/browser cache" rules.

.DESCRIPTION
    The applocker version of this module denied *execution* from Outlook's attachment cache and
    every browser's cache directory - locations a payload lands in before the user ever saves
    it. Windows 11 Home has no AppLocker to write those path denies, so this module reaches the
    same outcome one layer up, through the Attachment Manager, which is what tags a file with
    where it came from (the Mark-of-the-Web / Zone.Identifier alternate data stream) and drives
    the "this file came from another computer" gate:

    - SaveZoneInformation=2: Windows must PRESERVE the Mark-of-the-Web on saved attachments and
      downloads. This is the linchpin - MOTW is what makes SmartScreen, Defender, and Office
      Protected View treat a file as untrusted. (The dangerous setting, =1, strips it, and some
      "optimizer" tools set that; this pins it back.)
    - ScanWithAntiVirus=3: attachments are always handed to the registered AV (Defender) for a
      scan on open.
    - HideZoneInfoOnProperties=0: the "this file came from another computer - Unblock" control
      stays visible, so a user can make an informed choice rather than it being hidden.
    - DefaultFileTypeRisk=High: files of unknown/unlisted type are treated as high-risk (warn
      before running) rather than silently trusted.

    Together these ensure a payload delivered by email or web download cannot lose its
    untrusted marking - which is exactly what its author wants it to do to slip past SmartScreen
    and Defender. Registry-only, no execution is blocked outright, so there's no legitimate-file
    collateral: a real download the user chose still opens after the normal warning.

    Scope note: Attachment Manager policy is per-user; this writes the machine policy hive
    (HKLM) which Windows honors over per-user, plus the current user's hive. New user profiles
    inherit the HKLM policy.
#>

$script:AttachKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'
)
$script:AssocKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Associations',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Associations'
)

# name -> value written to each Attachments key. SaveZoneInformation=2 => preserve MOTW.
$script:AttachValues = [ordered]@{
    SaveZoneInformation      = 2
    ScanWithAntiVirus        = 3
    HideZoneInfoOnProperties = 0
}
# High-risk default for unlisted file types (0x6152). Warn before executing.
$script:DefaultFileTypeRisk = 6152

function Get-PhishingAttachmentGuardStatus {
    $primary = $script:AttachKeys[0]
    $saveZone = (Get-ItemProperty -Path $primary -Name 'SaveZoneInformation' -ErrorAction SilentlyContinue).SaveZoneInformation
    $scan = (Get-ItemProperty -Path $primary -Name 'ScanWithAntiVirus' -ErrorAction SilentlyContinue).ScanWithAntiVirus
    @(
        "Mark-of-the-Web preservation: $(if ($saveZone -eq 2) { 'forced on (downloads/attachments stay marked untrusted)' } else { 'not enforced (a tool or policy could strip MOTW, blinding SmartScreen/Defender)' })"
        "Attachment AV scan on open: $(if ($scan -eq 3) { 'always' } else { 'not forced' })"
    )
}

function Invoke-PhishingAttachmentGuardHardening {
    param([switch]$Remediate)
    $out = @()
    foreach ($key in $script:AttachKeys) {
        if ($Remediate) {
            if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
            foreach ($name in $script:AttachValues.Keys) {
                Set-ItemProperty -Path $key -Name $name -Value $script:AttachValues[$name] -Type DWord
            }
            $out += "Set Attachment Manager policy at $key (preserve Mark-of-the-Web, always AV-scan, keep Unblock visible)."
        } else {
            $out += "(dry run) Would set Attachment Manager policy at $key (SaveZoneInformation=2, ScanWithAntiVirus=3, HideZoneInfoOnProperties=0)."
        }
    }
    foreach ($key in $script:AssocKeys) {
        if ($Remediate) {
            if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
            Set-ItemProperty -Path $key -Name 'DefaultFileTypeRisk' -Value $script:DefaultFileTypeRisk -Type DWord
            $out += "Set DefaultFileTypeRisk=High at $key (unknown file types warned before running)."
        } else {
            $out += "(dry run) Would set DefaultFileTypeRisk=High at $key."
        }
    }
    $out
}

function Invoke-PhishingAttachmentGuardRollback {
    param([switch]$Remediate)
    $out = @()
    foreach ($key in $script:AttachKeys) {
        foreach ($name in $script:AttachValues.Keys) {
            if ($Remediate) {
                Remove-ItemProperty -Path $key -Name $name -Force -ErrorAction SilentlyContinue
            }
        }
        $out += if ($Remediate) { "Removed Attachment Manager policy overrides at $key." } else { "(dry run) Would remove Attachment Manager policy overrides at $key." }
    }
    foreach ($key in $script:AssocKeys) {
        if ($Remediate) {
            Remove-ItemProperty -Path $key -Name 'DefaultFileTypeRisk' -Force -ErrorAction SilentlyContinue
            $out += "Removed DefaultFileTypeRisk override at $key."
        } else {
            $out += "(dry run) Would remove DefaultFileTypeRisk override at $key."
        }
    }
    $out
}

Export-ModuleMember -Function Get-PhishingAttachmentGuardStatus, Invoke-PhishingAttachmentGuardHardening, Invoke-PhishingAttachmentGuardRollback
