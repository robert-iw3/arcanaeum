<#
.SYNOPSIS
    DoD Microsoft Edge STIG Computer V2R4

.DESCRIPTION
    This script checks and remediates registry settings for Microsoft Edge based on the
    DoD STIG Computer V2R4 guidelines. It verifies compliance for various security-related
    settings and can apply fixes when run with the -Remediate switch.

.PARAMETER Remediate
    When specified, the script will attempt to remediate any non-compliant settings by
    applying the expected values to the registry.  Without this switch, the script will
    only report compliance status without making changes.

.EXAMPLE
    .\MicrosoftEdge-STIG-Computer-V2R4.ps1
    This will check the current registry settings against the DoD STIG Computer V2R4
    requirements and output a compliance report without making any changes.

.EXAMPLE
    .\MicrosoftEdge-STIG-Computer-V2R4.ps1 -Remediate
    This will check the current registry settings and attempt to remediate any non-compliant
    settings by applying the expected values. A compliance report will be generated showing
    which settings were remediated.

.NOTES
    Author: Robert Weber
#>

param([switch]$Remediate)

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
    catch { $null }
}

function Set-RegValue {
    param([string]$Path, [string]$Name, [object]$Value, [string]$Type = "DWord")
    if (!(Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
}

# =============================================================================
# STIG RULES ARRAY
# =============================================================================
$rules = @(
    # === Download restrictions ===
    [pscustomobject]@{VID="Edge-DownloadRestrictions"; Title="Allow download restrictions"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="DownloadRestrictions"; Expected=1},

    # === Importing settings (all Disabled) ===
    [pscustomobject]@{VID="Edge-ImportAutofill"; Title="Allow importing of autofill form data"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="ImportAutofillFormData"; Expected=0},
    [pscustomobject]@{VID="Edge-ImportBrowserSettings"; Title="Allow importing of browser settings"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="ImportBrowserSettings"; Expected=0},
    [pscustomobject]@{VID="Edge-ImportBrowsingHistory"; Title="Allow importing of browsing history"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="ImportBrowsingHistory"; Expected=0},
    [pscustomobject]@{VID="Edge-ImportCookies"; Title="Allow importing of Cookies"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="ImportCookies"; Expected=0},
    [pscustomobject]@{VID="Edge-ImportExtensions"; Title="Allow importing of extensions"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="ImportExtensions"; Expected=0},
    [pscustomobject]@{VID="Edge-ImportHomePage"; Title="Allow importing of home page settings"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="ImportHomepage"; Expected=0},
    [pscustomobject]@{VID="Edge-ImportOpenTabs"; Title="Allow importing of open tabs"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="ImportOpenTabs"; Expected=0},
    [pscustomobject]@{VID="Edge-ImportPaymentInfo"; Title="Allow importing of payment info"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="ImportPaymentInfo"; Expected=0},
    [pscustomobject]@{VID="Edge-ImportSavedPasswords"; Title="Allow importing of saved passwords"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="ImportSavedPasswords"; Expected=0},
    [pscustomobject]@{VID="Edge-ImportSearchEngine"; Title="Allow importing of search engine settings"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="ImportSearchEngine"; Expected=0},
    [pscustomobject]@{VID="Edge-ImportShortcuts"; Title="Allow importing of shortcuts"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="ImportShortcuts"; Expected=0},

    # === Media autoplay ===
    [pscustomobject]@{VID="Edge-MediaAutoplay"; Title="Allow media autoplay for websites"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="AutoplayAllowed"; Expected=0},
    [pscustomobject]@{VID="Edge-MediaAutoplaySites"; Title="Allow media autoplay on specific sites"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge\AutoplayAllowlist"; Name="1"; Expected="[*.]gov"},  # and [*.]mil - handled via list

    # === Personalization & tracking ===
    [pscustomobject]@{VID="Edge-Personalization"; Title="Allow personalization of ads..."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="PersonalizationReportingEnabled"; Expected=0},
    [pscustomobject]@{VID="Edge-QUIC"; Title="Allow QUIC protocol"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="QuicAllowed"; Expected=0},
    [pscustomobject]@{VID="Edge-UserFeedback"; Title="Allow user feedback"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="UserFeedbackAllowed"; Expected=0},
    [pscustomobject]@{VID="Edge-PaymentQuery"; Title="Allow websites to query for available payment methods"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="PaymentAllowed"; Expected=0},

    # === Downloads & history ===
    [pscustomobject]@{VID="Edge-AskSaveLocation"; Title="Ask where to save downloaded files"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="AskForSaveLocation"; Expected=1},
    [pscustomobject]@{VID="Edge-TrackingPrevention"; Title="Block tracking of users' web-browsing activity"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="TrackingPreventionLevel"; Expected=2},  # Balanced

    # === InPrivate & paste ===
    [pscustomobject]@{VID="Edge-InPrivate"; Title="Configure InPrivate mode availability"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="InPrivateModeAvailability"; Expected=1},  # Disabled
    [pscustomobject]@{VID="Edge-DefaultPaste"; Title="Configure the default paste format of URLs"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="DefaultPasteFormat"; Expected=1},  # PlainText

    # === Share & background ===
    [pscustomobject]@{VID="Edge-ShareExperience"; Title="Configure the Share experience"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="ShareEnabled"; Expected=0},
    [pscustomobject]@{VID="Edge-BackgroundApps"; Title="Continue running background apps after Microsoft Edge closes"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="BackgroundModeEnabled"; Expected=0},

    # === Copilot & Developer tools ===
    [pscustomobject]@{VID="Edge-CopilotAccess"; Title="Control access to Microsoft 365 Copilot..."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="CopilotEnabled"; Expected=0},
    [pscustomobject]@{VID="Edge-DeveloperTools"; Title="Control where developer tools can be used"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="DeveloperToolsAvailability"; Expected=2},  # Don't allow

    # === Sync & AutoFill ===
    [pscustomobject]@{VID="Edge-Sync"; Title="Disable synchronization of data..."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="SyncDisabled"; Expected=1},
    [pscustomobject]@{VID="Edge-AutoFillAddresses"; Title="Enable AutoFill for addresses"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="AutofillAddressEnabled"; Expected=0},
    [pscustomobject]@{VID="Edge-AutoFillPayments"; Title="Enable AutoFill for payment instruments"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="AutofillCreditCardEnabled"; Expected=0},

    # === History & restart ===
    [pscustomobject]@{VID="Edge-DeleteHistory"; Title="Enable deleting browser and download history"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="AllowDeletingBrowserHistory"; Expected=0},
    [pscustomobject]@{VID="Edge-GuestMode"; Title="Enable guest mode"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="BrowserGuestModeEnabled"; Expected=0},
    [pscustomobject]@{VID="Edge-RestartNotification"; Title="Notify a user that a browser restart is recommended or required"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="RelaunchNotification"; Expected=2},  # Required

    # === Sidebar & Visual search ===
    [pscustomobject]@{VID="Edge-HubsSidebar"; Title="Show Hubs Sidebar"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="HubsSidebarEnabled"; Expected=0},
    [pscustomobject]@{VID="Edge-VisualSearch"; Title="Visual search enabled"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="VisualSearchEnabled"; Expected=0},

    # === Cast & other features ===
    [pscustomobject]@{VID="Edge-GoogleCast"; Title="Enable Google Cast"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="CastEnabled"; Expected=0},

    # === Pop-up & Cookies ===
    [pscustomobject]@{VID="Edge-PopupsAllowedSites"; Title="Allow pop-up windows on specific sites"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge\PopupsAllowed"; Name="1"; Expected="[*.]gov"},  # and [*.]mil
    [pscustomobject]@{VID="Edge-Cookies"; Title="Configure cookies"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="CookieMode"; Expected=4},  # SessionOnly with exceptions

    # === Web APIs ===
    [pscustomobject]@{VID="Edge-WebBluetooth"; Title="Control use of the Web Bluetooth API"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="WebBluetoothBlocklist"; Expected=2},
    [pscustomobject]@{VID="Edge-WebUSB"; Title="Control use of the WebUSB API"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="WebUsbBlocklist"; Expected=2},

    # === Geolocation & more ===
    [pscustomobject]@{VID="Edge-Geolocation"; Title="Default geolocation setting"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="DefaultGeolocationSetting"; Expected=2},  # Block
    [pscustomobject]@{VID="Edge-DefaultPopups"; Title="Default pop-up window setting"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="DefaultPopupsSetting"; Expected=2},  # Block

    # === Extensions & Search ===
    [pscustomobject]@{VID="Edge-BlockExtensions"; Title="Control which extensions cannot be installed"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist"; Name="1"; Expected="*"},
    [pscustomobject]@{VID="Edge-AuthSchemes"; Title="Supported authentication schemes"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="AuthSchemes"; Expected="ntlm,negotiate"},
    [pscustomobject]@{VID="Edge-PasswordManager"; Title="Enable saving passwords to the password manager"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="PasswordManagerEnabled"; Expected=0},

    # === Proxy ===
    [pscustomobject]@{VID="Edge-ProxySettings"; Title="Proxy settings"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="ProxySettings"; Expected="ADD YOUR PROXY CONFIGURATIONS HERE"},

    # === SmartScreen ===
    [pscustomobject]@{VID="Edge-SmartScreen"; Title="Configure Microsoft Defender SmartScreen"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="SmartScreenEnabled"; Expected=1},
    [pscustomobject]@{VID="Edge-SmartScreenPUA"; Title="Configure Microsoft Defender SmartScreen to block potentially unwanted apps"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="SmartScreenPuaEnabled"; Expected=1},
    [pscustomobject]@{VID="Edge-SmartScreenBypassSites"; Title="Prevent bypassing Microsoft Defender SmartScreen prompts for sites"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="PreventSmartScreenPromptOverride"; Expected=1},
    [pscustomobject]@{VID="Edge-SmartScreenBypassDownloads"; Title="Prevent bypassing of Microsoft Defender SmartScreen warnings about downloads"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="PreventSmartScreenPromptOverrideForFiles"; Expected=1},

    # === DNS & other ===
    [pscustomobject]@{VID="Edge-DNSClient"; Title="Use built-in DNS client"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="BuiltInDnsClientEnabled"; Expected=0},
    [pscustomobject]@{VID="Edge-NetworkPrediction"; Title="Enable network prediction"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="NetworkPredictionOptions"; Expected=2}  # Never
)

# =============================================================================
# MAIN EXECUTION
# =============================================================================
$report = @()

foreach ($rule in $rules) {
    $status = "Non-Compliant"
    $remediated = $false

    $current = Get-RegValue -Path $rule.Path -Name $rule.Name

    if ($current -eq $rule.Expected) {
        $status = "Compliant"
    }
    elseif ($Remediate) {
        Set-RegValue -Path $rule.Path -Name $rule.Name -Value $rule.Expected
        $remediated = $true
        $status = "Remediated"
    }

    $report += [pscustomobject]@{
        VID        = $rule.VID
        Title      = $rule.Title
        Status     = $status
        Remediated = if ($Remediate -and $remediated) { "Yes" } else { "No" }
    }
}

# =============================================================================
# OUTPUT REPORT
# =============================================================================
$report | Sort-Object VID | Format-Table -AutoSize

if ($Remediate) {
    Write-Host "`nAll DoD Microsoft Edge STIG Computer V2R4 settings have been remediated!" -ForegroundColor Green
} else {
    Write-Host "`nRun the script with -Remediate to apply fixes." -ForegroundColor Cyan
}
Write-Host "Script complete - DoD Microsoft Edge STIG Computer V2R4 is finished." -ForegroundColor White