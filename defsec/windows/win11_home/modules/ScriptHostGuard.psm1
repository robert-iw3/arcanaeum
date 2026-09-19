<#
.SYNOPSIS
    Neuters the script engines that ClickFix lures and phishing droppers rely on - the
    Home-edition substitute for the AppLocker baseline's Script-collection denies.

.DESCRIPTION
    Without AppLocker there is no way to *deny execution* of wscript.exe/cscript.exe/mshta.exe
    on Windows 11 Home, but the same attack chains can be broken one layer down:

    - Windows Script Host is disabled engine-wide via the registry (Enabled=0). A .vbs/.js/.jse/
      .wsf payload then refuses to run no matter how it is invoked - double-click, Win+R paste,
      or a dropper calling wscript.exe directly. Normal users never run WSH scripts; login-script
      or automation environments that do should skip this module.
    - The double-click file association for every WSH script type is pointed at the Edit verb
      (opens in Notepad) instead of execution, so even if WSH is ever re-enabled, an emailed
      "invoice.js" opens as harmless text.
    - .hta gets an additive Edit verb (Notepad) set as its default, defeating the double-click
      HTA vector. mshta.exe itself still executes .hta files passed to it directly - that
      residual path is covered by LolbinEgressGuard (mshta cannot reach the network to fetch or
      call back) and, on Pro/Enterprise, by the applocker baseline's explicit mshta deny.

    All changes are HKLM registry values, reversible per value by the Rollback function.
#>

$script:WshKey = 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings'

# ProgIds whose shell default verb is flipped to the built-in 'Edit' (Notepad) verb. Each of
# these classes ships with an Edit verb out of the box, so setting the default is additive -
# rollback just removes the default value and Windows falls back to the 'open' (execute) verb.
$script:EditDefaultProgIds = @('JSFile', 'JSEFile', 'VBSFile', 'VBEFile', 'WSFFile', 'WSHFile')

$script:HtaShellKey = 'HKLM:\SOFTWARE\Classes\htafile\shell'

function Get-ScriptHostGuardStatus {
    $out = @()
    $wsh = (Get-ItemProperty -Path $script:WshKey -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled
    if ($wsh -eq 0) {
        $out += 'Windows Script Host: disabled (Enabled=0)'
    } else {
        $out += "Windows Script Host: ENABLED (a pasted or double-clicked .vbs/.js payload will run)"
    }
    foreach ($progId in $script:EditDefaultProgIds) {
        $shellKey = "HKLM:\SOFTWARE\Classes\$progId\Shell"
        $default = (Get-ItemProperty -Path $shellKey -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
        if ($default -eq 'Edit') {
            $out += "${progId}: double-click opens in editor (default verb = Edit)"
        } else {
            $out += "${progId}: double-click EXECUTES (default verb = $(if ($default) { $default } else { 'open, implicit' }))"
        }
    }
    $htaDefault = (Get-ItemProperty -Path $script:HtaShellKey -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
    if ($htaDefault -eq 'Edit') {
        $out += 'htafile: double-click opens in editor (default verb = Edit)'
    } else {
        $out += 'htafile: double-click EXECUTES via mshta.exe'
    }
    $out
}

function Invoke-ScriptHostGuardHardening {
    param([switch]$Remediate)
    $out = @()
    if ($Remediate) {
        if (-not (Test-Path $script:WshKey)) { New-Item -Path $script:WshKey -Force | Out-Null }
        Set-ItemProperty -Path $script:WshKey -Name 'Enabled' -Value 0 -Type DWord
        $out += 'Disabled Windows Script Host engine-wide (Enabled=0) - .vbs/.js/.jse/.wsf payloads no longer run.'

        foreach ($progId in $script:EditDefaultProgIds) {
            $shellKey = "HKLM:\SOFTWARE\Classes\$progId\Shell"
            if (-not (Test-Path $shellKey)) { New-Item -Path $shellKey -Force | Out-Null }
            Set-ItemProperty -Path $shellKey -Name '(default)' -Value 'Edit'
            $out += "Set $progId default verb to Edit - double-click opens the script in an editor instead of executing it."
        }

        # htafile has no built-in Edit verb - add one (Notepad) and make it the default. The
        # original 'open' verb (mshta) is left untouched so rollback is a pure delete.
        $htaEditCmdKey = Join-Path (Join-Path $script:HtaShellKey 'Edit') 'command'
        if (-not (Test-Path $htaEditCmdKey)) { New-Item -Path $htaEditCmdKey -Force | Out-Null }
        Set-ItemProperty -Path $htaEditCmdKey -Name '(default)' -Value "$env:SystemRoot\System32\notepad.exe `"%1`""
        Set-ItemProperty -Path $script:HtaShellKey -Name '(default)' -Value 'Edit'
        $out += 'Added an Edit (Notepad) verb to htafile and made it the double-click default - .hta lures open as text.'
    } else {
        $out += "(dry run) Would disable Windows Script Host at $script:WshKey (Enabled=0)."
        $out += "(dry run) Would set the shell default verb to Edit for: $($script:EditDefaultProgIds -join ', ')."
        $out += '(dry run) Would add a Notepad Edit verb to htafile and make it the double-click default.'
    }
    $out
}

function Invoke-ScriptHostGuardRollback {
    param([switch]$Remediate)
    $out = @()
    if ($Remediate) {
        try {
            Remove-ItemProperty -Path $script:WshKey -Name 'Enabled' -Force -ErrorAction Stop
            $out += 'Re-enabled Windows Script Host (removed the Enabled=0 override).'
        } catch {
            $out += "Windows Script Host override not present or not removable: $($_.Exception.Message)"
        }
        foreach ($progId in $script:EditDefaultProgIds) {
            $shellKey = "HKLM:\SOFTWARE\Classes\$progId\Shell"
            try {
                Remove-ItemProperty -Path $shellKey -Name '(default)' -Force -ErrorAction Stop
                $out += "Restored $progId double-click behavior (removed the Edit default verb override)."
            } catch {
                $out += "$progId default verb override not present: nothing to undo."
            }
        }
        try {
            Remove-ItemProperty -Path $script:HtaShellKey -Name '(default)' -Force -ErrorAction Stop
            Remove-Item -Path (Join-Path $script:HtaShellKey 'Edit') -Recurse -Force -ErrorAction Stop
            $out += 'Restored htafile double-click behavior and removed the added Edit verb.'
        } catch {
            $out += "htafile overrides not present or not removable: $($_.Exception.Message)"
        }
    } else {
        $out += "(dry run) Would remove the WSH Enabled=0 override, the Edit default verbs on $($script:EditDefaultProgIds -join ', '), and the added htafile Edit verb."
    }
    $out
}

Export-ModuleMember -Function Get-ScriptHostGuardStatus, Invoke-ScriptHostGuardHardening, Invoke-ScriptHostGuardRollback
