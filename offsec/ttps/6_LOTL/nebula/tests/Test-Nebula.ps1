<#
.SYNOPSIS
    Validation script for NEBULA

.DESCRIPTION
    Tests that Nebula.ps1 loads correctly and validates basic functionality
#>

Write-Host ""
Write-Host "╔════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   NEBULA Validation Test Suite        ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$ErrorCount = 0
$SuccessCount = 0

function Test-Function {
    param(
        [string]$TestName,
        [scriptblock]$TestBlock
    )

    Write-Host "[TEST] $TestName... " -NoNewline -ForegroundColor Yellow

    try {
        & $TestBlock
        Write-Host "PASS" -ForegroundColor Green
        $script:SuccessCount++
        return $true
    } catch {
        Write-Host "FAIL" -ForegroundColor Red
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
        $script:ErrorCount++
        return $false
    }
}

# Test 1: Script file exists
Test-Function -TestName "Script file exists" -TestBlock {
    $scriptPath = Join-Path $PSScriptRoot "Nebula.ps1"
    if (-not (Test-Path $scriptPath)) {
        throw "Nebula.ps1 not found"
    }
}

# Test 2: Script has valid PowerShell syntax
Test-Function -TestName "Valid PowerShell syntax" -TestBlock {
    $scriptPath = Join-Path $PSScriptRoot "Nebula.ps1"
    $errors = $null
    $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $scriptPath -Raw), [ref]$errors)
    if ($errors.Count -gt 0) {
        throw "Syntax errors found: $($errors.Count)"
    }
}

# Test 3: WMI availability
Test-Function -TestName "WMI service available" -TestBlock {
    $wmi = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
    if (-not $wmi) {
        throw "WMI not accessible"
    }
}

# Test 4: COM object creation (WScript.Shell)
Test-Function -TestName "WScript.Shell COM object" -TestBlock {
    $wshell = New-Object -ComObject WScript.Shell -ErrorAction Stop
    if (-not $wshell) {
        throw "Cannot create WScript.Shell"
    }
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($wshell) | Out-Null
}

# Test 5: COM object creation (Shell.Application)
Test-Function -TestName "Shell.Application COM object" -TestBlock {
    $shell = New-Object -ComObject Shell.Application -ErrorAction Stop
    if (-not $shell) {
        throw "Cannot create Shell.Application"
    }
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null
}

# Test 6: Win32_Process WMI class accessible
Test-Function -TestName "Win32_Process WMI class" -TestBlock {
    $class = [wmiclass]"Win32_Process"
    if (-not $class) {
        throw "Cannot access Win32_Process class"
    }
}

# Test 7: WMI namespace enumeration
Test-Function -TestName "WMI namespace enumeration" -TestBlock {
    $namespaces = Get-WmiObject -Namespace "root" -Class __NAMESPACE -ErrorAction Stop
    if ($namespaces.Count -eq 0) {
        throw "No WMI namespaces found"
    }
}

# Test 8: PowerShell execution policy check
Test-Function -TestName "Execution policy check" -TestBlock {
    $policy = Get-ExecutionPolicy
    Write-Host "  (Current: $policy) " -NoNewline -ForegroundColor Gray
    if ($policy -eq "Restricted") {
        Write-Host ""
        Write-Host "  WARNING: Execution policy is Restricted. You may need to run:" -ForegroundColor Yellow
        Write-Host "  Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process" -ForegroundColor Yellow
    }
}

# Test 9: Check if running with admin privileges
Test-Function -TestName "Administrator check" -TestBlock {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Host "  (Admin: $isAdmin) " -NoNewline -ForegroundColor Gray
    if (-not $isAdmin) {
        Write-Host ""
        Write-Host "  NOTE: Some techniques require administrator privileges" -ForegroundColor Cyan
    }
}

# Test 10: Validate key functions are defined in script
Test-Function -TestName "Script function definitions" -TestBlock {
    $scriptPath = Join-Path $PSScriptRoot "Nebula.ps1"
    $content = Get-Content $scriptPath -Raw

    $requiredFunctions = @(
        "Show-Banner",
        "Show-MainMenu",
        "Show-WMIMenu",
        "Show-COMMenu",
        "Invoke-WMICalc",
        "Start-Nebula"
    )

    foreach ($func in $requiredFunctions) {
        if ($content -notmatch "function $func") {
            throw "Function $func not found"
        }
    }
}

# Summary
Write-Host ""
Write-Host "════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Test Results:" -ForegroundColor White
Write-Host "  ✓ Passed: $SuccessCount" -ForegroundColor Green
if ($ErrorCount -gt 0) {
    Write-Host "  ✗ Failed: $ErrorCount" -ForegroundColor Red
    Write-Host ""
    Write-Host "Some tests failed. Please review the errors above." -ForegroundColor Red
} else {
    Write-Host ""
    Write-Host "All tests passed! NEBULA is ready to use." -ForegroundColor Green
    Write-Host ""
    Write-Host "Run NEBULA with: .\Nebula.ps1" -ForegroundColor Cyan
}
Write-Host "════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

