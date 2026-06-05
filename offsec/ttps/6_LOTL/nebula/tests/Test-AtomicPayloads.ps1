<#
.SYNOPSIS
    Test script to validate Atomic Red Team payload integration in NEBULA

.DESCRIPTION
    This script validates that all Atomic Red Team payloads are properly
    integrated and accessible from the examples folder.
#>

Write-Host ""
Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  NEBULA - Atomic Red Team Payload Validation" -ForegroundColor Yellow
Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

$script:PassCount = 0
$script:FailCount = 0

function Test-FileExists {
    param(
        [string]$FilePath,
        [string]$Description
    )

    Write-Host "Testing: " -NoNewline -ForegroundColor White
    Write-Host $Description -ForegroundColor Gray

    if (Test-Path $FilePath) {
        Write-Host "  [✓] PASS - File exists: $FilePath" -ForegroundColor Green
        $script:PassCount++
        return $true
    } else {
        Write-Host "  [✗] FAIL - File not found: $FilePath" -ForegroundColor Red
        $script:FailCount++
        return $false
    }
}

function Test-FileContent {
    param(
        [string]$FilePath,
        [string]$SearchString,
        [string]$Description
    )

    Write-Host "Testing: " -NoNewline -ForegroundColor White
    Write-Host $Description -ForegroundColor Gray

    if (-not (Test-Path $FilePath)) {
        Write-Host "  [✗] FAIL - File not found: $FilePath" -ForegroundColor Red
        $script:FailCount++
        return $false
    }

    $content = Get-Content $FilePath -Raw
    if ($content -match $SearchString) {
        Write-Host "  [✓] PASS - Content found in file" -ForegroundColor Green
        $script:PassCount++
        return $true
    } else {
        Write-Host "  [✗] FAIL - Content not found: $SearchString" -ForegroundColor Red
        $script:FailCount++
        return $false
    }
}

Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "  File Existence Tests" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host ""

# Test all payload files exist
Test-FileExists -FilePath "examples\regsvr32_squiblydoo.sct" -Description "RegSvr32 Squiblydoo payload"
Test-FileExists -FilePath "examples\mshta_calc.hta" -Description "MSHTA calc payload"
Test-FileExists -FilePath "examples\rundll32_calc.sct" -Description "Rundll32 SCT payload"
Test-FileExists -FilePath "examples\rundll32_javascript.txt" -Description "Rundll32 reference"
Test-FileExists -FilePath "examples\msbuild_inline_task.csproj" -Description "MSBuild project file"
Test-FileExists -FilePath "examples\certutil_download.txt" -Description "CertUtil reference"
Test-FileExists -FilePath "examples\bitsadmin_transfer.txt" -Description "BITSAdmin reference"
Test-FileExists -FilePath "examples\installutil_bypass.txt" -Description "InstallUtil reference"
Test-FileExists -FilePath "examples\README.md" -Description "Examples README"

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "  Content Validation Tests" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host ""

# Test that payloads contain expected content
Test-FileContent -FilePath "examples\regsvr32_squiblydoo.sct" -SearchString "scriptlet" -Description "RegSvr32 contains scriptlet XML"
Test-FileContent -FilePath "examples\mshta_calc.hta" -SearchString "calc\.exe" -Description "MSHTA contains calc.exe reference"
Test-FileContent -FilePath "examples\rundll32_calc.sct" -SearchString "calc\.exe" -Description "Rundll32 contains calc.exe reference"
Test-FileContent -FilePath "examples\msbuild_inline_task.csproj" -SearchString "CodeTaskFactory" -Description "MSBuild contains inline task"
Test-FileContent -FilePath "examples\certutil_download.txt" -SearchString "certutil.*-urlcache" -Description "CertUtil contains -urlcache"
Test-FileContent -FilePath "examples\bitsadmin_transfer.txt" -SearchString "bitsadmin" -Description "BITSAdmin contains bitsadmin command"

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "  Attribution Tests" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host ""

# Test that attribution is present
Test-FileContent -FilePath "examples\README.md" -SearchString "Atomic Red Team" -Description "Examples README mentions Atomic Red Team"
Test-FileContent -FilePath "examples\certutil_download.txt" -SearchString "Atomic Red Team" -Description "CertUtil reference contains attribution"
Test-FileContent -FilePath "examples\bitsadmin_transfer.txt" -SearchString "Atomic Red Team" -Description "BITSAdmin reference contains attribution"
Test-FileContent -FilePath "README.md" -SearchString "Atomic Red Team" -Description "Main README contains attribution"

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "  Integration Tests" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host ""

# Test that Nebula.ps1 references the new payloads
Test-FileContent -FilePath "Nebula.ps1" -SearchString "regsvr32_squiblydoo\.sct" -Description "Nebula.ps1 uses regsvr32_squiblydoo.sct"
Test-FileContent -FilePath "Nebula.ps1" -SearchString "mshta_calc\.hta" -Description "Nebula.ps1 uses mshta_calc.hta"
Test-FileContent -FilePath "Nebula.ps1" -SearchString "rundll32_calc\.sct" -Description "Nebula.ps1 uses rundll32_calc.sct"
Test-FileContent -FilePath "Nebula.ps1" -SearchString "msbuild_inline_task\.csproj" -Description "Nebula.ps1 uses msbuild_inline_task.csproj"
Test-FileContent -FilePath "Nebula.ps1" -SearchString "certutil_download\.txt" -Description "Nebula.ps1 references certutil_download.txt"
Test-FileContent -FilePath "Nebula.ps1" -SearchString "bitsadmin_transfer\.txt" -Description "Nebula.ps1 references bitsadmin_transfer.txt"
Test-FileContent -FilePath "Nebula.ps1" -SearchString "installutil_bypass\.txt" -Description "Nebula.ps1 references installutil_bypass.txt"

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Test Summary" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Total Tests: " -NoNewline -ForegroundColor White
Write-Host ($script:PassCount + $script:FailCount) -ForegroundColor Gray
Write-Host "  Passed: " -NoNewline -ForegroundColor White
Write-Host $script:PassCount -ForegroundColor Green
Write-Host "  Failed: " -NoNewline -ForegroundColor White
Write-Host $script:FailCount -ForegroundColor $(if ($script:FailCount -eq 0) { "Green" } else { "Red" })
Write-Host ""

if ($script:FailCount -eq 0) {
    Write-Host "  ✓ ALL TESTS PASSED!" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Atomic Red Team payloads are properly integrated." -ForegroundColor Cyan
    exit 0
} else {
    Write-Host "  ✗ SOME TESTS FAILED" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Please review the failures above." -ForegroundColor Yellow
    exit 1
}

