<#
.SYNOPSIS
    Data Sensor - Rust Engine Compiler Pipeline

.DESCRIPTION
    Compiles the native Rust Machine Learning engine into a C-Compatible Dynamic
    Link Library (DataSensor_ML.dll). Acquires TraceEvent dependencies via NuGet
    and executes cryptographic hashing for verification.

@RW
#>
#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'
$WorkingDir = $PWD.Path
$ProjectDir = $WorkingDir
$BinDir = Join-Path $WorkingDir "Bin"
$DepDir = "C:\ProgramData\DataSensor\Dependencies"

$ESC = [char]27
$cRed = "$ESC[91m"; $cCyan = "$ESC[96m"; $cGreen = "$ESC[92m"; $cYellow = "$ESC[93m"; $cReset = "$ESC[0m"

Write-Host "`n$cCyan[*] INITIATING DATA SENSOR RUST COMPILER PIPELINE (v1.0)$cReset"

# ============================================================================
# 1. MSVC BUILD TOOLS VALIDATION
# ============================================================================
Write-Host "    [*] Verifying MSVC Desktop Workload & Universal C Runtime (UCRT)..." -ForegroundColor Gray
$vsWherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsInstallPath = $null

if (Test-Path $vsWherePath) {
    $paths = & $vsWherePath -latest -products * -property installationPath
    if ($paths) { if ($paths -is [array]) { $vsInstallPath = $paths[0] } else { $vsInstallPath = $paths } }
}

if (-not $vsInstallPath) {
    Write-Host "`n$cRed[!] CRITICAL FAILURE: Microsoft Visual C++ Build Tools not found.$cReset"
    Write-Host "$cYellow[!] The Rust compiler requires the MSVC toolchain to link the Native DLL.$cReset"
    Exit
}
Write-Host "    [+] MSVC Toolchain verified at: $vsInstallPath" -ForegroundColor Green

# ============================================================================
# 2. DEPENDENCY ACQUISITION (NuGet: TraceEvent)
# ============================================================================
Write-Host "`n    [*] Validating unmanaged C# Dependencies..." -ForegroundColor Gray
if (-not (Test-Path $DepDir)) { New-Item -ItemType Directory -Path $DepDir -Force | Out-Null }
$TraceEventDll = Join-Path $DepDir "Microsoft.Diagnostics.Tracing.TraceEvent.dll"

if (-not (Test-Path $TraceEventDll)) {
    Write-Host "    [*] Acquiring TraceEvent package from NuGet..." -ForegroundColor Yellow
    $NugetUrl = "https://www.nuget.org/api/v2/package/Microsoft.Diagnostics.Tracing.TraceEvent/3.2.2"
    $ZipPath = Join-Path $DepDir "traceevent.zip"
    $ExtractPath = Join-Path $DepDir "extracted"

    Invoke-WebRequest -Uri $NugetUrl -OutFile $ZipPath -UseBasicParsing
    Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force

    $ExtractedDll = Join-Path $ExtractPath "lib\netstandard2.0\Microsoft.Diagnostics.Tracing.TraceEvent.dll"
    Copy-Item $ExtractedDll -Destination $TraceEventDll -Force

    Remove-Item $ZipPath -Force
    Remove-Item $ExtractPath -Recurse -Force
    Write-Host "    [+] TraceEvent.dll staged successfully in ProgramData." -ForegroundColor Green
} else {
    Write-Host "    [+] TraceEvent.dll already staged." -ForegroundColor Green
}

# ============================================================================
# 3. RUST COMPILATION PIPELINE (WORKSPACE)
# ============================================================================
if (-not (Test-Path $BinDir)) { New-Item -ItemType Directory -Path $BinDir -Force | Out-Null }

Write-Host "`n    [*] Prepping Cargo build environment for Workspace..." -ForegroundColor Gray

Write-Host "    [*] Purging Cargo Cache and stale locks..." -ForegroundColor Yellow
& cmd.exe /c "cd /d `"$ProjectDir`" && cargo clean"

$CompileWrapper = Join-Path $WorkingDir "compile_native.cmd"
$WrapperLogic = @"
@echo off
cd /d "$ProjectDir"
set RUSTFLAGS=-C target-feature=+crt-static
cargo build --release --workspace
exit /b %ERRORLEVEL%
"@
Set-Content -Path $CompileWrapper -Value $WrapperLogic

try {
    Write-Host "    [*] Executing Cargo Release Build (ML & Hook Engines)..." -ForegroundColor Yellow
    & cmd.exe /c $CompileWrapper

    if ($LASTEXITCODE -ne 0) {
        Write-Host "`n$cRed[!] COMPILATION FAILED: Cargo returned exit code $LASTEXITCODE$cReset"
        Exit
    }

    # ============================================================================
    # 4. EXTRACTION, STAGING & CLEANUP
    # ============================================================================
    $CompiledMlDll   = Join-Path $ProjectDir "target\release\data_sensor_ml.dll"
    $CompiledHookDll = Join-Path $ProjectDir "target\release\data_sensor_hook.dll"
    $FinalMlDest     = Join-Path $ProjectDir "DataSensor_ML.dll"
    $FinalHookDest   = Join-Path $ProjectDir "DataSensor_Hook.dll"

    if ((Test-Path $CompiledMlDll) -and (Test-Path $CompiledHookDll)) {

        Copy-Item -Path $CompiledMlDll   -Destination $FinalMlDest   -Force
        Copy-Item -Path $CompiledHookDll -Destination $FinalHookDest -Force

        Write-Host "`n$cGreen[+] SUCCESS: Native Data Sensor Engines Compiled Successfully.$cReset"

        $MlHash   = (Get-FileHash -Path $FinalMlDest   -Algorithm SHA256).Hash
        $HookHash = (Get-FileHash -Path $FinalHookDest -Algorithm SHA256).Hash

        Write-Host "    -> DataSensor_ML.dll   | SHA256: $MlHash"   -ForegroundColor DarkGray
        Write-Host "    -> DataSensor_Hook.dll | SHA256: $HookHash`n" -ForegroundColor DarkGray

        $ManifestPath = Join-Path $ProjectDir "checksums.sha256"
@"
$MlHash  DataSensor_ML.dll
$HookHash  DataSensor_Hook.dll
"@ | Set-Content -Path $ManifestPath -Encoding ASCII -Force
        Write-Host "    -> Hash manifest written to: $ManifestPath" -ForegroundColor DarkGray

        Write-Host "    [*] Cleaning up temporary compilation directories..." -ForegroundColor Yellow
        Remove-Item -Path (Join-Path $ProjectDir "target") -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path (Join-Path $ProjectDir "Bin") -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "`n$cRed[!] ERROR: Expected output DLLs not found in target/release directory.$cReset"
    }
} finally {
    Remove-Item $CompileWrapper -Force -ErrorAction SilentlyContinue
}