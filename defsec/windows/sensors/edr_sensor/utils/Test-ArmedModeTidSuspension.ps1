<#
.SYNOPSIS
    End-to-end test of TID suspension. Dot-sourced in-process by the launcher's 'T' hotkey
    (same session as a running -ArmedMode launcher).
.DESCRIPTION
    Spawns a plain cmd.exe target, calls the real native containment methods on
    [DeepVisibilitySensor] directly (QuarantineNativeThread, CorrelateOnDiskArtifacts,
    PreserveForensics, ResumeNativeThread), and verifies each result against the OS.
    cmd.exe is used because powershell.exe/pwsh.exe are JIT-runtime-excluded by design.
#>

$failCount = 0

# Routes through the HUD's bounded alert panel when dot-sourced into the launcher (Add-AlertMessage
# exists in that session), falling back to plain Write-Host for standalone diagnostic runs -- and
# always writes to the diagnostic log too, so a live-test run leaves a permanent, greppable trace
# instead of just flashing on screen and scrolling away.
function Pass([string]$m) {
    if (Get-Command Add-AlertMessage -ErrorAction SilentlyContinue) { Add-AlertMessage "LIVE TEST PASS: $m" "$([char]27)[92;40m" }
    else { Write-Host "  [PASS] $m" -ForegroundColor Green }
    if (Get-Command Write-Diag -ErrorAction SilentlyContinue) { Write-Diag "[LIVE TEST] PASS: $m" "INFO" }
}
function Fail([string]$m) {
    if (Get-Command Add-AlertMessage -ErrorAction SilentlyContinue) { Add-AlertMessage "LIVE TEST FAIL: $m" "$([char]27)[91;40m" }
    else { Write-Host "  [FAIL] $m" -ForegroundColor Red }
    if (Get-Command Write-Diag -ErrorAction SilentlyContinue) { Write-Diag "[LIVE TEST] FAIL: $m" "WARN" }
    $script:failCount++
}

# NOTE: this script is dot-sourced (`. $liveTestPath`) by the launcher's 'T' hotkey, not run as
# its own process -- `exit` here would terminate the entire armed-mode sensor, not just the test.
# Every early-out below uses `return` instead.

if (-not ("DeepVisibilitySensor" -as [type])) {
    Fail "DeepVisibilitySensor not loaded in this session. Run via the launcher's 'T' hotkey, not standalone."
    return
}

$proc = $null
try {
    $proc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c timeout /t 180 /nobreak >nul" -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 800
    $proc.Refresh()
    $tids = @($proc.Threads | ForEach-Object { $_.Id })
    if ($tids.Count -lt 2) { Fail "Target presented $($tids.Count) threads, need >=2"; return }
    Pass "Target PID $($proc.Id) has $($tids.Count) threads"
    $tid = $tids[-1]

    $suspended = [DeepVisibilitySensor]::QuarantineNativeThread($tid, $proc.Id)
    Start-Sleep -Milliseconds 500
    $proc.Refresh()
    $t = $proc.Threads | Where-Object Id -eq $tid
    if ($suspended -and $t.ThreadState -eq 'Wait' -and $t.WaitReason -eq 'Suspended') {
        Pass "TID $tid suspended (ThreadState=Wait, WaitReason=Suspended)"
    } else {
        Fail "TID $tid not suspended (result=$suspended, state=$($t.ThreadState)/$($t.WaitReason))"
    }

    $artJson = [DeepVisibilitySensor]::CorrelateOnDiskArtifacts($proc.Id) | ConvertFrom-Json
    if ($artJson.ImageSHA256 -and $artJson.ImagePath -match 'cmd\.exe') {
        Pass "Artifact correlation returned image path + hash: $($artJson.ImagePath)"
    } else {
        Fail "Artifact correlation missing expected fields: $($artJson | ConvertTo-Json -Compress)"
    }

    $dumpPath = [DeepVisibilitySensor]::PreserveForensics($proc.Id, "cmd.exe")
    if ($dumpPath -and (Test-Path $dumpPath)) {
        Pass "Forensic dump written: $dumpPath"
    } else {
        Fail "Forensic dump not written (result=$dumpPath)"
    }

    $resumed = [DeepVisibilitySensor]::ResumeNativeThread($tid)
    Start-Sleep -Milliseconds 500
    $proc.Refresh()
    $t2 = $proc.Threads | Where-Object Id -eq $tid
    if ($resumed -and -not ($t2.ThreadState -eq 'Wait' -and $t2.WaitReason -eq 'Suspended')) {
        Pass "TID $tid resumed"
    } else {
        Fail "TID $tid did not resume cleanly (result=$resumed)"
    }
} finally {
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
}

if ($failCount -eq 0) {
    if (Get-Command Add-AlertMessage -ErrorAction SilentlyContinue) { Add-AlertMessage "LIVE TEST: ALL STAGES PASSED" "$([char]27)[92;40m" }
    else { Write-Host "=== ALL STAGES PASSED ===" -ForegroundColor Green }
    if (Get-Command Write-Diag -ErrorAction SilentlyContinue) { Write-Diag "[LIVE TEST] ALL STAGES PASSED" "STARTUP" }
} else {
    if (Get-Command Add-AlertMessage -ErrorAction SilentlyContinue) { Add-AlertMessage "LIVE TEST: $failCount STAGE(S) FAILED" "$([char]27)[91;40m" }
    else { Write-Host "=== $failCount STAGE(S) FAILED ===" -ForegroundColor Red }
    if (Get-Command Write-Diag -ErrorAction SilentlyContinue) { Write-Diag "[LIVE TEST] $failCount STAGE(S) FAILED" "WARN" }
}
