$logPath = "C:\Logs\malware_sandbox.log"
$maxSize = 10MB
$backupCount = 5

if (Test-Path $logPath) {
    $logSize = (Get-Item $logPath).Length
    if ($logSize -gt $maxSize) {
        for ($i = $backupCount - 1; $i -gt 0; $i--) {
            $src = "$logPath.$i"
            $dst = "$logPath.$($i + 1)"
            if (Test-Path $src) { Move-Item -Path $src -Destination $dst -Force }
        }
        Move-Item -Path $logPath -Destination "$logPath.1" -Force
        New-Item -Path $logPath -ItemType File
    }
}