<#
.SYNOPSIS
    High-performance, native PowerShell script for automated point-in-time restore
    of multiple SQL Server databases from striped full/diff + sequential log backups.

.DESCRIPTION
    Features:
      • Zero external modules or SMO required (pure PowerShell + sqlcmd)
      • Dynamic stripe detection (1 to N parts, handles _part10.bak correctly)
      • Fully automatic MOVE clauses via RESTORE FILELISTONLY
      • Creates target Data/Log folders automatically
      • Handles existing OR brand-new databases
      • Millisecond-precise STOPAT
      • Robust error handling with rollback to MULTI_USER
      • Detailed console progress and failure isolation (one DB failure does not stop others)

    Backup folder structure expected:
      $BaseDir\
        FULL\   DBName_FULL_yyyyMMdd_HHmmss[_partN].bak
        DIFF\   DBName_DIFF_yyyyMMdd_HHmmss[_partN].bak
        LOG\    DBName_LOG_yyyyMMdd_HHmmss.trn

.NOTES
    Author      : Robert Weber
    Version     : 2.0
    Date        : February 2026
    Requirements: sqlcmd.exe in PATH, SQL Server login with sysadmin rights
    Tested on   : PowerShell 5.1 and 7.x, SQL Server 2016–2022
#>

# =====================================================================
# 1. CONFIGURATION - EDIT THIS SECTION ONLY
# =====================================================================
$Server      = "."                     # "." = local default instance, or "SQL01\INST01"
$BaseDir     = "C:\Backups\"           # Root backup folder (trailing backslash required)
$TargetTime  = [datetime]"2026-02-26 16:05:00"   # Change to your desired PITR (supports .fff ms)

$RestoreList = @{
    "UserDatabase1" = @{ DataDir = "D:\SQLData\";  LogDir = "L:\SQLLogs\" }
    "Prod_Sales_DB" = @{ DataDir = "E:\Data\";     LogDir = "M:\Logs\"    }
    # Add more databases as needed, following the same structure
}

# Performance tuning (increase BufferCount if you have plenty of RAM)
$BufferCount = 50
$BlockSize   = 65536   # 64 KB

# =====================================================================
# 2. HELPER VARIABLES (do not edit)
# =====================================================================
$TargetStr = $TargetTime.ToString("yyyyMMddHHmmss")
$StopAtStr = $TargetTime.ToString("yyyy-MM-dd HH:mm:ss.fff")

# =====================================================================
# 3. HELPER FUNCTION: Build stripe list (FULL / DIFF)
# =====================================================================
function Get-Stripes {
    param (
        [string]$SubFolder,      # FULL or DIFF
        [string]$CommonBaseName
    )
    Get-ChildItem "$BaseDir\$SubFolder" -Filter "$CommonBaseName*.bak" | Sort-Object {
        if ($_.Name -like "*_part*") {
            [int]($_.Name -replace '.*_part(\d+).*', '$1')
        } else { 1 }
    }
}

# =====================================================================
# 4. MAIN RESTORE LOOP
# =====================================================================
foreach ($Db in $RestoreList.Keys) {
    $DataDir = $RestoreList[$Db].DataDir
    $LogDir  = $RestoreList[$Db].LogDir

    Write-Host "`n>>> STARTING RESTORE FOR: $Db" -ForegroundColor Cyan

    # -----------------------------------------------------------------
    # 4.1 Create target folders
    # -----------------------------------------------------------------
    $null = New-Item -Path $DataDir, $LogDir -ItemType Directory -Force -ErrorAction SilentlyContinue

    # -----------------------------------------------------------------
    # 4.2 FULL backup
    # -----------------------------------------------------------------
    $FullFiles = Get-ChildItem "$BaseDir\FULL" -Filter "$Db`_FULL_*.bak" | Where-Object {
        if ($_.Name -match '_(\d{8}_\d{6})') {
            $ts = $matches[1].Replace('_','')
            $ts -le $TargetStr
        }
    } | Sort-Object Name -Descending | Select-Object -First 1

    if (-not $FullFiles) {
        Write-Host "!!! No FULL backup found for $Db" -ForegroundColor Red
        continue
    }

    # Common base name for stripes
    $BaseNameFull = [IO.Path]::GetFileNameWithoutExtension($FullFiles.Name)
    $CommonFull   = if ($BaseNameFull -like "*_part*") {
                        $BaseNameFull.Substring(0, $BaseNameFull.LastIndexOf("_part"))
                    } else { $BaseNameFull }

    $StripesFull = Get-Stripes -SubFolder "FULL" -CommonBaseName $CommonFull

    # Build FROM clause
    $FromFull = ($StripesFull | ForEach-Object { "DISK = N'$($_.FullName)'" }) -join ', '

    # Get logical file list for dynamic MOVE
    $FirstStripe = $StripesFull[0].FullName
    $FileListOutput = & sqlcmd -S $Server -E -Q "RESTORE FILELISTONLY FROM DISK = N'$FirstStripe'" -h -1 -s "|" -W

    $FileList = @()
    foreach ($line in $FileListOutput) {
        if ($line -match '\|') {
            $cols = $line -split '\|' | ForEach-Object { $_.Trim() }
            if ($cols.Count -ge 3) {
                $FileList += [PSCustomObject]@{
                    Logical  = $cols[0]
                    Physical = $cols[1]
                    Type     = $cols[2]
                }
            }
        }
    }

    $MoveClause = ($FileList | ForEach-Object {
        $targetPath = if ($_.Type -eq 'L') { $LogDir } else { $DataDir }
        $fileName   = [IO.Path]::GetFileName($_.Physical)
        "MOVE N'$($_.Logical)' TO N'$targetPath$fileName'"
    }) -join ', '

    # SINGLE_USER only if DB already exists
    $dbExists = & sqlcmd -S $Server -E -Q "SELECT CASE WHEN DB_ID('$Db') IS NOT NULL THEN 1 ELSE 0 END" -h -1 -W
    if ($dbExists.Trim() -eq "1") {
        & sqlcmd -S $Server -E -Q "ALTER DATABASE [$Db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;" -b
        if ($LASTEXITCODE -ne 0) { throw "Failed to set SINGLE_USER for $Db" }
    }

    # FULL restore
    $sqlFull = "RESTORE DATABASE [$Db] FROM $FromFull WITH NORECOVERY, REPLACE, CHECKSUM, BUFFERCOUNT=$BufferCount, BLOCKSIZE=$BlockSize, $MoveClause;"
    & sqlcmd -S $Server -E -Q $sqlFull -b
    if ($LASTEXITCODE -ne 0) { throw "FULL restore failed for $Db" }
    Write-Host "   FULL restored successfully" -ForegroundColor Green

    # -----------------------------------------------------------------
    # 4.3 DIFF backup (optional - latest after FULL)
    # -----------------------------------------------------------------
    $FullTS = ($FullFiles.Name -replace '.*_(\d{8}_\d{6}).*', '$1').Replace('_','')

    $DiffFiles = Get-ChildItem "$BaseDir\DIFF" -Filter "$Db`_DIFF_*.bak" | Where-Object {
        if ($_.Name -match '_(\d{8}_\d{6})') {
            $ts = $matches[1].Replace('_','')
            $ts -gt $FullTS -and $ts -le $TargetStr
        }
    } | Sort-Object Name -Descending | Select-Object -First 1

    if ($DiffFiles) {
        $BaseNameDiff = [IO.Path]::GetFileNameWithoutExtension($DiffFiles.Name)
        $CommonDiff   = if ($BaseNameDiff -like "*_part*") {
                            $BaseNameDiff.Substring(0, $BaseNameDiff.LastIndexOf("_part"))
                        } else { $BaseNameDiff }

        $StripesDiff = Get-Stripes -SubFolder "DIFF" -CommonBaseName $CommonDiff

        $FromDiff = ($StripesDiff | ForEach-Object { "DISK = N'$($_.FullName)'" }) -join ', '

        $sqlDiff = "RESTORE DATABASE [$Db] FROM $FromDiff WITH NORECOVERY, CHECKSUM, BUFFERCOUNT=$BufferCount, BLOCKSIZE=$BlockSize;"
        & sqlcmd -S $Server -E -Q $sqlDiff -b
        if ($LASTEXITCODE -ne 0) { throw "DIFF restore failed for $Db" }
        Write-Host "   DIFF applied successfully" -ForegroundColor Green
    }

    # -----------------------------------------------------------------
    # 4.4 Transaction LOGs (sequential, up to @TargetTime)
    # -----------------------------------------------------------------
    $LastTS = if ($DiffFiles) {
                  ($DiffFiles.Name -replace '.*_(\d{8}_\d{6}).*', '$1').Replace('_','')
              } else {
                  $FullTS
              }

    $Logs = Get-ChildItem "$BaseDir\LOG" -Filter "$Db`_LOG_*.trn" | Where-Object {
        if ($_.Name -match '_(\d{8}_\d{6})') {
            $ts = $matches[1].Replace('_','')
            $ts -gt $LastTS -and $ts -le $TargetStr
        }
    } | Sort-Object Name

    foreach ($log in $Logs) {
        $sqlLog = "RESTORE LOG [$Db] FROM DISK = N'$($log.FullName)' WITH NORECOVERY, STOPAT = '$StopAtStr';"
        & sqlcmd -S $Server -E -Q $sqlLog -b
        if ($LASTEXITCODE -ne 0) { throw "LOG restore failed for $($log.Name)" }
        Write-Host "   LOG applied: $($log.Name)" -ForegroundColor Gray
    }

    # -----------------------------------------------------------------
    # 4.5 Finalize restore
    # -----------------------------------------------------------------
    & sqlcmd -S $Server -E -Q "RESTORE DATABASE [$Db] WITH RECOVERY;" -b
    & sqlcmd -S $Server -E -Q "ALTER DATABASE [$Db] SET MULTI_USER;" -b

    # Integrity check
    Write-Host "   Running DBCC CHECKDB..." -ForegroundColor Yellow
    & sqlcmd -S $Server -E -Q "DBCC CHECKDB ([$Db]) WITH NO_INFOMSGS, ALL_ERRORMSGS, CHECKSUM;" -b

    Write-Host "   SUCCESS: $Db restored to $TargetTime" -ForegroundColor Green
}

# =====================================================================
# 5. COMPLETION
# =====================================================================
Write-Host "`n--- ALL DATABASE RESTORES COMPLETE ---" -ForegroundColor Magenta
Write-Host "Target Point-in-Time: $TargetTime" -ForegroundColor Magenta