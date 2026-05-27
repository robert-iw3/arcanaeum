<#
.SYNOPSIS
    Scans Trellix ePO server logs for known issues based on common KB articles and exports findings to a CSV file with associated KB links.

.DESCRIPTION
    This script searches through ePO server log files for specific error patterns derived from Trellix KB articles.
    It collects matches with timestamps, messages, and KB links for fixes, then dumps the results to a CSV file.
    Deduplicates entries by log line (based on LogFile and LineNumber), combining multiple matching patterns and KB links.

    Optimized with a single regex pattern for all searches to improve performance on large log files.
    Extended with patterns related to ePO performance tuning and issues, including SQL Server tuning.
    Timestamp extraction is more robust, handling optional milliseconds and common variations.
    Added progress bar for scanning log files.

    Default ePO install directory: C:\Program Files (x86)\McAfee\ePolicy Orchestrator
    Default log subdirectories: DB\Logs, Server\logs
    Logs scanned: Recursively searches for *.log files in the specified subdirectories.

    Known patterns and KB links (based on Trellix documentation, expanded with additional patterns from deep search, including performance tuning and SQL Server tuning):
    - "Failed to load server keys" -> https://kcm.trellix.com/corporate/index?id=KB92812
    - "Sequence number invalid" -> https://kcm.trellix.com/corporate/index?id=KB60776
    - "UPDATE failed, 'NUMERIC_ROUNDABORT'" -> https://thrive.trellix.com/s/article/KB91112
    - "Failed to load props.xml" -> https://kcm.trellix.com/corporate/index?id=KB90603
    - "Failed to send HTTP request. Error=12029" -> https://thrive.trellix.com/s/article/KB87143
    - "ePO Server reached the maximum download limit" -> https://thrive.trellix.com/s/article/KB52973
    - "missing dependency" -> https://thrive.trellix.com/s/article/KB81799
    - "Could not allocate space for object" -> https://kcm.trellix.com/corporate/index?id=KB53461
    - "java.lang.OutOfMemoryError" -> https://thrive.trellix.com/s/article/KB71516
    - "Could not resolve an action for handleHttpError.do" -> https://kcm.trellix.com/corporate/index?id=KB84390
    - "com.mcafee.orion.core.db.base" -> https://kcm.trellix.com/corporate/index?id=KB69850
    - "Not authorized or invalid query" -> https://kcm.trellix.com/corporate/index?id=KB95021
    - "Initialization of plugin RepositoryMgmt failed" -> https://kcm.trellix.com/corporate/index?id=KB79341
    - "Initialization of plugin" -> https://kcm.trellix.com/corporate/index?id=KB92223
    - "Master Repository key corrupt" -> https://kcm.trellix.com/corporate/index?id=KB79341
    - "license for ePolicy Orchestrator is invalid" -> https://kcm.trellix.com/corporate/index?id=KB84438
    - "Failed to load the list of installed products" -> https://kcm.trellix.com/corporate/index?id=KB85017
    - "This site can't be reached" -> https://kcm.trellix.com/corporate/index?id=KB96091
    - "Could not allocate space for object 'OrionAuditLog'" -> https://kcm.trellix.com/corporate/index?id=KB53461
    - "GTI communication with Kerberos authentication fails" -> https://thrive.trellix.com/s/article/000013412
    - "performance spike in Users > Server tasks > Audit log when running a script" -> https://thrive.trellix.com/s/article/000013518
    - "epo.command" -> https://thrive.trellix.com/s/article/000015039
    - "ePO master depository update, checking in" -> https://support.motorolasolutions.com/s/article/KB0067410
    - "failed to send notification" -> https://kcm.trellix.com/corporate/index?id=KB60405
    - "The license for ePolicy Orchestrator is invalid" -> https://kcm.trellix.com/corporate/index?id=KB66166
    - "faulting module dal.dll" -> https://kcm.trellix.com/corporate/index?id=KB90944
    - "An unexpected error occurred" -> https://thrive.trellix.com/s/article/KB91420
    - "Unexpected error" -> https://kcm.trellix.com/corporate/index?id=KB91590
    - "An unexpected error" -> https://thrive.trellix.com/s/article/KB91594
    - "Failed to find the group membership in the OpenLDAP directory tree" -> https://kcm.trellix.com/corporate/index?id=KB91987
    - "Error executing script file 7_ePO_Indexes.sql" -> https://thrive.trellix.com/s/article/KB92171
    - "TLOS" -> https://thrive.trellix.com/s/article/KB92428
    - "The registered LDAP server has either been removed or otherwise does not exist" -> https://kcm.trellix.com/corporate/index?id=KB93315
    - "tries to connect to the wrong server" -> https://thrive.trellix.com/s/article/KB95533
    - "You have provided invalid credentials" -> https://thrive.trellix.com/s/article/KB51640
    - "Error 500" -> https://kcm.trellix.com/corporate/index?id=KB81737
    - "Error -2147024891" -> https://kcm.trellix.com/corporate/index?id=KB51652
    - "SQL errors recorded" -> https://thrive.trellix.com/s/article/KB89579
    - "Java thread hangs" -> https://kcm.trellix.com/corporate/index?id=KB78219
    - "Maximum Degree of Parallelism" -> https://kcm.trellix.com/corporate/index?id=KB79310
    - "fails to connect to the authentication server" -> https://kcm.trellix.com/corporate/index?id=KB95299
    - "McAfee Application server service terminated unexpectedly" -> https://community.spiceworks.com/t/event-di-7034-error-mcafee-application-server-service-terminated-unexpectedly/643203
    - "agent-server communication failures" -> https://kcm.trellix.com/corporate/index?id=KB90603
    - "performance issues" -> https://thrive.trellix.com/s/article/KB90961
    - "timeout" -> https://kcm.trellix.com/corporate/index?id=KB95299
    - "SQLSERVER.exe process has high CPU utilization" -> https://thrive.trellix.com/s/article/KB94945
    - "ePO console performance is slow" -> https://thrive.trellix.com/s/article/KB94945
    - "index fragmentation" -> https://thrive.trellix.com/s/article/KB67184
    - "large extended events tables" -> https://thrive.trellix.com/s/article/KB93761
    - "purging events does not reduce Rowcount" -> https://thrive.trellix.com/s/article/KB93761
    - "performance issues with ePO and SQL" -> https://kcm.trellix.com/corporate/index?id=KB79310

    You can extend the $patterns hashtable with more entries from additional KB articles.

.PARAMETER InstallDir
    The ePO installation directory. Default: "C:\Program Files (x86)\McAfee\ePolicy Orchestrator"

.PARAMETER LogSubdirs
    Array of subdirectories under InstallDir to scan for logs. Default: @("DB\Logs", "Server\logs")

.PARAMETER OutputCsv
    The path to the output CSV file. Default: "ePO_Log_Issues.csv"

.EXAMPLE
    .\Scan_ePO_Logs.ps1 -InstallDir "C:\Program Files (x86)\Trellix\ePolicy Orchestrator" -LogSubdirs @("DB\Logs", "Server\logs", "Other\Logs") -OutputCsv "issues.csv"

.NOTES
    Author: Robert Weber
#>

param (
    [string]$InstallDir = "C:\Program Files (x86)\McAfee\ePolicy Orchestrator",
    [string[]]$LogSubdirs = @("DB\Logs", "Server\logs"),
    [string]$OutputCsv = "ePO_Log_Issues.csv"
)

# Hashtable of error patterns to KB links
$patterns = @{
    "Failed to load server keys" = "https://kcm.trellix.com/corporate/index?id=KB92812"
    "Sequence number invalid" = "https://kcm.trellix.com/corporate/index?id=KB60776"
    "UPDATE failed, 'NUMERIC_ROUNDABORT'" = "https://thrive.trellix.com/s/article/KB91112"
    "Failed to load props.xml" = "https://kcm.trellix.com/corporate/index?id=KB90603"
    "Failed to send HTTP request. Error=12029" = "https://thrive.trellix.com/s/article/KB87143"
    "ePO Server reached the maximum download limit" = "https://thrive.trellix.com/s/article/KB52973"
    "missing dependency" = "https://thrive.trellix.com/s/article/KB81799"
    "Could not allocate space for object" = "https://kcm.trellix.com/corporate/index?id=KB53461"
    "java.lang.OutOfMemoryError" = "https://thrive.trellix.com/s/article/KB71516"
    "Could not resolve an action for handleHttpError.do" = "https://kcm.trellix.com/corporate/index?id=KB84390"
    "com.mcafee.orion.core.db.base" = "https://kcm.trellix.com/corporate/index?id=KB69850"
    "Not authorized or invalid query" = "https://kcm.trellix.com/corporate/index?id=KB95021"
    "Initialization of plugin RepositoryMgmt failed" = "https://kcm.trellix.com/corporate/index?id=KB79341"
    "Initialization of plugin" = "https://kcm.trellix.com/corporate/index?id=KB92223"
    "Master Repository key corrupt" = "https://kcm.trellix.com/corporate/index?id=KB79341"
    "license for ePolicy Orchestrator is invalid" = "https://kcm.trellix.com/corporate/index?id=KB84438"
    "Failed to load the list of installed products" = "https://kcm.trellix.com/corporate/index?id=KB85017"
    "This site can't be reached" = "https://kcm.trellix.com/corporate/index?id=KB96091"
    "Could not allocate space for object 'OrionAuditLog'" = "https://kcm.trellix.com/corporate/index?id=KB53461"
    "GTI communication with Kerberos authentication fails" = "https://thrive.trellix.com/s/article/000013412"
    "performance spike in Users > Server tasks > Audit log when running a script" = "https://thrive.trellix.com/s/article/000013518"
    "epo.command" = "https://thrive.trellix.com/s/article/000015039"
    "ePO master depository update, checking in" = "https://support.motorolasolutions.com/s/article/KB0067410"
    "failed to send notification" = "https://kcm.trellix.com/corporate/index?id=KB60405"
    "The license for ePolicy Orchestrator is invalid" = "https://kcm.trellix.com/corporate/index?id=KB66166"
    "faulting module dal.dll" = "https://kcm.trellix.com/corporate/index?id=KB90944"
    "An unexpected error occurred" = "https://thrive.trellix.com/s/article/KB91420"
    "Unexpected error" = "https://kcm.trellix.com/corporate/index?id=KB91590"
    "An unexpected error" = "https://thrive.trellix.com/s/article/KB91594"
    "Failed to find the group membership in the OpenLDAP directory tree" = "https://kcm.trellix.com/corporate/index?id=KB91987"
    "Error executing script file 7_ePO_Indexes.sql" = "https://thrive.trellix.com/s/article/KB92171"
    "TLOS" = "https://thrive.trellix.com/s/article/KB92428"
    "The registered LDAP server has either been removed or otherwise does not exist" = "https://kcm.trellix.com/corporate/index?id=KB93315"
    "tries to connect to the wrong server" = "https://thrive.trellix.com/s/article/KB95533"
    "You have provided invalid credentials" = "https://thrive.trellix.com/s/article/KB51640"
    "Error 500" = "https://kcm.trellix.com/corporate/index?id=KB81737"
    "Error -2147024891" = "https://kcm.trellix.com/corporate/index?id=KB51652"
    "SQL errors recorded" = "https://thrive.trellix.com/s/article/KB89579"
    "Java thread hangs" = "https://kcm.trellix.com/corporate/index?id=KB78219"
    "Maximum Degree of Parallelism" = "https://kcm.trellix.com/corporate/index?id=KB79310"
    "fails to connect to the authentication server" = "https://kcm.trellix.com/corporate/index?id=KB95299"
    "McAfee Application server service terminated unexpectedly" = "https://community.spiceworks.com/t/event-di-7034-error-mcafee-application-server-service-terminated-unexpectedly/643203"
    "agent-server communication failures" = "https://kcm.trellix.com/corporate/index?id=KB90603"
    "performance issues" = "https://thrive.trellix.com/s/article/KB90961"
    "timeout" = "https://kcm.trellix.com/corporate/index?id=KB95299"
    "SQLSERVER.exe process has high CPU utilization" = "https://thrive.trellix.com/s/article/KB94945"
    "ePO console performance is slow" = "https://thrive.trellix.com/s/article/KB94945"
    "index fragmentation" = "https://thrive.trellix.com/s/article/KB67184"
    "large extended events tables" = "https://thrive.trellix.com/s/article/KB93761"
    "purging events does not reduce Rowcount" = "https://thrive.trellix.com/s/article/KB93761"
    "performance issues with ePO and SQL" = "https://kcm.trellix.com/corporate/index?id=KB79310"
}

# Get log directories
$logDirs = $LogSubdirs | ForEach-Object { Join-Path $InstallDir $_ } | Where-Object { Test-Path $_ }

try {
    if ($logDirs.Count -eq 0) {
        throw "No log directories found in $InstallDir. Check the installation path and LogSubdirs."
    }

    # Get log files
    $logFiles = Get-ChildItem -Path $logDirs -Filter *.log -Recurse -File -ErrorAction Stop

    if ($logFiles.Count -eq 0) {
        Write-Warning "No log files found in the specified directories."
        exit
    }

    # Optimize regex: Escape patterns and join with |
    $escapedPatterns = $patterns.Keys | ForEach-Object { [regex]::Escape($_) }
    $combinedRegex = '(' + ($escapedPatterns -join '|') + ')'

    # Collect results using a hashtable for deduplication by LogFile:LineNumber
    $resultHash = @{}

    # Loop over each log file with progress bar
    $i = 0
    foreach ($file in $logFiles) {
        $i++
        Write-Progress -Activity "Scanning log files" -Status "Processing $($file.Name)" -PercentComplete ($i / $logFiles.Count * 100) -ErrorAction SilentlyContinue

        $matches = Select-String -Path $file.FullName -Pattern $combinedRegex -AllMatches -CaseSensitive:$false -ErrorAction Stop

        foreach ($match in $matches) {
            $key = "$($match.Path | Split-Path -Leaf):$($match.LineNumber)"
            $line = $match.Line

            # Robust timestamp extraction (handles optional milliseconds, brackets, timezones)
            $timestampRegex = '^\[?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d{1,6})?(\s?[A-Z]{3})?)\]?'
            $timestamp = if ($line -match $timestampRegex) { $matches[1] } else { "N/A" }

            if (-not $resultHash.ContainsKey($key)) {
                $resultHash[$key] = @{
                    LogFile    = $match.Path | Split-Path -Leaf
                    LineNumber = $match.LineNumber
                    Timestamp  = $timestamp
                    Message    = $line
                    Patterns   = @()
                    KBLinks    = @()
                }
            }

            # Find which specific patterns match this line (case-insensitive)
            foreach ($pat in $patterns.Keys) {
                if ($line -imatch [regex]::Escape($pat)) {
                    $resultHash[$key].Patterns += $pat
                    $resultHash[$key].KBLinks += $patterns[$pat]
                }
            }
        }
    }

    Write-Progress -Activity "Scanning log files" -Completed -ErrorAction SilentlyContinue

    # Convert to array of PSCustomObjects, joining arrays
    $results = @()
    foreach ($entry in $resultHash.Values) {
        $results += [PSCustomObject]@{
            LogFile    = $entry.LogFile
            LineNumber = $entry.LineNumber
            Timestamp  = $entry.Timestamp
            Message    = $entry.Message
            Patterns   = $entry.Patterns -join "; "
            KBLinks    = ($entry.KBLinks | Select-Object -Unique) -join "; "  # Dedupe KB links
        }
    }

    # Export to CSV
    if ($results.Count -gt 0) {
        $results | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Output "Findings exported to $OutputCsv"
    } else {
        Write-Output "No issues found matching the known patterns."
    }
}
catch {
    Write-Progress -Activity "Scanning log files" -Completed -ErrorAction SilentlyContinue
    Write-Error "An error occurred: $_"
}