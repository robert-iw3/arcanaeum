<#
.SYNOPSIS
    Export NEBULA test results

.DESCRIPTION
    Utility script to export and analyze NEBULA test results

.PARAMETER OutputPath
    Path to save the results file

.PARAMETER Format
    Output format: CSV, JSON, or HTML
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\NebulaResults",

    [Parameter(Mandatory=$false)]
    [ValidateSet("CSV", "JSON", "HTML")]
    [string]$Format = "CSV"
)

Write-Host ""
Write-Host "╔════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   NEBULA Results Export Utility       ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# This is a standalone utility - NEBULA would need to export results
# to a file that this script can read

$resultsFile = Join-Path $PSScriptRoot "nebula_results.json"

if (-not (Test-Path $resultsFile)) {
    Write-Host "[!] No results file found at: $resultsFile" -ForegroundColor Yellow
    Write-Host "[*] This utility exports test results logged by NEBULA." -ForegroundColor Gray
    Write-Host "[*] Run NEBULA and execute some tests first." -ForegroundColor Gray
    Write-Host ""

    # Create sample data for demonstration
    $sampleResults = @(
        [PSCustomObject]@{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            TestName = "Sample Test"
            Technique = "WMI Execution"
            Status = "SUCCESS"
            Details = "This is sample data"
        }
    )

    Write-Host "[*] Creating sample results file for demonstration..." -ForegroundColor Cyan
    $sampleResults | ConvertTo-Json | Out-File $resultsFile
}

Write-Host "[+] Loading results from: $resultsFile" -ForegroundColor Green
$results = Get-Content $resultsFile | ConvertFrom-Json

Write-Host "[*] Found $($results.Count) test results" -ForegroundColor Cyan
Write-Host ""

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputFile = "$OutputPath`_$timestamp.$($Format.ToLower())"

switch ($Format) {
    "CSV" {
        Write-Host "[*] Exporting to CSV format..." -ForegroundColor Yellow
        $results | Export-Csv -Path $outputFile -NoTypeInformation
        Write-Host "[+] Exported to: $outputFile" -ForegroundColor Green
    }

    "JSON" {
        Write-Host "[*] Exporting to JSON format..." -ForegroundColor Yellow
        $results | ConvertTo-Json -Depth 10 | Out-File $outputFile
        Write-Host "[+] Exported to: $outputFile" -ForegroundColor Green
    }

    "HTML" {
        Write-Host "[*] Generating HTML report..." -ForegroundColor Yellow

        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>NEBULA Test Results - $timestamp</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }
        h1 {
            color: #667eea;
            text-align: center;
            margin-bottom: 10px;
        }
        .subtitle {
            text-align: center;
            color: #666;
            margin-bottom: 30px;
        }
        .stats {
            display: flex;
            justify-content: space-around;
            margin-bottom: 30px;
        }
        .stat-box {
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            min-width: 150px;
        }
        .stat-box.success { background: #d4edda; color: #155724; }
        .stat-box.failed { background: #f8d7da; color: #721c24; }
        .stat-box.error { background: #fff3cd; color: #856404; }
        .stat-box h3 { margin: 0; font-size: 2em; }
        .stat-box p { margin: 5px 0 0 0; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th {
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
        }
        td {
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }
        tr:hover {
            background: #f5f5f5;
        }
        .status {
            padding: 5px 10px;
            border-radius: 5px;
            font-weight: bold;
            display: inline-block;
        }
        .status.SUCCESS { background: #28a745; color: white; }
        .status.FAILED { background: #dc3545; color: white; }
        .status.ERROR { background: #ffc107; color: black; }
        .status.DRY-RUN { background: #6c757d; color: white; }
        .status.INFO { background: #17a2b8; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌌 NEBULA Test Results</h1>
        <p class="subtitle">Generated: $timestamp</p>

        <div class="stats">
            <div class="stat-box success">
                <h3>$($results | Where-Object {$_.Status -eq "SUCCESS"} | Measure-Object | Select-Object -ExpandProperty Count)</h3>
                <p>Successful</p>
            </div>
            <div class="stat-box failed">
                <h3>$($results | Where-Object {$_.Status -eq "FAILED"} | Measure-Object | Select-Object -ExpandProperty Count)</h3>
                <p>Failed</p>
            </div>
            <div class="stat-box error">
                <h3>$($results | Where-Object {$_.Status -eq "ERROR"} | Measure-Object | Select-Object -ExpandProperty Count)</h3>
                <p>Errors</p>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Test Name</th>
                    <th>Technique</th>
                    <th>Status</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
"@

        foreach ($result in $results) {
            $html += @"
                <tr>
                    <td>$($result.Timestamp)</td>
                    <td>$($result.TestName)</td>
                    <td>$($result.Technique)</td>
                    <td><span class="status $($result.Status)">$($result.Status)</span></td>
                    <td>$($result.Details)</td>
                </tr>
"@
        }

        $html += @"
            </tbody>
        </table>
    </div>
</body>
</html>
"@

        $html | Out-File $outputFile -Encoding UTF8
        Write-Host "[+] HTML report generated: $outputFile" -ForegroundColor Green

        # Try to open in browser
        Write-Host "[*] Opening report in browser..." -ForegroundColor Cyan
        try {
            Start-Process $outputFile
        } catch {
            Write-Host "[!] Could not auto-open browser. Please open manually." -ForegroundColor Yellow
        }
    }
}

Write-Host ""
Write-Host "════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Export complete!" -ForegroundColor Green
Write-Host "════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Generate statistics
Write-Host "Test Statistics:" -ForegroundColor White
Write-Host "  Total Tests: $($results.Count)" -ForegroundColor Gray
Write-Host "  Successful: $($results | Where-Object {$_.Status -eq 'SUCCESS'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Green
Write-Host "  Failed: $($results | Where-Object {$_.Status -eq 'FAILED'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Red
Write-Host "  Errors: $($results | Where-Object {$_.Status -eq 'ERROR'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Yellow
Write-Host ""

# Show technique breakdown
Write-Host "Techniques Tested:" -ForegroundColor White
$results | Group-Object -Property Technique | Sort-Object Count -Descending | ForEach-Object {
    Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor Cyan
}
Write-Host ""

