@echo off
REM NEBULA Launcher
REM Quick launcher for NEBULA TUI

echo.
echo ========================================
echo   NEBULA Launcher
echo ========================================
echo.

REM Check if running as admin
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [+] Running with Administrator privileges
) else (
    echo [!] Not running as Administrator
    echo [!] Some techniques may require elevation
)

echo.
echo [*] Starting NEBULA...
echo.

REM Launch PowerShell with Nebula
powershell.exe -ExecutionPolicy Bypass -File "%~dp0Nebula.ps1"

pause

