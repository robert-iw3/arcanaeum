# Dockerfile for Windows - Hypothetical for Testing Trellix Agent/ENS in Container
# Use ONLY for testing. Base on Windows Server Core.

FROM mcr.microsoft.com/windows/servercore:ltsc2022

# Install Trellix Agent (FramePkg.exe)
# Assume FramePkg.exe is copied into build context
COPY FramePkg.exe C:\Temp\FramePkg.exe

# Run installation silently
RUN powershell -Command "Start-Process 'C:\Temp\FramePkg.exe' -ArgumentList '/install=agent /silent' -Wait"

# Install ENS components (example; use actual MSIs or tools)
# COPY ENS_installer.msi C:\Temp\ENS_installer.msi
# RUN msiexec /i C:\Temp\ENS_installer.msi /qn

# Ensure services run
CMD ["powershell", "-Command", "C:\\Program Files\\McAfee\\Agent\\cmdagent.exe /c; Get-Content 'C:\\ProgramData\\McAfee\\Agent\\logs\\masvc.log' -Tail 100 -Wait"]

# To build: docker build -t trellix-windows .
# To run (with process isolation; for Hyper-V: --isolation=hyperv): docker run --isolation=hyperv -v C:\ProgramData\McAfee:C:\ProgramData\McAfee -v C:\Program Files\McAfee:C:\Program Files\McAfee -d trellix-windows