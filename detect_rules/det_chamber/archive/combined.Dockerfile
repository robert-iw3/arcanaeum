FROM mcr.microsoft.com/windows/servercore:ltsc2022-amd64

RUN powershell -Command \
    Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe -OutFile python-installer.exe; \
    Start-Process -FilePath python-installer.exe -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1' -Wait; \
    Remove-Item python-installer.exe

RUN pip install psutil python-logging-handlers pywin32

RUN powershell -Command \
    Invoke-WebRequest -Uri https://2.na.dl.wireshark.org/win64/Wireshark-4.2.6-x64.exe -OutFile wireshark-installer.exe; \
    Start-Process -FilePath wireshark-installer.exe -ArgumentList '/S /D=C:\Wireshark' -Wait; \
    Remove-Item wireshark-installer.exe

RUN powershell -Command \
    Invoke-WebRequest -Uri https://download.sysinternals.com/files/SysinternalsSuite.zip -OutFile sysinternals.zip; \
    Expand-Archive -Path sysinternals.zip -DestinationPath C:\Sysinternals -Force; \
    Remove-Item sysinternals.zip

RUN powershell -Command \
    New-Item -ItemType Directory -Path E:\Tools\Windows -Force; \
    New-Item -ItemType Directory -Path E:\Malware -Force; \
    New-Item -ItemType Directory -Path E:\Collections -Force; \
    New-Item -ItemType Directory -Path C:\Logs -Force

WORKDIR /app
COPY malware_sandbox.py .
COPY malware_sandbox.ps1 .
COPY Tools/Windows/Procmon.exe E:/Tools/Windows/
COPY Tools/Windows/MagnetRESPONSE.exe E:/Tools/Windows/
COPY Tools/Windows/etl2pcapng.exe E:/Tools/Windows/
COPY Tools/Windows/malw.pmc E:/Tools/Windows/
COPY Malware/ E:/Malware/
COPY logrotate.ps1 C:/logrotate.ps1

RUN powershell -Command \
    New-Item -ItemType Directory -Path C:\Logs -Force; \
    "C:\logrotate.ps1" | Out-File -FilePath C:\Windows\System32\Tasks\logrotate -Encoding ASCII; \
    schtasks /create /tn "LogRotate" /tr "powershell -File C:\logrotate.ps1" /sc daily /st 00:00

USER ContainerAdministrator

# Entrypoint with analysis and logging
CMD ["powershell", "-Command", "python malware_sandbox.py; tshark -r E:\\Collections\\*.pcap -T fields -e ip.src -e ip.dst -e tcp.port > C:\\Logs\\pcap_summary.txt; C:\\Sysinternals\\procexp.exe /t > C:\\Logs\\procexp.txt"]