#FROM mcr.microsoft.com/windows/servercore:ltsc2019
FROM mcr.microsoft.com/windows/servercore:ltsc2022
#FROM mcr.microsoft.com/windows/servercore:ltsc2025

RUN powershell -Command \
    Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe -OutFile python-installer.exe; \
    Start-Process -FilePath python-installer.exe -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1' -Wait; \
    Remove-Item python-installer.exe

RUN pip install psutil python-logging-handlers pywin32 yara-python pefile

# Install Wireshark (tshark)
RUN powershell -Command \
    Invoke-WebRequest -Uri https://2.na.dl.wireshark.org/win64/Wireshark-4.2.6-x64.exe -OutFile wireshark-installer.exe; \
    Start-Process -FilePath wireshark-installer.exe -ArgumentList '/S /D=C:\Wireshark' -Wait; \
    Remove-Item wireshark-installer.exe

# Install Sysinternals Suite
RUN powershell -Command \
    Invoke-WebRequest -Uri https://download.sysinternals.com/files/SysinternalsSuite.zip -OutFile sysinternals.zip; \
    Expand-Archive -Path sysinternals.zip -DestinationPath C:\Sysinternals -Force; \
    Remove-Item sysinternals.zip

# Install Volatility 3
RUN powershell -Command \
    Invoke-WebRequest -Uri https://github.com/volatilityfoundation/volatility3/releases/download/v2.7.0/volatility3-2.7.0-Windows-x64.zip -OutFile volatility.zip; \
    Expand-Archive -Path volatility.zip -DestinationPath C:\Volatility -Force; \
    Move-Item -Path C:\Volatility\volatility3-2.7.0-Windows-x64\vol.exe -Destination E:\Tools\Windows\vol.exe; \
    Remove-Item -Recurse C:\Volatility; \
    Remove-Item volatility.zip

# Install CAPA
RUN powershell -Command \
    Invoke-WebRequest -Uri https://github.com/mandiant/capa/releases/download/v7.1.0/capa-windows-x64.exe -OutFile E:\Tools\Windows\capa.exe

# Install YARA
RUN powershell -Command \
    Invoke-WebRequest -Uri https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-4.5.2-2309-win64.zip -OutFile yara.zip; \
    Expand-Archive -Path yara.zip -DestinationPath C:\YARA -Force; \
    Move-Item -Path C:\YARA\yara64.exe -Destination E:\Tools\Windows\yara64.exe; \
    Remove-Item -Recurse C:\YARA; \
    Remove-Item yara.zip

# Clone YARA rules
RUN powershell -Command \
    git clone https://github.com/reversinglabs/reversinglabs-yara-rules E:\YARA\Rules\reversinglabs; \
    git clone https://github.com/elastic/protections-artifacts E:\YARA\Rules\elastic

RUN powershell -Command \
    New-Item -ItemType Directory -Path E:\Tools\Windows -Force; \
    New-Item -ItemType Directory -Path E:\Malware -Force; \
    New-Item -ItemType Directory -Path E:\Collections -Force; \
    New-Item -ItemType Directory -Path C:\Logs -Force; \
    New-Item -ItemType Directory -Path E:\YARA -Force

WORKDIR /app
COPY malware_sandbox.py .
COPY compile_yara_rules.py .
COPY filter_yara_rules.ps1 .
COPY malware_sandbox.ps1 .
COPY Tools/Windows/Procmon.exe E:/Tools/Windows/
COPY Tools/Windows/MagnetRESPONSE.exe E:/Tools/Windows/
COPY Tools/Windows/etl2pcapng.exe E:/Tools/Windows/
COPY Tools/Windows/malw.pmc E:/Tools/Windows/
COPY Malware/ E:/Malware/

USER ContainerAdministrator

CMD ["powershell", "-Command", "python E:\\app\\compile_yara_rules.py; python malware_sandbox.py --simulate-network; if (Test-Path E:\\Collections\\*.pcap) { tshark -r E:\\Collections\\*.pcap -T fields -e ip.src -e ip.dst -e tcp.port > C:\\Logs\\pcap_summary.txt }; C:\\Sysinternals\\procexp.exe /t > C:\\Logs\\procexp.txt"]