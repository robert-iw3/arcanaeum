FROM mcr.microsoft.com/windows/servercore:ltsc2022-amd64

RUN powershell -Command \
    Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe -OutFile python-installer.exe; \
    Start-Process -FilePath python-installer.exe -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1' -Wait; \
    Remove-Item python-installer.exe

RUN pip install psutil

WORKDIR /app

COPY malware_sandbox.py .
COPY Tools/Windows/ E:/Tools/Windows/
COPY Malware/ E:/Malware/

RUN powershell -Command New-Item -ItemType Directory -Path E:\Collections -Force

USER ContainerAdministrator

CMD ["python", "malware_sandbox.py"]