<#
.SYNOPSIS
    provision_sandbox.ps1 - Native Windows provisioning script replacing Ansible.
.DESCRIPTION
    Installs container runtimes, sets up the environment, and deploys the Malware Sandbox.
#>

param (
    [string]$ContainerRuntime = "docker",
    [int]$KubernetesReplicas = 1,
    [string]$EvidenceTool = "magnet",
    [string]$CuckooVmIp = "192.168.56.10"
)

$ErrorActionPreference = "Stop"

Write-Host "Starting Malware Sandbox Provisioning..." -ForegroundColor Cyan

# 1. Install Chocolatey if missing
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Chocolatey..." -ForegroundColor Yellow
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}

# 2. Container Runtime Installation
switch ($ContainerRuntime) {
    "docker" {
        Write-Host "Installing Docker Desktop..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri "https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe" -OutFile "DockerInstaller.exe"
        Start-Process -Wait -FilePath ".\DockerInstaller.exe" -ArgumentList 'install --quiet'
        Remove-Item ".\DockerInstaller.exe" -Force

        Write-Host "Building and Running Docker Container in detached mode..." -ForegroundColor Yellow
        docker build -t malware-sandbox C:\vagrant

        $cuckooArg = if ($EvidenceTool -eq 'cuckoo') { "--cuckoo-url http://${CuckooVmIp}:8090" } else { "" }
        # Note: -d flag used instead of -it to prevent WinRM hang
        docker run -d --isolation=hyperv --network=none `
            -v C:\vagrant\Malware:c:\Malware `
            -v C:\vagrant\Collections:c:\Collections `
            -v C:\vagrant\Logs:c:\Logs `
            malware-sandbox python malware_sandbox.py --malws-path c:\Malware --collection-dir c:\Collections --parallel 4 --volatility-plugins windows.pslist,windows.netscan --simulate-network --evidence-tool $EvidenceTool $cuckooArg
    }

    "podman" {
        Write-Host "Installing Podman..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri "https://github.com/containers/podman/releases/latest/download/podman-installer-windows-amd64.exe" -OutFile "PodmanInstaller.exe"
        Start-Process -Wait -FilePath ".\PodmanInstaller.exe" -ArgumentList '/quiet'
        Remove-Item ".\PodmanInstaller.exe" -Force

        Write-Host "Building and Running Podman Container..." -ForegroundColor Yellow
        podman build -t malware-sandbox C:\vagrant

        $cuckooArg = if ($EvidenceTool -eq 'cuckoo') { "--cuckoo-url http://${CuckooVmIp}:8090" } else { "" }
        podman run -d --isolation=hyperv --network=none `
            -v C:\vagrant\Malware:c:\Malware `
            -v C:\vagrant\Collections:c:\Collections `
            -v C:\vagrant\Logs:c:\Logs `
            malware-sandbox python malware_sandbox.py --malws-path c:\Malware --collection-dir c:\Collections --parallel 4 --volatility-plugins windows.pslist,windows.netscan --simulate-network --evidence-tool $EvidenceTool $cuckooArg
    }

    "kubernetes" {
        Write-Host "Installing Kubernetes CLI..." -ForegroundColor Yellow
        choco install kubernetes-cli -y

        Write-Host "Initializing Kubeadm..." -ForegroundColor Yellow
        kubeadm init --pod-network-cidr=10.244.0.0/16

        Write-Host "Configuring Kubernetes Deployment..." -ForegroundColor Yellow
        $k8sFile = "C:\vagrant\kubernetes-deployment.yaml"
        $k8sContent = Get-Content -Path $k8sFile -Raw
        $k8sContent = $k8sContent -replace 'replicas: 1', "replicas: $KubernetesReplicas"
        $k8sContent = $k8sContent -replace 'value: "magnet"', "value: `"$EvidenceTool`""
        $k8sContent = $k8sContent -replace 'value: "http://192.168.56.10:8090"', "value: `"http://${CuckooVmIp}:8090`""
        $k8sContent | Set-Content -Path $k8sFile

        kubectl apply -f $k8sFile
    }

    default {
        Write-Error "Invalid container_runtime specified: $ContainerRuntime"
        exit 1
    }
}

Write-Host "Provisioning Complete." -ForegroundColor Green