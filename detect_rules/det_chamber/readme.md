# Malware Sandbox

## Overview
Malware Sandbox automates malware analysis in a secure Windows environment using Docker, Podman, or Kubernetes on Hyper-V/VMware VMs. It analyzes all files in a malware directory (any extension) or specific files, using:
- **Network Capture**: INetSim for C2 traffic.
- **Process Monitoring**: Process Monitor.
- **Evidence Collection**: Magnet RESPONSE or Cuckoo Sandbox.
- **Memory Analysis**: Volatility.
- **Static Analysis**: CAPA, YARA, pefile.
- **Reports**: JSON in `E:\Collections`.

YARA rules are cloned from ReversingLabs and Elastic, filtered for Windows x64. Deployment uses Terraform, Vagrant, Packer, and Ansible, with Windows updates, Ansible installed on VMs, health checks, auto-scaling, and RBAC.

## System Requirements
- **Small-Scale (10–50 files)**: 4-core CPU, 8GB RAM, 100GB SSD.
- **Large-Scale (500 files)**:
  - Magnet: 8-core CPU, 16GB RAM, 500GB SSD (~2–3h, `--parallel 8`).
  - Cuckoo: 16-core CPU, 32GB RAM, 1TB SSD (~4–6h, `--parallel 4`).
- **VM**: 2–4 cores, 2–4GB RAM, 60GB+ disk, Hyper-V/VMware isolation.
- **OS**: Windows Server 2019/2022/2025 or Windows 10/11 (user-selectable).

## Prerequisites
- **Tools**: `download_tools.ps1` fetches `Procmon.exe`, `etl2pcapng.exe`, `vol.exe`, `capa.exe`, `yara64.exe`, `inetsim.exe`. Place licensed `MagnetRESPONSE.exe`, `malw.pmc` in `E:\Tools\Windows`.
- **Cuckoo**: Optional server at `http://<cuckoo_vm_ip>:8090` (Terraform or manual).
- **YARA Rules**: Cloned by `Dockerfile` from:
  - `https://github.com/reversinglabs/reversinglabs-yara-rules`
  - `https://github.com/elastic/protections-artifacts`
- **Malware**: Place in `Malware/`.
- **Python**: 3.12.7 with `psutil`, `python-logging-handlers`, `pywin32`, `yara-python`, `pefile`, `requests` (installed during VM provisioning).
- **Software**: Terraform, Vagrant, Packer (on host); Ansible, Python, Chocolatey (on VM).
- **Vagrant Boxes**:
  - `server2019`: `StefanScherer/windows_2019`
  - `server2022`: `peru/windows-server-2022-standard-x64-eval` (default)
  - `server2025`: Custom box (build with Packer)
  - `win10`: `gusztavvargadr/windows-10`
  - `win11`: `gusztavvargadr/windows-11`
- **Directories**:
  ```
  project/
  ├── malware_sandbox.py
  ├── malware_sandbox.ps1
  ├── compile_yara_rules.py
  ├── filter_yara_rules.ps1
  ├── download_tools.ps1
  ├── Dockerfile
  ├── docker-compose.yml
  ├── ansible-playbook.yml
  ├── kubernetes-deployment.yaml
  ├── terraform/
  │   ├── variables.tf
  │   ├── terraform_hyperv.tf
  │   ├── terraform_vmware.tf
  ├── provisioning/
  │   ├── vagrant_hyperv.Vagrantfile
  │   ├── vagrant_vmware.Vagrantfile
  │   ├── packer_hyperv.json
  │   ├── packer_vmware.json
  ├── Tools/Windows/
  ├── Malware/
  ├── YARA/
  ├── Collections/
  ├── Logs/
  ```

## Setup
1. Place malware in `Malware/`.
2. Place `MagnetRESPONSE.exe`, `malw.pmc` in `E:\Tools\Windows` (if using Magnet).
3. Update `terraform/variables.tf` or `terraform.tfvars` with valid `iso_urls`, `iso_checksums` for Terraform/Packer.
4. For `server2025`, build a custom Vagrant box with Packer:
   ```bash
   git clone https://github.com/rgl/windows-vagrant
   cd windows-vagrant
   packer build -var 'iso_url=https://your-source/windows_server_2025_preview.iso' -var 'iso_checksum=sha256:your_checksum_here' windows-2025-amd64-hyperv.json
   vagrant box add windows-2025-amd64 windows-2025-amd64-hyperv.box
   ```

### Windows Server 2025 Custom Box
- **Source ISO**: Obtain the Windows Server 2025 preview ISO from Microsoft’s Evaluation Center (https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2025).
- **Checksum**: Calculate the SHA256 checksum using `powershell -Command "Get-FileHash -Path <iso_file> -Algorithm SHA256"`.
- **Build Commands**:
   ```bash
   export HOST_OS="server2025"
   export ISO_URLS="https://your-source/windows_server_2025_preview.iso"
   export ISO_CHECKSUM="sha256:your_checksum_here"
   cd provisioning
   packer build packer_hyperv.json
   vagrant box add windows-2025-amd64 windows-2025-amd64-hyperv.box
   ```
- **Usage**: Set `HOST_OS=server2025` before running `vagrant up`.

## Configuration
- **Scripts** (`malware_sandbox.py`/`malware_sandbox.ps1`):
  - `--malws-path` / `-MalwsPath`: Malware directory (default: `E:\Malware`).
  - `--malware` / `-Malware`: Specific files (default: all files).
  - `--parallel`: Processes (default: 4; 8 for Magnet, 4 for Cuckoo).
  - `--simulate-network` / `-SimulateNetwork`: Enable INetSim.
  - `--evidence-tool` / `-EvidenceTool`: `magnet` or `cuckoo`.
  - `--cuckoo-url` / `-CuckooUrl`: Cuckoo API (default: `http://192.168.56.10:8090`).
- **Terraform** (`variables.tf`):
  - `virtualization_platform`: `hyperv` or `vmware`.
  - `host_os`: `server2019`, `server2022` (default), `server2025`, `win10`, `win11`.
  - `container_runtime`: `docker`, `podman`, `kubernetes`.
  - `evidence_tool`: `magnet` or `cuckoo`.
- **Vagrant**:
  - Set `HOST_OS` to select base OS (`server2019`, `server2022` (default), `server2025`, `win10`, `win11`).

## Deployment
VMs are provisioned with Windows updates, Chocolatey, Python, Ansible, and prerequisites, ready to run `ansible-playbook.yml`. Optimized for bare-metal servers (Hyper-V or VMware Workstation).

### Terraform
```bash
cd terraform
terraform init
terraform apply -var="virtualization_platform=hyperv" -var="host_os=server2022" -var="container_runtime=kubernetes" -var="evidence_tool=cuckoo" -var="hyperv_password=your_password" -var="ansible_winrm_password=your_winrm_password"
```

### Vagrant
```bash
cd provisioning
export HOST_OS="server2022"  # or server2019, server2025, win10, win11
export CONTAINER_RUNTIME="kubernetes"
export EVIDENCE_TOOL="cuckoo"
vagrant up --provider hyperv  # or vmware_desktop
```

### Packer
```bash
cd provisioning
export HOST_OS="server2022"
export CONTAINER_RUNTIME="kubernetes"
export EVIDENCE_TOOL="cuckoo"
packer build packer_hyperv.json
```

### Local
```bash
python malware_sandbox.py --malws-path E:\Malware --collection-dir E:\Collections --parallel 4 --simulate-network --evidence-tool cuckoo --cuckoo-url http://192.168.56.10:8090
```

### Containers
- **Docker**:
  ```bash
  docker build -t malware-sandbox .
  docker run -it --isolation=hyperv --network=none -v %CD%\Malware:/Malware -v %CD%\Collections:/Collections -v %CD%\Logs:/Logs malware-sandbox python malware_sandbox.py --parallel 4 --simulate-network --evidence-tool cuckoo --cuckoo-url http://192.168.56.10:8090
  ```
- **Podman**:
  ```bash
  podman build -t malware-sandbox .
  podman run -it --isolation=hyperv --network=none -v ./Malware:/Malware:Z -v ./Collections:/Collections:Z -v ./Logs:/Logs:Z malware-sandbox python malware_sandbox.py --parallel 4 --simulate-network --evidence-tool cuckoo --cuckoo-url http://192.168.56.10:8090
  ```
- **Kubernetes**:
  ```bash
  kubectl apply -f kubernetes-deployment.yaml
  kubectl get pods -n malware-sandbox
  ```
- **Ansible** (on VM):
  ```bash
  ansible-playbook C:\vagrant\ansible-playbook.yml --extra-vars "container_runtime=kubernetes kubernetes_replicas=2 evidence_tool=cuckoo cuckoo_vm_ip=192.168.56.10"
  ```

## Monitoring
- **Logs**: `C:\Logs\malware_sandbox.log`, `errors.log`, `yara_compile.log`, `download_tools.log`.
- **Outputs**: `E:\Collections\<ComputerName>-<Timestamp>\summary.json`.
- **Kubernetes**: Check pod health (`kubectl describe pod -n malware-sandbox`), metrics (`kubectl port-forward svc/prometheus 9090:9090 -n malware-sandbox`).
- **Resources**: Monitor CPU/RAM/disk with Task Manager.

## Security
- **Isolation**: Hyper-V/VMware VMs, `--network=none`, Windows nodes for Kubernetes.
- **RBAC**: Restricts pod/deployment access to `malware-sandbox` namespace.
- **PSP**: Prevents privileged containers.
- **Cuckoo**: Runs in a separate VM.

## Notes
- **No File Filtering**: Analyzes all files in `Malware/` (e.g., `.exe`, `.dat`, no extension).
- **Health Checks**: VM (`Test-WSMan`), runtime (`kubectl cluster-info`), pod probes (`livenessProbe`, `readinessProbe`).
- **Auto-Scaling**: Kubernetes HPA scales 1–4 replicas (70% CPU, 80% memory).
- **VM Provisioning**: VMs are updated (Windows updates) and have Python, Ansible, and prerequisites installed.
- **CI/CD**: Validate with:
  ```bash
  ruby -c provisioning/vagrant_hyperv.Vagrantfile
  ruby -c provisioning/vagrant_vmware.Vagrantfile
  terraform fmt -check terraform
  yamllint .
  ansible-lint ansible-playbook.yml
  kubectl apply --dry-run=client -f kubernetes-deployment.yaml
  ```
- **Errors**: Check `C:\Logs\errors.log`.
- **Bare-Metal Setup**: Ensure Hyper-V is enabled (`Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All`) or VMware Workstation is installed.