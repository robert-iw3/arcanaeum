variable "virtualization_platform" {
  description = "Virtualization platform to use"
  type        = string
  default     = "hyperv"
  validation {
    condition     = contains(["hyperv", "vmware"], var.virtualization_platform)
    error_message = "Virtualization platform must be 'hyperv' or 'vmware'."
  }
}

variable "host_os" {
  description = "Operating system for the VM"
  type        = string
  default     = "server2022"
  validation {
    condition     = contains(["server2019", "server2022", "server2025", "win10", "win11"], var.host_os)
    error_message = "Host OS must be 'server2019', 'server2022', 'server2025', 'win10', or 'win11'."
  }
}

variable "container_runtime" {
  description = "Container runtime to use"
  type        = string
  default     = "docker"
  validation {
    condition     = contains(["docker", "podman", "kubernetes"], var.container_runtime)
    error_message = "Container runtime must be 'docker', 'podman', or 'kubernetes'."
  }
}

variable "evidence_tool" {
  description = "Evidence collection tool"
  type        = string
  default     = "magnet"
  validation {
    condition     = contains(["magnet", "cuckoo"], var.evidence_tool)
    error_message = "Evidence tool must be 'magnet' or 'cuckoo'."
  }
}

variable "vm_name" {
  description = "Name of the VM"
  type        = string
  default     = "malware-sandbox"
}

variable "cpu_count" {
  description = "Number of CPUs for the VM"
  type        = number
  default     = 2
}

variable "memory_mb" {
  description = "Memory in MB for the VM"
  type        = number
  default     = 2048
}

variable "disk_size_gb" {
  description = "Disk size in GB for the VM"
  type        = number
  default     = 60
}

variable "iso_urls" {
  description = "URLs for OS ISOs"
  type        = map(string)
  default     = {
    server2019 = "https://go.microsoft.com/fwlink/p/?LinkID=2195334&clcid=0x409&culture=en-us&country=US"
    server2022 = "https://go.microsoft.com/fwlink/p/?LinkID=2195404&clcid=0x409&culture=en-us&country=US"
    server2025 = "https://your-source/windows_server_2025_preview.iso"
    win10     = "https://go.microsoft.com/fwlink/p/?LinkID=2195166&clcid=0x409&culture=en-us&country=US"
    win11     = "https://go.microsoft.com/fwlink/p/?LinkID=2196230&clcid=0x409&culture=en-us&country=US"
  }
}

variable "iso_checksums" {
  description = "Checksums for OS ISOs"
  type        = map(string)
  default     = {
    server2019 = "sha256:your_checksum_here"
    server2022 = "sha256:your_checksum_here"
    server2025 = "sha256:your_checksum_here"
    win10     = "sha256:your_checksum_here"
    win11     = "sha256:your_checksum_here"
  }
}

variable "vsphere_user" {
  description = "vSphere username"
  type        = string
  default     = ""
}

variable "vsphere_password" {
  description = "vSphere password"
  type        = string
  default     = ""
  sensitive   = true
}

variable "vsphere_server" {
  description = "vSphere server address"
  type        = string
  default     = ""
}

variable "hyperv_password" {
  description = "Hyper-V administrator password"
  type        = string
  default     = ""
  sensitive   = true
}

variable "ansible_winrm_user" {
  description = "WinRM username for Ansible"
  type        = string
  default     = "Administrator"
}

variable "ansible_winrm_password" {
  description = "WinRM password for Ansible"
  type        = string
  default     = ""
  sensitive   = true
}

variable "cuckoo_vm_name" {
  description = "Name of the Cuckoo VM"
  type        = string
  default     = "cuckoo-server"
}

variable "cuckoo_vm_ip" {
  description = "IP address of the Cuckoo VM"
  type        = string
  default     = "192.168.56.10"
}

variable "cuckoo_api_port" {
  description = "Cuckoo API port"
  type        = string
  default     = "8090"
}