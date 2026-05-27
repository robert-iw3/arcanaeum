terraform {
  required_providers {
    hyperv = {
      source  = "taliesins/hyperv"
      version = "~> 1.0.3"
    }
  }
}

provider "hyperv" {
  user            = "Administrator"
  password        = var.hyperv_password
  host            = "localhost"
}

resource "hyperv_vhd" "malware_sandbox_vhd" {
  path = "C:\\Users\\Public\\Documents\\Hyper-V\\Virtual Hard Disks\\${var.vm_name}.vhdx"
  size = var.disk_size_gb * 1073741824
}

resource "hyperv_vm_instance" "malware_sandbox_vm" {
  name                   = var.vm_name
  memory_startup_bytes  = var.memory_mb * 1024 * 1024
  processor_count       = var.cpu_count
  dynamic_memory        = true
  static_memory         = false
  generation            = 2
  state                 = "Running"

  network_adaptors {
    name        = "Network Adapter"
    switch_name = "Default Switch"
  }

  hard_disk_drives {
    controller_type     = "Scsi"
    controller_number   = 0
    controller_location = 0
    path               = hyperv_vhd.malware_sandbox_vhd.path
  }

  integration_services = {
    "Guest Service Interface" = true
    "Heartbeat"              = true
    "Key-Value Pair Exchange" = true
    "Shutdown"               = true
    "Time Synchronization"   = true
    "VSS"                    = true
  }

  provisioner "local-exec" {
    command = <<-EOT
      powershell -Command "Start-Sleep -Seconds 30; Test-WSMan -ComputerName ${var.vm_name} -ErrorAction Stop"
    EOT
  }

  provisioner "remote-exec" {
    inline = [
      "powershell -Command \"Install-PackageProvider -Name NuGet -Force; Install-Module -Name PSWindowsUpdate -Force\"",
      "powershell -Command \"Install-WindowsUpdate -AcceptAll -AutoReboot\"",
      "powershell -Command \"choco install python -y --version 3.12.7\"",
      "powershell -Command \"pip install ansible pywinrm\"",
      "powershell -Command \"New-Item -Path 'E:\\Malware' -ItemType Directory -Force\"",
      "powershell -Command \"New-Item -Path 'E:\\Collections' -ItemType Directory -Force\"",
      "powershell -Command \"New-Item -Path 'C:\\Logs' -ItemType Directory -Force\"",
      "powershell -Command \"New-Item -Path 'E:\\Tools\\Windows' -ItemType Directory -Force\"",
      "powershell -Command \"ansible-playbook -i 'localhost,' --connection=winrm --extra-vars 'ansible_user=${var.ansible_winrm_user} ansible_password=${var.ansible_winrm_password} container_runtime=${var.container_runtime} evidence_tool=${var.evidence_tool} cuckoo_vm_ip=${var.cuckoo_vm_ip}' C:\\vagrant\\ansible-playbook.yml\""
    ]
    connection {
      type     = "winrm"
      user     = var.ansible_winrm_user
      password = var.ansible_winrm_password
      host     = var.vm_name
    }
  }
}

resource "hyperv_vhd" "cuckoo_vhd" {
  count = var.evidence_tool == "cuckoo" ? 1 : 0
  path  = "C:\\Users\\Public\\Documents\\Hyper-V\\Virtual Hard Disks\\${var.cuckoo_vm_name}.vhdx"
  size  = var.disk_size_gb * 1073741824
}

resource "hyperv_vm_instance" "cuckoo_vm" {
  count                 = var.evidence_tool == "cuckoo" ? 1 : 0
  name                  = var.cuckoo_vm_name
  memory_startup_bytes  = 4096 * 1024 * 1024
  processor_count       = 4
  dynamic_memory        = true
  static_memory         = false
  generation            = 2
  state                 = "Running"

  network_adaptors {
    name        = "Network Adapter"
    switch_name = "Default Switch"
  }

  hard_disk_drives {
    controller_type     = "Scsi"
    controller_number   = 0
    controller_location = 0
    path               = hyperv_vhd.cuckoo_vhd[0].path
  }

  integration_services = {
    "Guest Service Interface" = true
    "Heartbeat"              = true
    "Key-Value Pair Exchange" = true
    "Shutdown"               = true
    "Time Synchronization"   = true
    "VSS"                    = true
  }

  provisioner "remote-exec" {
    inline = [
      "powershell -Command \"Install-PackageProvider -Name NuGet -Force; Install-Module -Name PSWindowsUpdate -Force\"",
      "powershell -Command \"Install-WindowsUpdate -AcceptAll -AutoReboot\"",
      "powershell -Command \"choco install python -y --version 3.12.7\"",
      "powershell -Command \"pip install cuckoo\"",
      "powershell -Command \"cuckoo --host ${var.cuckoo_vm_ip} --port ${var.cuckoo_api_port}\""
    ]
    connection {
      type     = "winrm"
      user     = var.ansible_winrm_user
      password = var.ansible_winrm_password
      host     = var.cuckoo_vm_name
    }
  }
}