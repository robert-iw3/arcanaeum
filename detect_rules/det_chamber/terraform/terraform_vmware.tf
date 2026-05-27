provider "vsphere" {
  user           = var.vsphere_user
  password       = var.vsphere_password
  vsphere_server = var.vsphere_server
  allow_unverified_ssl = true
}

data "vsphere_datacenter" "dc" {
  name = "Datacenter"
}

data "vsphere_datastore" "datastore" {
  name          = "Datastore"
  datacenter_id = data.vsphere_datacenter.dc.id
}

data "vsphere_compute_cluster" "cluster" {
  name          = "Cluster"
  datacenter_id = data.vsphere_datacenter.dc.id
}

data "vsphere_network" "network" {
  name          = "VM Network"
  datacenter_id = data.vsphere_datacenter.dc.id
}

resource "vsphere_virtual_machine" "malware_sandbox_vm" {
  name             = var.vm_name
  resource_pool_id = data.vsphere_compute_cluster.cluster.resource_pool_id
  datastore_id     = data.vsphere_datastore.datastore.id
  num_cpus         = var.cpu_count
  memory           = var.memory_mb
  guest_id         = var.host_os == "server2019" ? "windows9Server64Guest" : var.host_os == "server2022" ? "windows9Server64Guest" : var.host_os == "server2025" ? "windows9Server64Guest" : var.host_os == "win10" ? "windows9_64Guest" : "windows9_64Guest"
  network_interface {
    network_id = data.vsphere_network.network.id
  }
  disk {
    label = "disk0"
    size  = var.disk_size_gb
  }
  cdrom {
    datastore_id = data.vsphere_datastore.datastore.id
    path         = var.iso_urls[var.host_os]
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

resource "vsphere_virtual_machine" "cuckoo_vm" {
  count            = var.evidence_tool == "cuckoo" ? 1 : 0
  name             = var.cuckoo_vm_name
  resource_pool_id = data.vsphere_compute_cluster.cluster.resource_pool_id
  datastore_id     = data.vsphere_datastore.datastore.id
  num_cpus         = 4
  memory           = 4096
  guest_id         = "windows9Server64Guest"
  network_interface {
    network_id = data.vsphere_network.network.id
  }
  disk {
    label = "disk0"
    size  = var.disk_size_gb
  }
  cdrom {
    datastore_id = data.vsphere_datastore.datastore.id
    path         = var.iso_urls[var.host_os]
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