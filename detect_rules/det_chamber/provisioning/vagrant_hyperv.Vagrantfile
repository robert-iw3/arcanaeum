Vagrant.configure("2") do |config|
  # Map HOST_OS to Vagrant boxes
  host_os = ENV["HOST_OS"] || "server2022"
  config.vm.box = case host_os
                  when "server2019"
                    "StefanScherer/windows_2019"
                  when "server2022"
                    "peru/windows-server-2022-standard-x64-eval"
                  when "server2025"
                    "windows-2025-amd64"  # Custom box, build with Packer
                  when "win10"
                    "gusztavvargadr/windows-10"
                  when "win11"
                    "gusztavvargadr/windows-11"
                  else
                    "peru/windows-server-2022-standard-x64-eval"
                  end

  config.vm.hostname = ENV["VM_NAME"] || "malware-sandbox"
  config.vm.provider "hyperv" do |hv|
    hv.vmname = ENV["VM_NAME"] || "malware-sandbox"
    hv.cpus = ENV["CPU_COUNT"] || 2
    hv.memory = ENV["MEMORY_MB"] || 2048
    hv.enable_virtualization_extensions = true
    hv.linked_clone = true
  end
  config.vm.provision "shell", inline: <<-SHELL
    powershell -Command "Install-PackageProvider -Name NuGet -Force; Install-Module -Name PSWindowsUpdate -Force"
    powershell -Command "Install-WindowsUpdate -AcceptAll -AutoReboot"
    powershell -Command "choco install python -y --version 3.12.7"
    powershell -Command "pip install ansible pywinrm"
    powershell -Command "Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart"
    powershell -Command "New-Item -Path 'E:\\Malware' -ItemType Directory -Force"
    powershell -Command "New-Item -Path 'E:\\Collections' -ItemType Directory -Force"
    powershell -Command "New-Item -Path 'C:\\Logs' -ItemType Directory -Force"
    powershell -Command "New-Item -Path 'E:\\Tools\\Windows' -ItemType Directory -Force"
    powershell -Command "Test-WSMan -ErrorAction Stop"
    powershell -Command "ansible-playbook -i 'localhost,' --connection=winrm --extra-vars 'ansible_user=$($env:ANSIBLE_WINRM_USER) ansible_password=$($env:ANSIBLE_WINRM_PASSWORD) container_runtime=$($env:CONTAINER_RUNTIME) evidence_tool=$($env:EVIDENCE_TOOL) cuckoo_vm_ip=$($env:CUCKOO_VM_IP)' C:\\vagrant\\ansible-playbook.yml"
  SHELL
end