source "amazon-ebs" "nomad-podman" {
  ami_name      = "nomad-consul-vault-ubuntu-${formatdate("YYYYMMDDHHMMSS", timestamp())}"
  instance_type = "t3.medium"
  region        = "us-east-1"
  source_ami_filter {
    filters = {
      name                = "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"
      virtualization-type = "hvm"
    }
    most_recent = true
    owners      = ["099720109477"]
  }
  ssh_username = "ubuntu"
}

build {
  sources = ["source.amazon-ebs.nomad-podman"]

  provisioner "shell" {
    inline = [
      "sudo apt-get update",
      "sudo apt-get install -y unzip curl chrony podman crun slirp4netns cni-plugins logrotate",
      "sudo useradd -r -s /sbin/nologin -M nomad",
      "sudo useradd -r -s /sbin/nologin -M consul",
      "sudo useradd -r -s /sbin/nologin -M vault",
      "sudo mkdir -p /etc/nomad.d /opt/nomad/data /var/log/nomad",
      "sudo mkdir -p /etc/consul.d /opt/consul/data /var/log/consul",
      "sudo mkdir -p /etc/vault.d /opt/vault/data /var/log/vault",
      "sudo chown -R nomad:nomad /etc/nomad.d /opt/nomad/data /var/log/nomad",
      "sudo chown -R consul:consul /etc/consul.d /opt/consul/data /var/log/consul",
      "sudo chown -R vault:vault /etc/vault.d /opt/vault/data /var/log/vault",
      "sudo chmod 0700 /etc/nomad.d /opt/nomad/data /etc/consul.d /opt/consul/data /etc/vault.d /opt/vault/data",
      "sudo chmod 0750 /var/log/nomad /var/log/consul /var/log/vault",
      "sudo mkdir -p /home/nomad/.config/containers",
      "sudo bash -c 'cat <<EOF > /home/nomad/.config/containers/storage.conf\n[storage]\ndriver = \"overlay\"\nrunroot = \"/run/user/1000\"\ngraphroot = \"/home/nomad/.local/share/containers/storage\"\n[network]\nnetwork_backend = \"cni\"\nEOF'",
      "sudo mkdir -p /home/nomad/.config/cni/net.d",
      "sudo bash -c 'cat <<EOF > /home/nomad/.config/cni/net.d/99-nomad.conflist\n{\n  \"cniVersion\": \"0.4.0\",\n  \"name\": \"nomad\",\n  \"plugins\": [\n    {\n      \"type\": \"bridge\",\n      \"bridge\": \"nomad0\",\n      \"isGateway\": true,\n      \"ipMasq\": true,\n      \"ipam\": {\n        \"type\": \"host-local\",\n        \"subnet\": \"10.88.0.0/16\",\n        \"routes\": [\n          { \"dst\": \"0.0.0.0/0\" }\n        ]\n      }\n    }\n  ]\n}\nEOF'",
      "sudo chown -R nomad:nomad /home/nomad/.config",
      "sudo chmod -R 0600 /home/nomad/.config",
      "sudo curl -fsSL https://releases.hashicorp.com/nomad/1.9.2/nomad_1.9.2_linux_amd64.zip -o /tmp/nomad.zip",
      "sudo unzip /tmp/nomad.zip -d /usr/local/bin",
      "sudo chmod 0750 /usr/local/bin/nomad",
      "sudo chown nomad:nomad /usr/local/bin/nomad",
      "sudo /usr/local/bin/nomad --version | grep '1.9.2' || exit 1",
      "sudo curl -fsSL https://releases.hashicorp.com/consul/1.20.0/consul_1.20.0_linux_amd64.zip -o /tmp/consul.zip",
      "sudo unzip /tmp/consul.zip -d /usr/local/bin",
      "sudo chmod 0750 /usr/local/bin/consul",
      "sudo chown consul:consul /usr/local/bin/consul",
      "sudo /usr/local/bin/consul --version | grep '1.20.0' || exit 1",
      "sudo curl -fsSL https://releases.hashicorp.com/vault/1.17.2/vault_1.17.2_linux_amd64.zip -o /tmp/vault.zip",
      "sudo unzip /tmp/vault.zip -d /usr/local/bin",
      "sudo chmod 0750 /usr/local/bin/vault",
      "sudo chown vault:vault /usr/local/bin/vault",
      "sudo /usr/local/bin/vault --version | grep '1.17.2' || exit 1",
      "sudo sysctl -w vm.max_map_count=262144",
      "sudo sysctl -w net.core.somaxconn=1024",
      "sudo sysctl -w user.max_user_namespaces=28633",
      "sudo sysctl -w net.ipv4.ip_unprivileged_port_start=80",
      "sudo bash -c 'echo nomad:100000:65536 > /etc/subuid'",
      "sudo bash -c 'echo nomad:100000:65536 > /etc/subgid'",
      "sudo rm -f /tmp/nomad.zip /tmp/consul.zip /tmp/vault.zip"
    ]
  }
}