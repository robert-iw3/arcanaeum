#!/bin/bash
set -x

DNF=$(which dnf 2>/dev/null)
APT_GET=$(which apt-get 2>/dev/null)

echo "Running"

if [[ ! -z ${DNF} ]]; then
  echo "Installing Docker with RHEL Workaround"
  sudo dnf -yq install policycoreutils-python dnf-utils device-mapper-persistent-data lvm2
  sudo dnf -y remove docker-engine-selinux container-selinux
  sudo dnf-config-manager -y --add-repo https://download.docker.com/linux/centos/docker-ce.repo

  # sudo dnf install -y --setopt=obsoletes=0 \
  #  docker-ce \
  #  docker-ce-selinux

  # Pinning Docker version as the above does not work at the moment
  sudo dnf install -y --setopt=obsoletes=0 \
   docker-ce \
   docker-ce-cli \
   containerd.io \
   docker-buildx-plugin \
   docker-compose-plugin
elif [[ ! -z ${APT_GET} ]]; then
  echo "Installing Docker"
  curl -sSL https://get.docker.com/ | sudo sh
else
  echo "Prerequisites not installed due to OS detection failure"
  exit 1;
fi

sudo sh -c "echo \"DOCKER_OPTS='--dns 127.0.0.1 --dns 8.8.8.8 --dns-search service.consul'\" >> /etc/default/docker"

sudo systemctl enable docker
sudo systemctl start docker

echo "Complete"
