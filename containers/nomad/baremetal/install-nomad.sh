#!/bin/bash
# Install HashiCorp Nomad on Debian or Red Hat-based systems

# Exit on error
set -e

# Variables
NOMAD_VERSION="1.9.2"
ARCH="amd64"
NOMAD_ZIP="nomad_${NOMAD_VERSION}_linux_${ARCH}.zip"
NOMAD_URL="https://releases.hashicorp.com/nomad/${NOMAD_VERSION}/${NOMAD_ZIP}"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/nomad.d"
DATA_DIR="/opt/nomad/data"

# Detect OS
if [ -f /etc/debian_version ]; then
    OS="debian"
    PKG_MANAGER="apt-get"
elif [ -f /etc/redhat-release ]; then
    OS="redhat"
    PKG_MANAGER="yum"
else
    echo "Unsupported OS. This script supports Debian/Ubuntu or RHEL/CentOS."
    exit 1
fi

# Install dependencies
echo "Installing dependencies..."
if [ "$OS" = "debian" ]; then
    sudo $PKG_MANAGER update -y
    sudo $PKG_MANAGER install -y unzip curl
elif [ "$OS" = "redhat" ]; then
    sudo $PKG_MANAGER install -y unzip curl
fi

# Download and install Nomad
echo "Downloading Nomad ${NOMAD_VERSION}..."
curl -sSL "$NOMAD_URL" -o "/tmp/${NOMAD_ZIP}"

echo "Installing Nomad..."
sudo unzip -o "/tmp/${NOMAD_ZIP}" -d "$INSTALL_DIR"
sudo chmod +x "${INSTALL_DIR}/nomad"
rm "/tmp/${NOMAD_ZIP}"

# Verify installation
nomad version

# Create directories for Nomad configuration and data
echo "Setting up Nomad directories..."
sudo mkdir -p "$CONFIG_DIR" "$DATA_DIR"
sudo chown -R $(whoami):$(whoami) "$DATA_DIR"
sudo chmod 755 "$CONFIG_DIR" "$DATA_DIR"

# Ensure Nomad binary is in PATH
if ! command -v nomad &> /dev/null; then
    echo "Nomad binary not found in PATH. Please ensure ${INSTALL_DIR} is in your PATH."
    exit 1
fi

echo "Nomad installation completed successfully!"
echo "Next steps:"
echo "1. Configure Nomad by editing ${CONFIG_DIR}/nomad.hcl"
echo "2. Set up a systemd service to run Nomad (e.g., /etc/systemd/system/nomad.service)"
echo "3. Start Nomad with: sudo systemctl start nomad"