#!/usr/bin/env python3
"""
Script to deploy the outbound network traffic monitoring system in Docker.
Prompts for network interface and manages Docker container deployment.

RW
"""

import subprocess
import sys
import logging
from pathlib import Path
import shutil

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

def check_prerequisites():
    """Check for Docker and Docker Compose."""
    for cmd in ["docker", "docker", "compose"]:  # Check for 'docker compose'
        if not shutil.which(cmd):
            logger.error(f"Missing dependency: {cmd}")
            sys.exit(1)

def get_network_interfaces():
    """Retrieve available network interfaces."""
    try:
        output = subprocess.run(
            ["ip", "link", "show"], capture_output=True, text=True, check=True
        ).stdout
        interfaces = [
            line.split(": ")[1]
            for line in output.splitlines()
            if ": " in line and "lo:" not in line
        ]
        return interfaces
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to list interfaces: {e}")
        sys.exit(1)

def validate_interface(iface, interfaces):
    """Validate network interface is up."""
    if iface not in interfaces:
        return False
    try:
        subprocess.run(
            ["ip", "link", "show", iface, "up"],
            capture_output=True,
            text=True,
            check=True,
        )
        return True
    except subprocess.CalledProcessError:
        logger.error(f"Interface {iface} is not up or does not exist.")
        return False

def setup_host_directories():
    """Ensure host log directories exist with correct permissions."""
    for log_dir in ["/var/log/outbound_collector", "/var/log/siem"]:
        dir_path = Path(log_dir)
        dir_path.mkdir(parents=True, exist_ok=True)
        subprocess.run(["chmod", "750", str(dir_path)], check=True)
        subprocess.run(["chown", "root:root", str(dir_path)], check=True)

def deploy_container():
    """Deploy the Docker containers."""
    try:
        subprocess.run(["docker", "compose", "build"], check=True)
        subprocess.run(["docker", "compose", "up", "-d"], check=True)
        logger.info("Docker containers deployed successfully.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to deploy containers: {e}")
        sys.exit(1)

def main():
    check_prerequisites()
    interfaces = get_network_interfaces()
    if not interfaces:
        logger.error("No network interfaces found.")
        sys.exit(1)

    max_attempts = 3
    for attempt in range(max_attempts):
        logger.info(f"Available interfaces: {', '.join(interfaces)}")
        iface = input(f"Enter the network interface to monitor (attempt {attempt + 1}/{max_attempts}): ")
        if validate_interface(iface, interfaces):
            break
        if attempt == max_attempts - 1:
            logger.error("Max attempts reached. Exiting.")
            sys.exit(1)

    setup_host_directories()
    deploy_container()

if __name__ == "__main__":
    main()