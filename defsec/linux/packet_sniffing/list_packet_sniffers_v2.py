#!/usr/bin/env python3
"""
Python script to list processes with open packet sockets by parsing /proc/net/packet.
Designed for agentless Endpoint Detection and Response (EDR) on Linux.

Licensed under the MIT License (MIT).

RW

Usage: Run with root privileges to ensure access to all process directories.
"""

import os
import sys
import re
import json
from pathlib import Path
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
import logging

# Configuration
PROC_PATH = Path('/proc')
LOG_FILE = Path('/var/log/list_packet_sniffers.log')
SUMMARY_JSON = Path('/var/log/packet_sniffers_summary.json')
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
BACKUP_COUNT = 5  # Keep 5 backup logs

# Setup logging with rotation
handler = RotatingFileHandler(LOG_FILE, maxBytes=MAX_LOG_SIZE, backupCount=BACKUP_COUNT)
handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s', datefmt='%Y-%m-%dT%H:%M:%SZ'))
logging.basicConfig(level=logging.INFO, handlers=[handler, logging.StreamHandler(sys.stdout)])
logger = logging.getLogger(__name__)

def ensure_file_permissions(file_path):
    """
    Ensure the specified file exists with restricted permissions (600).

    Args:
        file_path (Path): Path to the file.
    """
    try:
        file_path.touch(exist_ok=True)
        os.chmod(file_path, 0o600)
    except OSError as e:
        logger.error(f"Failed to set permissions on {file_path}: {e}")
        sys.exit(1)

def main():
    """Main function to find processes with open packet sockets."""
    # Check for root privileges
    if os.geteuid() != 0:
        logger.error("This script requires root privileges.")
        sys.exit(1)

    # Ensure log and JSON file permissions
    ensure_file_permissions(LOG_FILE)
    ensure_file_permissions(SUMMARY_JSON)

    logger.info(f"Starting script with Python {sys.version.split()[0]} on {os.uname().sysname}")
    logger.info("Parsing inodes from /proc/net/packet")
    logger.info("---------------------------------------------------------------------")

    # Check if /proc/net/packet exists
    packet_file = PROC_PATH / 'net' / 'packet'
    if not packet_file.exists():
        logger.error(f"{packet_file} not found.")
        error_output = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sockets_found": 0,
            "processes": [],
            "error": f"{packet_file} not found"
        }
        with SUMMARY_JSON.open("w") as f:
            json.dump(error_output, f, indent=4)
        sys.exit(1)

    # Check if running in a container
    if (Path('/.dockerenv').exists() or
            Path('/run/.containerenv').exists() or
            any('docker' in line or 'lxc' in line for line in (PROC_PATH / '1' / 'cgroup').read_text().splitlines())):
        logger.info("Detected container environment. Ensure /proc is properly mounted.")

    # Read /proc/net/packet, skip header, and extract unique inode numbers
    inodes = set()
    try:
        with open(packet_file, 'r') as f:
            next(f)  # Skip header
            for line in f:
                parts = line.split()
                if len(parts) >= 9 and parts[8].isdigit():
                    inodes.add(parts[8])
    except (IOError, PermissionError) as e:
        logger.error(f"Failed to read {packet_file}: {e}")
        error_output = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sockets_found": 0,
            "processes": [],
            "error": f"Failed to read {packet_file}: {str(e)}"
        }
        with SUMMARY_JSON.open("w") as f:
            json.dump(error_output, f, indent=4)
        sys.exit(1)

    if not inodes:
        logger.info("No inodes found in /proc/net/packet. No packet sockets are currently open.")
        output = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sockets_found": 0,
            "processes": []
        }
        with SUMMARY_JSON.open("w") as f:
            json.dump(output, f, indent=4)
        sys.exit(0)

    logger.info(f"Found inodes: {', '.join(sorted(inodes))}")
    logger.info("")

    processes = []
    for packet_inode in sorted(inodes):
        logger.info(f"Searching for processes with packet socket inode: {packet_inode}")
        found_process = False

        # Iterate through all process directories
        for pid_dir in PROC_PATH.glob('[0-9]*'):
            pid = pid_dir.name
            comm_file = pid_dir / 'comm'
            exe_link = pid_dir / 'exe'
            fd_dir = pid_dir / 'fd'

            if not fd_dir.is_dir():
                continue

            process_name = "Unknown"
            try:
                if comm_file.exists() and comm_file.is_file():
                    process_name = comm_file.read_text().strip()
                elif exe_link.exists() and exe_link.is_symlink():
                    process_name = os.path.basename(os.readlink(exe_link))
            except (PermissionError, FileNotFoundError, OSError):
                logger.debug(f"Skipped PID {pid} due to permission or file error")
                continue

            # Iterate through all file descriptors
            for fd_link in fd_dir.iterdir():
                if fd_link.is_symlink():
                    try:
                        target = os.readlink(fd_link)
                        logger.debug(f"Checking FD: {fd_link} -> {target}")
                        match = re.match(r'^socket:\[(\d+)\]$', target)
                        if match:
                            socket_inode = match.group(1)
                            logger.debug(f"Comparing inode: {socket_inode} (FD) vs {packet_inode} (target)")
                            if socket_inode == packet_inode:
                                logger.info(f"  PID: {pid} (Name: {process_name})")
                                logger.info(f"    FD: {fd_link.name} -> {target}")
                                found_process = True
                                processes.append({
                                    "pid": pid,
                                    "name": process_name,
                                    "fd": fd_link.name,
                                    "inode": packet_inode
                                })
                    except (PermissionError, FileNotFoundError, OSError):
                        logger.debug(f"Skipped FD {fd_link} due to permission or file error")
                        continue

        if not found_process:
            logger.info(f"No process found for inode {packet_inode}.")
            logger.info("This may indicate a hidden process. Consider using tools like 'process_decloak'.")

        logger.info("---------------------------------------------------------------------")

    # Write JSON output
    output = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sockets_found": len(inodes),
        "processes": processes
    }
    try:
        with SUMMARY_JSON.open("w") as f:
            json.dump(output, f, indent=4)
        os.chmod(SUMMARY_JSON, 0o600)
    except OSError as e:
        logger.error(f"Failed to write to {SUMMARY_JSON}: {e}")
        sys.exit(1)

    logger.info(f"Summary: Found {len(processes)} processes with packet sockets.")
    logger.info(f"Detailed report written to {LOG_FILE}")
    logger.info(f"JSON summary written to {SUMMARY_JSON}")
    logger.info("Script finished.")

if __name__ == "__main__":
    main()