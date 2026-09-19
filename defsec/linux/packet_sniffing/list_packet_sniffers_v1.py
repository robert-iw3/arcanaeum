#!/usr/bin/env python3
"""
Python script to list processes with open packet sockets by parsing /proc/net/packet.
It accesses /proc/net/packet and /proc/[pid]/fd directly to find processes associated with
packet sockets. It can help find processes that are sniffing network traffic without relying
on external tools like lsof.

Agentless Endpoint Detection and Response (EDR) for Linux.

Licensed under the MIT License (MIT).

Usage: Run this script with root privileges to ensure access to all process directories.

sudo python3 list_packet_sniffers_v1.py
"""

import os
import sys
import re
from pathlib import Path
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# Configuration
PROC_PATH = Path('/proc')

def main():
    # Check for root privileges
    if os.geteuid() != 0:
        logging.error("This script must be run as root. Please use 'sudo' or switch to the root user.")
        sys.exit(1)

    logging.info("Parsing inodes from /proc/net/packet and finding associated processes")
    logging.info("---------------------------------------------------------------------")

    # Check if /proc/net/packet exists
    packet_file = PROC_PATH / 'net' / 'packet'
    if not packet_file.exists():
        logging.error(f"Error: {packet_file} not found.")
        sys.exit(1)

    # Read /proc/net/packet, skip header, and extract unique inode numbers
    inodes = set()
    with open(packet_file, 'r') as f:
        next(f)  # Skip header
        for line in f:
            parts = line.split()
            if len(parts) >= 9:
                inode = parts[8]
                if inode.isdigit():
                    inodes.add(inode)

    if not inodes:
        logging.info("No inodes found in /proc/net/packet. No packet sockets are currently open.")
        sys.exit(0)

    logging.info("Found the following unique inodes in /proc/net/packet:")
    logging.info(', '.join(sorted(inodes)))
    logging.info("")

    for packet_inode in sorted(inodes):
        logging.info(f"Searching for processes with packet socket inode: {packet_inode}")
        found_process = False

        # Iterate through all process directories
        for pid_dir in PROC_PATH.glob('[0-9]*'):
            pid = pid_dir.name
            comm_file = pid_dir / 'comm'
            exe_link = pid_dir / 'exe'
            fd_dir = pid_dir / 'fd'

            # Check if the process directory and its 'fd' subdirectory exist
            if not fd_dir.is_dir():
                continue

            process_name = "Unknown"
            try:
                if comm_file.exists() and comm_file.is_file():
                    process_name = comm_file.read_text().strip()
                elif exe_link.exists() and exe_link.is_symlink():
                    # Fallback to executable path if 'comm' is not available
                    process_name = os.path.basename(os.readlink(exe_link))
            except (PermissionError, FileNotFoundError):
                continue  # Skip if permission denied or file not found

            # Iterate through all file descriptors for the current process
            for fd_link in fd_dir.iterdir():
                if fd_link.is_symlink():
                    try:
                        target = os.readlink(fd_link)
                        # Check if the target is a socket and contains the inode number
                        # Common format for socket file descriptors is "socket:[inode]"
                        match = re.match(r'^socket:\[(\d+)\]$', target)
                        if match:
                            socket_inode = match.group(1)
                            if socket_inode == packet_inode:
                                logging.info(f"  PID: {pid} (Name: {process_name})")
                                logging.info(f"    FD: {fd_link.name} -> {target}")
                                found_process = True
                    except (PermissionError, FileNotFoundError):
                        continue  # Skip inaccessible file descriptors

        if not found_process:
            logging.info(f"No process found with a file descriptor linking to inode {packet_inode}.")
            logging.info("This may indicate that a process is grabbing packets but is not showing itself in /proc.")
            logging.info("If you suspect a hidden process, consider using tools like 'process_decloak' for further investigation.")

        logging.info("---------------------------------------------------------------------")

    logging.info("Script finished.")

if __name__ == "__main__":
    main()