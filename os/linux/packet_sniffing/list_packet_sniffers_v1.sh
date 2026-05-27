#!/bin/bash
# This script lists processes that have packet sockets open by parsing /proc/net/packet.
#
# It accesses /proc/net/packet and /proc/[pid]/fd directly to find processes associated with
# packet sockets. It can help find processes that are sniffing network traffic without relying
# on external tools like lsof.
#
# Agentless Endpoint Detection and Response (EDR) for Linux
#
# Licensed under the MIT License (MIT)

# Usage: Run this script with root privileges to ensure access to all process directories.

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Please use 'sudo' or switch to the root user."
    exit 1
fi

echo "Parsing inodes from /proc/net/packet and finding associated processes"
echo "---------------------------------------------------------------------"

# Check if /proc/net/packet exists
if [ ! -f "/proc/net/packet" ]; then
    echo "Error: /proc/net/packet not found."
    exit 1
fi

# Read /proc/net/packet, skip header, and extract unique inode numbers
inodes=$(awk 'NR > 1 {print $9}' /proc/net/packet | sort -u)

if [ -z "$inodes" ]; then
    echo "No inodes found in /proc/net/packet. No packet sockets are currently open."
    exit 0
fi

echo "Found the following unique inodes in /proc/net/packet:"
echo "$inodes"
echo ""

for packet_inode in $inodes; do
    echo "Searching for processes with packet socket inode: $packet_inode"
    found_process=false

    # Iterate through all process directories
    for pid_dir in /proc/[0-9]*; do
        pid=$(basename "$pid_dir")
        comm_file="$pid_dir/comm"
        exe_link="$pid_dir/exe"

        # Check if the process directory and its 'fd' subdirectory exist
        if [ ! -d "$pid_dir/fd" ]; then
            continue
        fi

        process_name="Unknown"
        if [ -f "$comm_file" ]; then
            process_name=$(cat "$comm_file")
        elif [ -L "$exe_link" ]; then
            # Fallback to executable path if 'comm' is not available
            process_name=$(readlink -f "$exe_link" | xargs basename)
        fi

        # Iterate through all file descriptors for the current process
        for fd_link in "$pid_dir"/fd/*; do
            if [ -L "$fd_link" ]; then
                # Read the target of the symlink
                target=$(readlink "$fd_link")

                # Check if the target is a socket and contains the inode number
                # Common format for socket file descriptors is "socket:[inode]"
                if [[ "$target" =~ ^socket:\[([0-9]+)\]$ ]]; then
                    socket_inode="${BASH_REMATCH[1]}"

                    if [ "$socket_inode" = "$packet_inode" ]; then
                        echo "  PID: $pid (Name: $process_name)"
                        echo "    FD: $(basename "$fd_link") -> $target"
                        found_process=true
                    fi
                fi
            fi
        done
    done

    if ! $found_process; then
        echo "No process found with a file descriptor linking to inode $packet_inode."
        echo "This may indicate that a process is grabbing packets but is not showing itself in /proc."
        echo "If you suspect a hidden process, consider using tools like 'process_decloak' for further investigation."
    fi
    echo "---------------------------------------------------------------------"
done

echo "Script finished."