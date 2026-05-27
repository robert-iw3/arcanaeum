#!/bin/bash

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

# Get list of all home directories
home_dirs=$(awk -F':' '{ print $6 }' /etc/passwd)

function find_ssh_private_key {
    for dir in $home_dirs; do
        # Check if the .ssh directory exists
        if [ -d $dir/.ssh ]; then
            # Find all files in the .ssh directory that contain the word "PRIVATE"
            private_files=$(grep -lR "PRIVATE" $dir/.ssh 2>/dev/null)

            # If private_files is not empty, report
            if [ ! -z "$private_files" ]; then
                echo "User with home directory $dir has files in their .ssh directory that are likely private keys:"
                echo "$private_files"
            fi
        fi
    done
}

function find_ssh_keys_duplicates {
    for dir in $home_dirs; do
        # Check if the authorized_keys file exists
        if [ -f $dir/.ssh/authorized_keys ]; then
            # Sort keys, count duplicates, and print any with count > 1
            echo "Processing $dir/.ssh/authorized_keys."
            sort "$dir/.ssh/authorized_keys" | uniq -c | while read count key
            do
                if [ "$count" -gt 1 ]; then
                    echo "$key is duplicated $count times"
                fi
            done
        fi
    done
}

function find_ssh_keys_excessive {
    for dir in $home_dirs; do
        # Check if the authorized_keys file exists
        if [ -f $dir/.ssh/authorized_keys ]; then
            # Count the number of keys (lines) in the file
            num_keys=$(wc -l < $dir/.ssh/authorized_keys)

            # If 10 or more keys, report
            if [ $num_keys -ge $KEY_COUNT ]; then
                echo "User with home directory $dir has $num_keys keys in their authorized_keys file."
            fi
        fi
    done
}

function find_ssh_keys_modified_24hr {
    # 24 hours in seconds. Adjust to suit.
    SECONDS_LIMIT=86400

    # Get the current time
    now=$(date +%s)

    for dir in $home_dirs; do
        # Check if the authorized_keys file exists
        if [ -f $dir/.ssh/authorized_keys ]; then
            # Get the last modification time of the file
            mtime=$(stat -c %Y $dir/.ssh/authorized_keys)

            # Calculate the difference in seconds between now and the file's mtime
            diff=$((now - mtime))

            # If the file was modified in the last 24 hours (86400 seconds)
            if [ $diff -le $SECONDS_LIMIT ]; then
                echo "User with home directory $dir has modified their authorized_keys file in the last 24 hours."
            fi
        fi
    done
}

function find_ssh_keys_options_search {
    for dir in $home_dirs; do
        # Check if the authorized_keys file exists
        if [ -f $dir/.ssh/authorized_keys ]; then
            # Check if the file contains any lines that have options keywords present.
            options_set=$(egrep -l '^(command|environment|agent-forwarding|port-forwarding|user-rc|X11-forwarding|.*,\s*(command|environment|agent-forwarding|port-forwarding|user-rc|X11-forwarding))' $dir/.ssh/authorized_keys 2>/dev/null)

            # If options_set is not empty, report
            if [ ! -z "$options_set" ]; then
                echo "User with home directory $dir has options set in their authorized_keys file:"
                echo "$options_set"
            fi
        fi
    done
}

function ssh_keys2_search {
    for dir in $home_dirs; do
        # Check if the authorized_keys2 file exists
        if [ -f $dir/.ssh/authorized_keys2 ]; then
            echo "An authorized_keys2 file was found at: $dir/.ssh/authorized_keys2."
        fi
    done
}

find_ssh_private_key
find_ssh_keys_duplicates
find_ssh_keys_excessive
find_ssh_keys_modified_24hr
find_ssh_keys_options_search
ssh_keys2_search