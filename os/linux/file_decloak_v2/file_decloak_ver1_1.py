#!/usr/bin/env python3
"""
File Decloaking Utility - Version 1.1
Detects cloaked data in files potentially hidden by LKM or LD_PRELOAD rootkits.
Compares file contents and sizes using standard I/O and memory-mapped I/O.

Usage:
    python3 file_decloak.py -f <file> [-v] [-o <output_file>] [--version]
"""

import argparse
import mmap
import os
import sys
import binascii
import hashlib
from datetime import datetime
from termcolor import colored  # Requires: pip install termcolor

VERSION = "1.1"

def validate_file(file_path):
    """Validate that the file exists, is a file, and is readable."""
    if not os.path.exists(file_path):
        print(colored(f"Error: File '{file_path}' does not exist", "red"))
        sys.exit(1)
    if not os.path.isfile(file_path):
        print(colored(f"Error: '{file_path}' is not a file", "red"))
        sys.exit(1)
    if not os.access(file_path, os.R_OK):
        print(colored(f"Error: No read permission for '{file_path}'", "red"))
        sys.exit(1)
    return True

def get_file_metadata(file_path):
    """Retrieve file metadata (size, permissions, owner, timestamps)."""
    stat = os.stat(file_path)
    return {
        "size": stat.st_size,
        "permissions": oct(stat.st_mode)[-3:],
        "owner": os.stat(file_path).st_uid,
        "mtime": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
    }

def compute_file_hash(file_path):
    """Compute SHA-256 hash of file contents."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def read_standard_io(file_path, verbose=False):
    """Read file contents using standard I/O and return size."""
    file_size = 0
    contents = []
    try:
        with open(file_path, "r+b") as f:
            for line in f:
                contents.append(line)
                file_size += len(line)
                if verbose:
                    try:
                        print(line.decode('utf-8').rstrip())
                    except UnicodeDecodeError:
                        print(f"hex: {binascii.hexlify(line).decode('utf-8')}")
    except Exception as e:
        print(colored(f"Error reading '{file_path}' with standard I/O: {e}", "red"))
        sys.exit(1)
    return file_size, contents

def read_mmap_io(file_path, verbose=False):
    """Read file contents using memory-mapped I/O and return size."""
    file_size = 0
    contents = []
    try:
        with open(file_path, "r+b") as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                file_size = mm.size()
                while True:
                    line = mm.readline()
                    if not line:
                        break
                    contents.append(line)
                    if verbose:
                        try:
                            print(line.decode('utf-8').rstrip())
                        except UnicodeDecodeError:
                            print(f"hex: {binascii.hexlify(line).decode('utf-8')}")
    except Exception as e:
        print(colored(f"Error reading '{file_path}' with mmap I/O: {e}", "red"))
        sys.exit(1)
    return file_size, contents

def dump_cloaked_data(file_path, std_contents, mmap_contents, output_file=None):
    """Dump differing contents to a file or print to console."""
    diff_contents = [line for line in mmap_contents if line not in std_contents]
    if not diff_contents:
        return
    output = "\n".join(
        line.decode('utf-8', errors='ignore').rstrip() if line.decode('utf-8', errors='ignore') else
        f"hex: {binascii.hexlify(line).decode('utf-8')}" for line in diff_contents
    )
    if output_file:
        try:
            with open(output_file, "w") as f:
                f.write(output)
            print(colored(f"Cloaked data dumped to '{output_file}'", "yellow"))
        except Exception as e:
            print(colored(f"Error writing to '{output_file}': {e}", "red"))
    else:
        print(colored("\nCloaked Data Contents:", "yellow"))
        print(output)

def main():
    """Main function to process files and detect cloaked data."""
    parser = argparse.ArgumentParser(
        description="Detect cloaked data in files potentially hidden by LKM or LD_PRELOAD rootkits."
    )
    parser.add_argument("-f", "--file", action="append", required=True, help="File to analyze (can specify multiple)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print file contents during analysis")
    parser.add_argument("-o", "--output", help="Output file for cloaked data")
    parser.add_argument("--version", action="store_true", help="Show script version")
    args = parser.parse_args()

    if args.version:
        print(f"File Decloaking Utility - Version {VERSION}")
        sys.exit(0)

    print(colored(f"\nFile Decloaking Utility - Version {VERSION}", "cyan"))
    print("=" * 55)
    print("Agentless Security for Linux\n")

    for file_path in args.file:
        print(colored(f"\nAnalyzing file: {file_path}", "cyan"))
        print("-" * 40)

        # Validate file
        validate_file(file_path)

        # Display metadata
        metadata = get_file_metadata(file_path)
        print(f"File Metadata:")
        print(f"  Size: {metadata['size']} bytes")
        print(f"  Permissions: {metadata['permissions']}")
        print(f"  Owner UID: {metadata['owner']}")
        print(f"  Last Modified: {metadata['mtime']}")
        print(f"  SHA-256: {compute_file_hash(file_path)}")

        # Read with standard I/O
        print(colored("\nStandard I/O Contents:", "green"))
        std_size, std_contents = read_standard_io(file_path, args.verbose)

        # Read with memory-mapped I/O
        print(colored("\nMemory-Mapped I/O Contents:", "green"))
        mmap_size, mmap_contents = read_mmap_io(file_path, args.verbose)

        # Compare sizes and contents
        print(f"\nStandard I/O size: {std_size} bytes")
        print(f"Memory-Mapped I/O size: {mmap_size} bytes")
        if std_size != mmap_size or std_contents != mmap_contents:
            print(colored("\nALERT: File sizes or contents do not match. Potential cloaked data detected!", "red"))
            dump_cloaked_data(file_path, std_contents, mmap_contents, args.output)
        else:
            print(colored("\nOK: File sizes and contents match. No cloaked data detected.", "green"))

if __name__ == "__main__":
    main()