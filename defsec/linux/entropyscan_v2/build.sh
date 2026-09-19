#!/bin/bash
# Build script for entropy_scan
#
# entropy_scan is an entropy scanner to spot packed/encrypted binaries and processes on Linux and other platforms.
#

echo "Building for current OS."
go build -ldflags="-s -w"