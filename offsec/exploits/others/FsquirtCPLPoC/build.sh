#!/usr/bin/env bash
set -euo pipefail

CC="x86_64-w64-mingw32-gcc"

echo "[*] Building bthprops.cpl (CPL loading from fsquirt.exe PoC)..."

$CC -shared -o bthprops.cpl main.c\
    -Wall \
    -Wl,--subsystem,windows \
    -luser32 \
    -lkernel32

if [[ -f "bthprops.cpl" ]]; then
    echo "[+] Built bthprops.cpl successfully!"
    strip bthprops.cpl
    echo "[+] Stripped debug symbols"
    echo ""
    echo "Usage:"
    echo "  [+] Place bthprops.cpl in the target directory"
else
    echo "[!] Build failed - bthprops.cpl not found" >&2
    exit 1
fi
