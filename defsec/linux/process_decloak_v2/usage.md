### Prerequisites
---

Podman: Install Podman on your system (e.g., sudo apt install podman or sudo dnf install podman on Linux).

Python 3.6+: Required to run the script.

Go 1.23+: Needed to build the Go application (included in the container build process).

Root Privileges: Required for Podman commands and process scanning (both container and host processes).

Host /var/log Permissions: Ensure the host’s /var/log directory is writable (e.g., sudo chmod 770 /var/log) for logging unless using -log-stdout.

Source Files: Ensure the following files are in the same directory as the script:

```console
.
├── Dockerfile
├── go.mod
├── podman_process_decloak.py
├── process_decloak.go
├── processutils/
│   └── processutils.go
```

---

```bash
sudo python3 podman_process_decloak.py [options]
```

### Options
---

`--build`: Build the Podman image before running (required for first run or after code changes).

`--no-recreate`: Reuse an existing container if available, instead of removing and recreating it.

`--container-name <name>`: Specify the container name (default: processdecloak).

`-json`: Output results in JSON format.

`--host-proc`: Scan host processes (mounts /proc to /host_proc; requires `--privileged`).

`-o`, `--output <file>`: Save output to the specified file.

`--append`: Append to the output file instead of overwriting (used with `-o`).

`--timeout <seconds>`: Set timeout for scan execution (default: 300 seconds).

`--log <file>`: Log script actions to the specified file (default: stderr).

`--verbose`: Enable verbose logging for debugging.

`--summarize`: Summarize JSON output (e.g., count of hidden PIDs; used with `-json`).

`-log-stdout`: Log process_decloak messages to stdout instead of a file (recommended for containers).

### Constraints
---

Process scanning (container or host) requires root privileges, enforced by the Go application.

Use `-json` for machine-readable output; otherwise, output is human-readable.

The `--host-proc` flag requires `--privileged` and mounts /proc to /host_proc in the container.

### Examples
---

1. ***Build and scan for hidden PIDs in the container:***

    `sudo python3 podman_process_decloak.py --build -json -log-stdout`

    Builds the image and scans for hidden PIDs in the container, outputting in JSON and logging to stdout.

2. ***Scan host processes with JSON output and summary:***

    `sudo python3 podman_process_decloak.py --host-proc -json --summarize`

    Scans host processes, outputs in JSON, and prepends a summary.

3. ***Scan and save output to a file:***

    `sudo python3 podman_process_decloak.py -json -o hidden_pids.json`

    Scans container processes and saves JSON output to hidden_pids.json.

4. ***Reuse existing container with timeout:***

    `sudo python3 podman_process_decloak.py --no-recreate --timeout 600`

    Reuses the container and scans with a 10-minute timeout.

5. ***Scan with verbose logging to a file:***

    `sudo python3 podman_process_decloak.py --log scan.log --verbose`

    Scans container processes and logs script actions to scan.log with verbose output.

### Notes
---

The `--privileged` flag is used only for `--host-proc` to minimize security risks.

The container is removed and recreated unless `--no-recreate` is specified.

Host process scanning (`--host-proc`) mounts /proc to /host_proc and sets the HOST_PROC environment variable.

Logs are written to stderr by default or to a file with `--log`. Use `-log-stdout` for container-friendly logging.

Use `--verbose` for detailed logs during debugging.

The `--summarize` flag provides a summary for JSON output, showing the number of hidden PIDs found.

The process_decloak.go is in the main package, and processutils.go is in the processutils subpackage under github.com/sandflysecurity/sandfly-processdecloak.