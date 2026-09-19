import argparse
import json
import logging
import os
import subprocess
import sys

def setup_logging(log_file, verbose):
    """Configure logging to file or console."""
    level = logging.DEBUG if verbose else logging.INFO
    if log_file:
        logging.basicConfig(filename=log_file, level=level,
                           format='%(asctime)s [%(levelname)s] %(message)s')
    else:
        logging.basicConfig(stream=sys.stderr, level=level,
                           format='%(asctime)s [%(levelname)s] %(message)s')
    logging.info("Starting podman_process_decloak")

def validate_path(path):
    """Validate that a log file path is writable."""
    if path:
        dir_path = os.path.dirname(path) or "."
        if not os.path.exists(dir_path):
            raise argparse.ArgumentTypeError(f"Directory for log file {path} does not exist")
        if not os.access(dir_path, os.W_OK):
            raise argparse.ArgumentTypeError(f"Directory for log file {path} is not writable")
    return path

def validate_host_log_dir():
    """Validate that the host's /var/log is writable."""
    log_dir = "/var/log"
    if not os.path.exists(log_dir):
        raise argparse.ArgumentTypeError(f"Host log directory {log_dir} does not exist")
    if not os.access(log_dir, os.W_OK):
        raise argparse.ArgumentTypeError(f"Host log directory {log_dir} is not writable. Ensure proper permissions (e.g., sudo chmod 770 /var/log)")
    return log_dir

def summarize_json_output(json_str):
    """Summarize JSON output with key metrics."""
    try:
        data = json.loads(json_str)
        pid_count = data.get("pid_count", 0)
        return f"Summary: {pid_count} hidden PIDs found"
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse JSON for summary: {e}")
        return "Summary: Unable to parse JSON output"

def main():
    parser = argparse.ArgumentParser(description="Build and run Podman container for process_decloak.")
    parser.add_argument("--build", action="store_true", help="Build the Podman image before running")
    parser.add_argument("--no-recreate", action="store_true", help="Remove any existing container before running")
    parser.add_argument("--container-name", default="processdecloak", help="Name of the Podman container (default: processdecloak)")
    parser.add_argument("-json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--host-proc", action="store_true", help="Scan host processes (mounts /proc to /host_proc; requires --privileged)")
    parser.add_argument("-o", "--output", type=str, help="Save output to the specified file")
    parser.add_argument("--append", action="store_true", help="Append to output file instead of overwriting")
    parser.add_argument("--timeout", type=int, default=300, help="Timeout for scan execution in seconds (default: 300)")
    parser.add_argument("--log", type=validate_path, help="Log script actions to the specified file (default: stderr)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--summarize", action="store_true", help="Summarize JSON output (used with -json)")
    parser.add_argument("-log-stdout", action="store_true", help="Log process_decloak messages to stdout instead of /var/log/process_decloak.log")

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.log, args.verbose)

    # Validate host /var/log directory
    if not args.log_stdout:
        validate_host_log_dir()

    # Validate inputs
    image_name = "processdecloak"

    # Build image if requested
    if args.build:
        logging.info("Building Podman image")
        try:
            subprocess.check_call(["sudo", "podman", "build", "-t", image_name, "."])
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to build image: {e}")
            sys.exit(1)

    # Remove existing container if not reusing
    if not args.no_recreate:
        logging.info(f"Removing existing container {args.container_name}")
        subprocess.call(["sudo", "podman", "rm", "-f", args.container_name])

    # Build run command with arguments
    run_cmd = ["sudo", "podman", "run", "--rm", "--name", args.container_name]
    if args.host_proc:
        run_cmd += ["--privileged", "-v", "/proc:/host_proc:Z", "-e", "HOST_PROC=/host_proc"]
    run_cmd += ["-v", "/var/log:/var/log:Z"]
    run_cmd += [image_name]
    if args.json:
        run_cmd += ["-json"]
    if args.log_stdout:
        run_cmd += ["-log-stdout"]
    else:
        run_cmd += ["-log", "/var/log/process_decloak.log"]

    # Run scan and capture output
    logging.info(f"Running scan with command: {' '.join(run_cmd)}")
    try:
        output = subprocess.check_output(run_cmd, timeout=args.timeout).decode()
        if args.json and args.summarize:
            summary = summarize_json_output(output)
            output = f"{summary}\n\n{output}"
        if args.output:
            mode = "a" if args.append else "w"
            with open(args.output, mode) as f:
                f.write(output)
            logging.info(f"Output written to {args.output} (mode: {mode})")
        else:
            print(output)
    except subprocess.TimeoutExpired:
        logging.error(f"Scan timed out after {args.timeout} seconds")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        logging.error(f"Scan failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()