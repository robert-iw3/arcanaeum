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
    logging.info("Starting podman_entropy_scan")

def validate_path(path, is_file=False):
    """Validate that a path is readable and not a symlink."""
    if not os.path.exists(path):
        raise argparse.ArgumentTypeError(f"Path {path} does not exist")
    if not os.access(path, os.R_OK):
        raise argparse.ArgumentTypeError(f"Path {path} is not readable")
    if os.path.islink(path):
        raise argparse.ArgumentTypeError(f"Path {path} is a symlink, which is not allowed")
    if is_file and not os.path.isfile(path):
        raise argparse.ArgumentTypeError(f"Path {path} is not a file")
    return os.path.abspath(path)

def summarize_json_output(json_str):
    """Summarize JSON output with key metrics."""
    try:
        data = json.loads(json_str)
        files = data.get("files", [])
        high_entropy_count = len([f for f in files if f.get("entropy", 0) >= 7.0])
        elf_count = len([f for f in files if f.get("is_elf", False)])
        return (f"Summary: {len(files)} files scanned, {high_entropy_count} with entropy >= 7.0, "
                f"{elf_count} ELF files")
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse JSON for summary: {e}")
        return "Summary: Unable to parse JSON output"

def main():
    parser = argparse.ArgumentParser(description="Build and run Podman container for entropy_scan.")
    parser.add_argument("--build", action="store_true", help="Build the Podman image before running")
    parser.add_argument("--no-recreate", action="store_true", help="Reuse existing container if available")
    parser.add_argument("--container-name", default="entropyscan", help="Name of the Podman container (default: entropyscan)")
    parser.add_argument("-csv", action="store_true", help="Output results in CSV format")
    parser.add_argument("-delim", default=",", help="Change the default delimiter for CSV files")
    parser.add_argument("-dir", type=lambda x: validate_path(x), help="Host directory to analyze (mounts to /scan)")
    parser.add_argument("-file", type=lambda x: validate_path(x, is_file=True), help="Host file to analyze (mounts dir to /scan)")
    parser.add_argument("-proc", action="store_true", help="Check running processes in container (defaults to ELF only)")
    parser.add_argument("--host-proc", action="store_true", help="Check running processes on host (requires /proc mount)")
    parser.add_argument("-elf", action="store_true", help="Only check ELF executables")
    parser.add_argument("-entropy", type=float, default=0.0, help="Show files/processes with entropy >= this value (0.0-8.0)")
    parser.add_argument("-json", action="store_true", help="Output in JSON format")
    parser.add_argument("-version", action="store_true", help="Show version and exit")
    parser.add_argument("-o", "--output", type=str, help="Save output to specified file")
    parser.add_argument("--append", action="store_true", help="Append to output file instead of overwriting")
    parser.add_argument("--timeout", type=int, default=300, help="Timeout for scan execution in seconds (default: 300)")
    parser.add_argument("--log", type=str, help="Log to specified file (default: stderr)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.log, args.verbose)

    # Validate inputs
    if args.entropy > 8.0 or args.entropy < 0.0:
        parser.error("Entropy value must be between 0.0 and 8.0")
    if args.dir and args.file:
        parser.error("Specify either -dir or -file, not both")
    if (args.dir or args.file) and (args.proc or args.host_proc):
        parser.error("-proc or --host-proc cannot be combined with -dir or -file")
    if args.proc and args.host_proc:
        parser.error("Specify either -proc or --host-proc, not both")
    if not (args.dir or args.file or args.proc or args.host_proc or args.version):
        parser.error("Must specify -dir, -file, -proc, --host-proc, or -version")

    image_name = "entropyscan"
    volume_path = None
    proc_path = "/proc" if args.proc else "/host_proc" if args.host_proc else None

    # Build image if requested
    if args.build:
        logging.info("Building Podman image")
        try:
            subprocess.check_call(["sudo", "podman", "build", "-t", image_name, "."])
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to build image: {e}")
            sys.exit(1)

    # Check if container exists and is running
    container_exists = False
    if not args.no_recreate:
        logging.info(f"Removing existing container {args.container_name}")
        subprocess.call(["sudo", "podman", "rm", "-f", args.container_name])
    else:
        try:
            result = subprocess.check_output(["sudo", "podman", "ps", "-a", "--filter", f"name={args.container_name}", "--format", "{{.State}}"]).decode().strip()
            container_exists = bool(result)
            logging.info(f"Container {args.container_name} exists with state: {result}")
        except subprocess.CalledProcessError:
            logging.debug(f"Container {args.container_name} does not exist")

    # Start container if not reusing or not running
    if not container_exists or not args.no_recreate:
        run_cmd = ["sudo", "podman", "run", "-d", "--name", args.container_name]
        if args.proc or args.host_proc:
            run_cmd.append("--privileged")
        if args.dir:
            volume_path = args.dir
            run_cmd += ["-v", f"{volume_path}:/scan:Z"]
        elif args.file:
            volume_path = os.path.dirname(args.file)
            run_cmd += ["-v", f"{volume_path}:/scan:Z"]
        if args.host_proc:
            run_cmd += ["-v", "/proc:/host_proc:Z"]
        run_cmd += [image_name]
        logging.info(f"Starting container with command: {' '.join(run_cmd)}")
        try:
            subprocess.check_call(run_cmd)
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to start container: {e}")
            sys.exit(1)

    # Build exec command
    exec_cmd = ["sudo", "podman", "exec", args.container_name, "/entropy_scan"]
    if args.version:
        exec_cmd += ["-version"]
    if args.proc or args.host_proc:
        exec_cmd += ["-proc"]
    if args.elf:
        exec_cmd += ["-elf"]
    if args.entropy != 0.0:
        exec_cmd += ["-entropy", str(args.entropy)]
    if args.csv:
        exec_cmd += ["-csv"]
    if args.delim != ",":
        exec_cmd += ["-delim", args.delim]
    if args.json:
        exec_cmd += ["-json"]
    if args.dir:
        exec_cmd += ["-dir", "/scan"]
    if args.file:
        file_base = os.path.basename(args.file)
        exec_cmd += ["-file", f"/scan/{file_base}"]

    # Run exec and capture output
    logging.info(f"Running scan with command: {' '.join(exec_cmd)}")
    try:
        output = subprocess.check_output(exec_cmd, timeout=args.timeout).decode()
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