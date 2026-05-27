import argparse
import json
import logging
import os
import shutil
import subprocess
import time
import tempfile
from pathlib import Path
from typing import List, Optional

# Configuration
LOG_FILE = "/var/log/docker_stig.log"
JSON_LOG_FILE = "/var/log/docker_stig.json"
BACKUP_DIR = "/var/backups/docker"
DOCKER_DAEMON_JSON = "/etc/docker/daemon.json"
DOCKER_SOCK = "/run/containerd/containerd.sock"
DOCKER_LEGACY_CONF = "/etc/default/docker"
ETC_DOCKER_PATH = "/etc/docker"
DOCKER_SOCKET_PATH = "/lib/systemd/system/docker.socket"
DOCKER_SERVICE_PATH = "/lib/systemd/system/docker.service"
SYSLOG_ADDRESS = "udp://127.0.0.1:25224"
AUDIT_RULES_FILE = "/etc/audit/rules.d/docker.rules"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ],
    datefmt="%Y-%m-%dT%H:%M:%SZ"
)
logger = logging.getLogger(__name__)

def setup_json_logging():
    """Initialize JSON log file."""
    Path(JSON_LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(JSON_LOG_FILE).touch()
    os.chown(JSON_LOG_FILE, 0, 0)
    os.chmod(JSON_LOG_FILE, 0o640)

def log_json(stig_id: str, status: str, message: str):
    """Log to JSON file."""
    with open(JSON_LOG_FILE, "a") as f:
        json.dump({"id": stig_id, "status": status, "message": message, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, f)
        f.write("\n")

def check_privileges():
    """Check for root or CAP_SYS_ADMIN."""
    try:
        result = subprocess.run(["capsh", "--print"], capture_output=True, text=True, check=True)
        if "cap_sys_admin" not in result.stdout:
            logger.error("This script requires root or CAP_SYS_ADMIN privileges")
            log_json("ERROR", "ERROR", "Missing required privileges")
            exit(1)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to check capabilities: {e}")
        log_json("ERROR", "ERROR", f"Failed to check capabilities: {e}")
        exit(1)

def check_deps():
    """Check for required dependencies."""
    deps = ["jq", "auditctl", "ausearch", "docker", "rsyslogd"]
    for cmd in deps:
        if not shutil.which(cmd):
            logger.error(f"{cmd} is required but not installed")
            log_json("ERROR", "ERROR", f"{cmd} not installed")
            exit(1)

def backup_file(file: str):
    """Backup a file before modification."""
    file_path = Path(file)
    if file_path.exists():
        backup_path = Path(BACKUP_DIR) / f"{file_path.name}.{int(time.time())}"
        Path(BACKUP_DIR).mkdir(parents=True, exist_ok=True)
        shutil.copy2(file, backup_path)
        logger.info(f"Backed up {file} to {backup_path}")
        log_json("INFO", "INFO", f"Backed up {file} to {backup_path}")

def validate_path(path: str) -> Path:
    """Validate and resolve a path."""
    path = Path(path).resolve()
    if str(path).find("..") != -1:
        logger.error(f"Invalid path: {path}")
        log_json("ERROR", "ERROR", f"Invalid path: {path}")
        exit(1)
    return path

def configure_file(path: str, owner: str, perms: int, stig_id: str, desc: str, verbose: bool):
    """Configure file ownership and permissions."""
    path = validate_path(path)
    if path.exists():
        backup_file(path)
        subprocess.run(["chown", owner, path], check=True)
        logger.info(f"{stig_id}, PASS, {desc} (ownership set to {owner})")
        log_json(stig_id, "PASS", f"{desc} (ownership set to {owner})")
        if verbose:
            result = subprocess.run(["stat", "-c", "%U:%G", path], capture_output=True, text=True)
            print(f"Command: stat -c %U:%G {path}\nOutput: {result.stdout}")
        subprocess.run(["chmod", f"{perms:o}", path], check=True)
        logger.info(f"{stig_id}, PASS, {desc} (permissions set to {perms:o})")
        log_json(stig_id, "PASS", f"{desc} (permissions set to {perms:o})")
        if verbose:
            result = subprocess.run(["stat", "-c", "%a", path], capture_output=True, text=True)
            print(f"Command: stat -c %a {path}\nOutput: {result.stdout}")
    else:
        logger.info(f"{stig_id}, N/A, {path} does not exist")
        log_json(stig_id, "N/A", f"{path} does not exist")

def update_daemon_json(key: str, value: str, stig_id: str, desc: str, verbose: bool):
    """Update daemon.json with a key-value pair."""
    backup_file(DOCKER_DAEMON_JSON)
    with open(DOCKER_DAEMON_JSON, "r") as f:
        config = json.load(f)
    if key in config and json.dumps(config[key]) == value:
        logger.info(f"{stig_id}, PASS, {desc} (already set)")
        log_json(stig_id, "PASS", f"{desc} (already set)")
    else:
        config[key] = json.loads(value)
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            json.dump(config, tmp, indent=2)
            tmp_path = tmp.name
        shutil.move(tmp_path, DOCKER_DAEMON_JSON)
        logger.info(f"{stig_id}, PASS, {desc} (updated)")
        log_json(stig_id, "PASS", f"{desc} (updated)")
    if verbose:
        result = subprocess.run(["jq", f".{key}", DOCKER_DAEMON_JSON], capture_output=True, text=True)
        print(f"Command: jq .{key} {DOCKER_DAEMON_JSON}\nOutput: {result.stdout}")

def check_containers(format_str: str, pattern: str, stig_id: str, fail_msg: str, pass_msg: str, verbose: bool):
    """Check container configurations."""
    result = subprocess.run(f"docker ps --quiet --all | xargs --no-run-if-empty docker inspect --format '{format_str}'", shell=True, capture_output=True, text=True)
    if pattern in result.stdout:
        logger.info(f"{stig_id}, FAIL, {fail_msg}")
        log_json(stig_id, "FAIL", fail_msg)
    else:
        logger.info(f"{stig_id}, PASS, {pass_msg}")
        log_json(stig_id, "PASS", pass_msg)
    if verbose:
        print(f"Command: docker ps --quiet --all | xargs --no-run-if-empty docker inspect --format '{format_str}'")
        print(f"Output: {result.stdout}")

def main():
    parser = argparse.ArgumentParser(description="Apply Docker STIG configurations")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed command output")
    parser.add_argument("--json", "-j", action="store_true", help="Output logs in JSON format")
    parser.add_argument("--ip", "-i", help="Set Docker bind IP")
    parser.add_argument("--sock", "-s", default=DOCKER_SOCK, help="Set Docker socket path")
    args = parser.parse_args()

    # Initialize logging
    Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(LOG_FILE).touch()
    os.chown(LOG_FILE, 0, 0)
    os.chmod(LOG_FILE, 0o640)
    if args.json:
        setup_json_logging()

    logger.info("Starting Docker STIG configuration")
    log_json("INFO", "INFO", "Starting Docker STIG configuration")

    check_deps()
    check_privileges()

    # Validate socket
    DOCKER_SOCK = validate_path(args.sock)
    if not DOCKER_SOCK.is_socket():
        logger.error(f"Docker socket {DOCKER_SOCK} does not exist")
        log_json("ERROR", "ERROR", f"Docker socket {DOCKER_SOCK} does not exist")
        exit(1)

    # Initialize daemon.json
    DOCKER_DAEMON_JSON = validate_path(DOCKER_DAEMON_JSON)
    if not DOCKER_DAEMON_JSON.exists():
        with open(DOCKER_DAEMON_JSON, "w") as f:
            json.dump({}, f)
        logger.info(f"Created {DOCKER_DAEMON_JSON}")
        log_json("INFO", "INFO", f"Created {DOCKER_DAEMON_JSON}")

    # Auto-detect IP
    PRI_IP = args.ip
    if not PRI_IP:
        try:
            PRI_INTERFACE = subprocess.run("ip route | grep -m 1 'default via' | grep -Po '(?<=dev )\\S+'", shell=True, capture_output=True, text=True).stdout.strip()
            PRI_IP = subprocess.run(f"ip -f inet addr show {PRI_INTERFACE} | grep -Po '(?<=inet )(\\d{{1,3}}\\.)+\\d{{1,3}}'", shell=True, capture_output=True, text=True).stdout.strip() or "127.0.0.1"
            logger.info(f"Auto-detected IP: {PRI_IP} (interface: {PRI_INTERFACE})")
            log_json("INFO", "INFO", f"Auto-detected IP: {PRI_IP}")
            choice = input(f"Confirm Docker bind to {PRI_IP}? (y/n): ").lower()
            if choice != "y":
                logger.error(f"User declined IP {PRI_IP}, please specify with --ip")
                log_json("ERROR", "ERROR", f"User declined IP {PRI_IP}")
                exit(1)
        except subprocess.CalledProcessError:
            PRI_IP = "127.0.0.1"
            logger.info(f"Fallback to IP: {PRI_IP}")
            log_json("INFO", "INFO", f"Fallback to IP: {PRI_IP}")

    # File permissions and ownership
    configure_file(DOCKER_DAEMON_JSON, "root:root", 0o644, "V-235867", "Set daemon.json ownership and permissions", args.verbose)
    configure_file(DOCKER_SOCK, "root:docker", 0o660, "V-235865", "Set docker socket ownership and permissions", args.verbose)
    configure_file(ETC_DOCKER_PATH, "root:root", 0o755, "V-235855", "Set /etc/docker ownership and permissions", args.verbose)
    configure_file(DOCKER_SOCKET_PATH, "root:root", 0o644, "V-235853", "Set docker.socket ownership and permissions", args.verbose)
    configure_file(DOCKER_SERVICE_PATH, "root:root", 0o644, "V-235851", "Set docker.service ownership and permissions", args.verbose)
    configure_file(DOCKER_LEGACY_CONF, "root:root", 0o644, "V-235869", "Set legacy docker conf ownership and permissions", args.verbose)

    # Container checks
    check_containers('{{ .Id }}: SecurityOpt={{ .HostConfig.SecurityOpt }}', 'unconfined', 'V-235812', 'Found containers with seccomp unconfined', 'No seccomp unconfined containers found', args.verbose)
    check_containers('{{ .Id }}: Ulimits={{ .HostConfig.Ulimits }}', 'no value', 'V-235844', 'Containers override ulimit', 'No containers override default ulimit', args.verbose)
    check_containers('{{ .Id }}: PidMode={{ .HostConfig.PidMode }}', 'host', 'V-235784', 'Containers running with host PID namespace', 'No containers with host PID namespace', args.verbose)
    check_containers('{{ .Id }}: IpcMode={{ .HostConfig.IpcMode }}', 'host', 'V-235785', 'Containers running with host IPC namespace', 'No containers with host IPC namespace', args.verbose)
    check_containers('{{ .Id }}: UsernsMode={{ .HostConfig.UsernsMode }}', 'host', 'V-235817', 'Containers sharing host user namespace', 'No containers sharing host user namespace', args.verbose)
    check_containers('{{ .Id }}: UTSMode={{ .HostConfig.UTSMode }}', 'host', 'V-235811', 'Containers sharing host UTS namespace', 'No containers with host UTS namespace', args.verbose)
    check_containers('{{ .Id }}: Devices={{ .HostConfig.Devices }}', 'pathincontainer', 'V-235809', 'Containers with host devices passed in', 'No containers with host devices', args.verbose)
    check_containers('{{ .Id }}: Volumes={{ .Mounts }}', 'Source:[^ ]+:(/|/boot|/dev|/etc|/lib|/proc|/sys|/usr)$', 'V-235783', 'Sensitive directories mapped into containers', 'No sensitive directories mapped', args.verbose)
    check_containers('{{ .Id }}: Propagation={{range $mnt := .Mounts}} {{json $mnt.Propagation}} {{end}}', 'shared', 'V-235810', 'Mount propagation set to shared', 'No mounts set to shared propagation', args.verbose)
    check_containers('{{ .Id }}: CapAdd={{ .HostConfig.CapAdd }} CapDrop={{ .HostConfig.CapDrop }}', 'CapAdd=<no value> CapDrop=<no value>$', 'V-235801', 'Containers with added capabilities', 'No containers with additional capabilities', args.verbose)
    check_containers('{{ .Id }}: Privileged={{ .HostConfig.Privileged }}', 'true', 'V-235802', 'Containers running as privileged', 'No containers running as privileged', args.verbose)

    # AppArmor check
    result = subprocess.run("docker ps --quiet --all | xargs --no-run-if-empty docker inspect --format '{{ .Id }}: AppArmorProfile={{ .AppArmorProfile }}'", shell=True, capture_output=True, text=True)
    if "unconfined" in result.stdout:
        logger.info("V-235799, FAIL, Containers running without AppArmor profiles")
        log_json("V-235799", "FAIL", "Containers running without AppArmor profiles")
    else:
        logger.info("V-235799, PASS, All containers running with AppArmor profiles")
        log_json("V-235799", "PASS", "All containers running with AppArmor profiles")
    if args.verbose:
        print("Command: docker ps --quiet --all | xargs --no-run-if-empty docker inspect --format '{{ .Id }}: AppArmorProfile={{ .AppArmorProfile }}'")
        print(f"Output: {result.stdout}")

    # SSHD check
    pass_flag = True
    containers = subprocess.run("docker ps -qa", shell=True, capture_output=True, text=True).stdout.splitlines()
    for container in containers:
        result = subprocess.run(f"docker exec {container} ps -el", shell=True, capture_output=True, text=True, stderr=subprocess.DEVNULL)
        if "sshd" in result.stdout.lower():
            logger.info(f"V-235803, FAIL, Container {container} running sshd")
            log_json("V-235803", "FAIL", f"Container {container} running sshd")
            if args.verbose:
                print(f"Command: docker exec {container} ps -el | grep -i sshd")
                print(f"Output: {result.stdout}")
            pass_flag = False
    if pass_flag:
        logger.info("V-235803, PASS, No containers running sshd")
        log_json("V-235803", "PASS", "No containers running sshd")

    # Storage driver check
    result = subprocess.run("docker info --format '{{ .Driver }}'", shell=True, capture_output=True, text=True)
    if result.stdout.strip() == "aufs":
        logger.info("V-235790, FAIL, AUFS storage driver detected")
        log_json("V-235790", "FAIL", "AUFS storage driver detected")
    else:
        logger.info("V-235790, PASS, No AUFS storage driver detected")
        log_json("V-235790", "PASS", "No AUFS storage driver detected")
    if args.verbose:
        print("Command: docker info --format '{{ .Driver }}'")
        print(f"Output: {result.stdout}")

    # Experimental features
    result = subprocess.run("docker version --format '{{ .Server.Experimental }}'", shell=True, capture_output=True, text=True)
    if "false" in result.stdout:
        logger.info("V-235792, PASS, Experimental features disabled")
        log_json("V-235792", "PASS", "Experimental features disabled")
    else:
        logger.info("V-235792, FAIL, Experimental features enabled")
        log_json("V-235792", "FAIL", "Experimental features enabled")
    if args.verbose:
        print("Command: docker version --format '{{ .Server.Experimental }}'")
        print(f"Output: {result.stdout}")

    # Insecure registries
    dockerd = subprocess.run("pgrep -af dockerd", shell=True, capture_output=True, text=True).stdout
    daemon_json = subprocess.run(f"grep 'insecure-registry' {DOCKER_DAEMON_JSON}", shell=True, capture_output=True, text=True, stderr=subprocess.DEVNULL).stdout
    if "insecure-registry" in dockerd or daemon_json:
        logger.info("V-235789, FAIL, Insecure registries configured")
        log_json("V-235789", "FAIL", "Insecure registries configured")
    else:
        logger.info("V-235789, PASS, No insecure registries configured")
        log_json("V-235789", "PASS", "No insecure registries configured")
    if args.verbose:
        print(f"Command: pgrep -af dockerd && grep 'insecure-registry' {DOCKER_DAEMON_JSON}")
        print(f"Output: {dockerd}\n{daemon_json}")

    # Userland proxy
    if "userland-proxy" in dockerd:
        logger.info("V-235791, FAIL, Userland-proxy flag used in dockerd arguments")
        log_json("V-235791", "FAIL", "Userland-proxy flag used in dockerd arguments")
    else:
        result = subprocess.run(f"jq -e '.\"userland-proxy\" == false' {DOCKER_DAEMON_JSON}", shell=True, capture_output=True, text=True, stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            logger.info("V-235791, PASS, Userland-proxy disabled in daemon.json")
            log_json("V-235791", "PASS", "Userland-proxy disabled in daemon.json")
        else:
            update_daemon_json('"userland-proxy"', "false", "V-235791", "Disable userland-proxy", args.verbose)

    # IP binding
    result = subprocess.run(f"jq -e '.\"ip\" and .\"ip\" != \"0.0.0.0\"' {DOCKER_DAEMON_JSON}", shell=True, capture_output=True, text=True, stderr=subprocess.DEVNULL)
    if result.returncode == 0:
        logger.info("V-235820, PASS, Docker configured to listen on specific IP")
        log_json("V-235820", "PASS", "Docker configured to listen on specific IP")
    else:
        update_daemon_json('"ip"', f'"{PRI_IP}"', "V-235820", "Bind Docker to specific IP", args.verbose)

    # Logging configuration
    result = subprocess.run(f"jq -e '.\"log-driver\" == \"syslog\"' {DOCKER_DAEMON_JSON}", shell=True, capture_output=True, text=True, stderr=subprocess.DEVNULL)
    if result.returncode == 0:
        logger.info("V-235831, PASS, Log driver set to syslog")
        log_json("V-235831", "PASS", "Log driver set to syslog")
    else:
        update_daemon_json('"log-driver"', '"syslog"', "V-235831", "Configure log driver to syslog", args.verbose)

    result = subprocess.run(f"jq -e '.\"log-opts\".\"syslog-address\"' {DOCKER_DAEMON_JSON}", shell=True, capture_output=True, text=True, stderr=subprocess.DEVNULL)
    if result.returncode == 0:
        logger.info("V-235833, PASS, Remote syslog configured")
        log_json("V-235833", "PASS", "Remote syslog configured")
    else:
        update_daemon_json('"log-opts"', json.dumps({"syslog-address": SYSLOG_ADDRESS, "tag": "container_name/{{.Name}}", "syslog-facility": "daemon"}), "V-235833", "Configure remote syslog", args.verbose)

    # Log size limits
    result = subprocess.run(f"jq -e '.\"log-opts\".\"max-size\" and .\"log-opts\".\"max-file\"' {DOCKER_DAEMON_JSON}", shell=True, capture_output=True, text=True, stderr=subprocess.DEVNULL)
    if result.returncode == 0:
        logger.info("V-235786, PASS, Log max-size and max-file configured")
        log_json("V-235786", "PASS", "Log max-size and max-file configured")
    else:
        update_daemon_json('"log-opts"', json.dumps({"max-size": "10m", "max-file": "3"}), "V-235786", "Configure log max-size and max-file", args.verbose)

    # Audit rules
    audit_rules = f"""\
-w {DOCKER_DAEMON_JSON} -p wa -k docker
-w {DOCKER_SERVICE_PATH} -p wa -k docker
-w {DOCKER_SOCKET_PATH} -p wa -k docker
"""
    audit_check = subprocess.run(f"auditctl -l | grep -E '(-w {DOCKER_DAEMON_JSON}|-w {DOCKER_SERVICE_PATH}|-w {DOCKER_SOCKET_PATH})'", shell=True, capture_output=True, text=True)
    if len(audit_check.stdout.splitlines()) >= 3:
        logger.info("V-235779, PASS, Audit rules present for Docker files")
        log_json("V-235779", "PASS", "Audit rules present for Docker files")
    else:
        with open(AUDIT_RULES_FILE, "w") as f:
            f.write(audit_rules)
        os.chmod(AUDIT_RULES_FILE, 0o640)
        subprocess.run(["augenrules", "--load"], check=True)
        logger.info("V-235779, PASS, Audit rules added for Docker files")
        log_json("V-235779", "PASS", "Audit rules added for Docker files")
    if args.verbose:
        print(f"Command: auditctl -l | grep -E '(-w {DOCKER_DAEMON_JSON}|-w {DOCKER_SERVICE_PATH}|-w {DOCKER_SOCKET_PATH})'")
        print(f"Output: {audit_check.stdout}")

    # Privileged exec sessions
    result = subprocess.run("ausearch -k docker | grep exec | grep privileged", shell=True, capture_output=True, text=True, stderr=subprocess.DEVNULL)
    if result.stdout:
        logger.info("V-235813, FAIL, Exec sessions running with privileged flag")
        log_json("V-235813", "FAIL", "Exec sessions running with privileged flag")
    else:
        logger.info("V-235813, PASS, No privileged exec sessions found")
        log_json("V-235813", "PASS", "No privileged exec sessions found")
    if args.verbose:
        print("Command: ausearch -k docker | grep exec | grep privileged")
        print(f"Output: {result.stdout}")

    # User flag in exec
    result = subprocess.run("pgrep -af 'docker exec' | grep -E '\\-u|\\-\\-user'", shell=True, capture_output=True, text=True)
    if result.stdout:
        logger.info("V-235814, FAIL, Exec sessions running with user flag")
        log_json("V-235814", "FAIL", "Exec sessions running with user flag")
    else:
        logger.info("V-235814, PASS, No exec sessions with user flag found")
        log_json("V-235814", "PASS", "No exec sessions with user flag found")
    if args.verbose:
        print("Command: pgrep -af 'docker exec' | grep -E '\\-u|\\-\\-user'")
        print(f"Output: {result.stdout}")

    # Host port check
    result = subprocess.run("docker ps --quiet --all | xargs --no-run-if-empty docker inspect --format '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}' | grep -Po '(?<=HostPort:)\\d+' | sort -n | head -n 1", shell=True, capture_output=True, text=True)
    low_port = result.stdout.strip()
    if low_port and int(low_port) < 1024:
        logger.info("V-235819, FAIL, Host ports below 1024 mapped into containers")
        log_json("V-235819", "FAIL", "Host ports below 1024 mapped into containers")
    else:
        logger.info("V-235819, PASS, No host ports mapped below 1024")
        log_json("V-235819", "PASS", "No host ports mapped below 1024")
    if args.verbose:
        print("Command: docker ps --quiet --all | xargs --no-run-if-empty docker inspect --format '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}'")
        print(f"Output: {result.stdout}")

    # Manual port checks
    logger.info("V-235837, MANUAL, Review exposed ports in SSP (HostPort field)")
    log_json("V-235837", "MANUAL", "Review exposed ports in SSP (HostPort field)")
    result = subprocess.run("docker ps -q | xargs --no-run-if-empty docker inspect --format '{{ .Id }}: {{ .Name }}: Ports={{ .NetworkSettings.Ports }}' | grep HostPort", shell=True, capture_output=True, text=True)
    print(result.stdout)

    logger.info("V-235804, MANUAL, Review exposed ports in SSP (Host field)")
    log_json("V-235804", "MANUAL", "Review exposed ports in SSP (Host field)")
    result = subprocess.run("docker ps --quiet | xargs --no-run-if-empty docker inspect --format '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}' | grep -i host", shell=True, capture_output=True, text=True)
    print(result.stdout)

    logger.info("Docker STIG configuration complete. Restart Docker service to apply changes.")
    log_json("INFO", "INFO", "Docker STIG configuration complete")
    if args.json:
        logger.info(f"JSON output written to {JSON_LOG_FILE}")
        log_json("INFO", "INFO", f"JSON output written to {JSON_LOG_FILE}")

if __name__ == "__main__":
    main()