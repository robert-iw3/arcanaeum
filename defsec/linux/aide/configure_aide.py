#!/usr/bin/env python3
"""
Enhanced AIDE Configuration Script - Balanced Ruleset + SIEM Integration

This script configures AIDE with a comprehensive yet performant ruleset,
hardens cron/at, and sets up SIEM-friendly reporting. It also includes a
simple Python shipper for HTTP/SIEM integration.

Designed for modern Linux systems, it ensures critical files are monitored
while excluding volatile paths for better performance. The script creates a
systemd timer for daily checks and logs both human-readable and JSON outputs
for audit and SIEM purposes.

@RW
"""

import argparse
import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path

# ================== CONFIG ==================
LOG_FILE = "/var/log/aide_config.log"
JSON_LOG_FILE = "/var/log/aide_config.json"
BACKUP_DIR = "/var/backups/aide"
AIDE_CONF = "/etc/aide/aide.conf"
AIDE_CONF_DIR = "/etc/aide/aide.conf.d"
AIDE_LOG_DIR = "/var/log/aide"
RSYSLOG_CONF = "/etc/rsyslog.d/50-default.conf"
SHIPPER_PATH = "/usr/local/bin/aide-ship-to-siem.py"

AIDE_RULES = """# Enhanced AIDE Ruleset - Balanced Coverage + Performance
FIPSR   = p+i+n+u+g+s+m+c+acl+xattrs+selinux+sha512
NORMAL  = p+i+n+u+g+s+m+c+acl+xattrs+selinux+sha512
LOG     = p+i+n+u+g+s+m+c+acl+xattrs+selinux
PERMS   = p+u+g+acl+xattrs+selinux

# Volatile exclusions (performance)
!/proc
!/sys
!/dev
!/run
!/tmp
!/var/tmp
!/var/run
!/var/lock
!/var/cache
!/var/spool
!/var/log/journal
!/var/lib/docker
!/var/lib/lxcfs
!/var/lib/kubelet
!/var/lib/containerd
!/home/*/.cache

# Critical areas
/bin          FIPSR
/sbin         FIPSR
/usr/bin      FIPSR
/usr/sbin     FIPSR
/usr/local/bin FIPSR
/lib          FIPSR
/lib64        FIPSR
/usr/lib      FIPSR
/usr/lib64    FIPSR
/boot         FIPSR
/etc          NORMAL
/root         PERMS

# Lighter rules
/var/log      LOG
/home         PERMS

# Self-protection
/etc/aide     FIPSR
/var/lib/aide FIPSR

# SIEM-ready reporting
report_format = json
report_url = file:/var/log/aide/aide_report.json
report_url = syslog:authpriv
"""

SYSTEMD_SERVICE = "/etc/systemd/system/aidecheck.service"
SYSTEMD_TIMER = "/etc/systemd/system/aidecheck.timer"

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(message)s",
                    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
                    datefmt="%Y-%m-%dT%H:%M:%SZ")
logger = logging.getLogger(__name__)

def log_json(status: str, message: str):
    try:
        with open(JSON_LOG_FILE, "a") as f:
            json.dump({"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "status": status, "message": message}, f)
            f.write("\n")
    except Exception:
        pass

def setup_dirs():
    for d in (Path(BACKUP_DIR), Path(AIDE_LOG_DIR), Path(AIDE_CONF_DIR)):
        d.mkdir(parents=True, exist_ok=True)
        os.chown(d, 0, 0)
        os.chmod(d, 0o750)

def check_privileges():
    try:
        if "cap_sys_admin" not in subprocess.run(["capsh", "--print"], capture_output=True, text=True).stdout.lower():
            if os.geteuid() != 0:
                logger.error("Requires root or CAP_SYS_ADMIN")
                exit(1)
    except:
        if os.geteuid() != 0:
            logger.error("Requires root")
            exit(1)

def check_deps():
    for cmd in ["aide", "aideinit", "systemctl"]:
        if not shutil.which(cmd):
            logger.error(f"Missing: {cmd}")
            exit(1)

def backup_file(p: str):
    path = Path(p)
    if path.exists():
        bk = Path(BACKUP_DIR) / f"{path.name}.{int(time.time())}"
        shutil.copy2(path, bk)
        logger.info(f"Backed up {p}")

def install_shipper():
    logger.info("Installing SIEM shipper")
    code = '''#!/usr/bin/env python3
import json, sys, os, socket
from datetime import datetime
import urllib.request
def ship(r="/var/log/aide/aide_report.json"):
    h = socket.gethostname()
    ts = datetime.utcnow().isoformat() + "Z"
    jpath = "/var/log/aide/aide_events.jsonl"
    try:
        with open(r) as f: rep = json.load(f)
        ev = [{"@timestamp": ts, "host.name": h, "event.module": "aide", "aide": rep}]
    except:
        with open(r, errors="ignore") as f: ev = [{"@timestamp": ts, "host.name": h, "event.module": "aide", "message": f.read(20000)}]
    with open(jpath, "a") as f:
        for e in ev: f.write(json.dumps(e)+"\\n")
    if os.getenv("AIDE_SIEM_HTTP_URL"):
        try:
            req = urllib.request.Request(os.getenv("AIDE_SIEM_HTTP_URL"), data=json.dumps(ev[0]).encode(), headers={"Content-Type":"application/json", "Authorization":f"Bearer {os.getenv('AIDE_SIEM_TOKEN','')}"})
            urllib.request.urlopen(req, timeout=8)
        except Exception as e: print(f"HTTP ship failed: {e}", file=sys.stderr)
if __name__ == "__main__": ship(sys.argv[1] if len(sys.argv)>1 else None)
'''
    Path(SHIPPER_PATH).write_text(code)
    os.chmod(SHIPPER_PATH, 0o755)
    os.chown(SHIPPER_PATH, 0, 0)

def configure_cron():
    logger.info("[1/6] Hardening cron/at")
    for f in ("/etc/cron.deny", "/etc/at.deny"): Path(f).unlink(missing_ok=True)
    for f in ("/etc/cron.allow", "/etc/at.allow"):
        Path(f).write_text("root\n")
        os.chmod(f, 0o600)
    subprocess.run(["systemctl", "mask", "--now", "atd.service"], capture_output=True)
    if Path(RSYSLOG_CONF).exists():
        backup_file(RSYSLOG_CONF)
        subprocess.run(["sed", "-i", "s/^#cron\\./cron\\./", RSYSLOG_CONF], capture_output=True)

def configure_rules():
    logger.info("[2/6] Installing comprehensive rules")
    Path(AIDE_CONF_DIR).mkdir(parents=True, exist_ok=True)
    (Path(AIDE_CONF_DIR) / "10_aide_enhanced.conf").write_text(AIDE_RULES)
    conf = Path(AIDE_CONF)
    if conf.exists():
        backup_file(AIDE_CONF)
        if "@@include" not in conf.read_text():
            with open(conf, "a") as f: f.write("\n@@include /etc/aide/aide.conf.d/*.conf\n")

def init_db():
    logger.info("[3/6] Initializing database (may take minutes)")
    Path("/var/lib/aide").mkdir(parents=True, exist_ok=True)
    subprocess.run(["aideinit", "--yes"], check=True, capture_output=True, timeout=900)

def activate_db():
    logger.info("[4/6] Activating database")
    for new in Path("/var/lib/aide").glob("aide.db.new*"):
        target = str(new).replace(".new", "")
        if Path(target).exists(): backup_file(target)
        shutil.move(str(new), target)
        os.chmod(target, 0o600)

def setup_timer():
    logger.info("[5/6] Setting up daily timer")
    service = f"""[Unit]
Description=AIDE daily check
After=network.target
[Service]
Type=oneshot
ExecStart=/usr/bin/aide --check
ExecStartPost={SHIPPER_PATH}
Nice=19
IOSchedulingClass=idle
StandardOutput=append:/var/log/aide/aide.log
StandardError=append:/var/log/aide/aide.log"""
    timer = """[Unit]
Description=Daily AIDE check timer
[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=30min
[Install]
WantedBy=timers.target"""
    for p, c in [(SYSTEMD_SERVICE, service), (SYSTEMD_TIMER, timer)]:
        Path(p).write_text(c)
        os.chmod(p, 0o644)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", "aidecheck.timer"], check=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--json", "-j", action="store_true")
    args = parser.parse_args()

    setup_dirs()
    if args.json:
        Path(JSON_LOG_FILE).touch()
        os.chmod(JSON_LOG_FILE, 0o640)

    logger.info("=== Starting Enhanced AIDE Configuration ===")
    log_json("INFO", "Started")

    check_deps()
    check_privileges()
    configure_cron()
    configure_rules()
    init_db()
    activate_db()
    install_shipper()
    setup_timer()

    logger.info("=== AIDE Configuration Complete ===")
    logger.info(f"SIEM events: {AIDE_LOG_DIR}/aide_events.jsonl")
    logger.info(f"Timer: {SYSTEMD_TIMER}")
    log_json("SUCCESS", "Complete")

if __name__ == "__main__":
    main()