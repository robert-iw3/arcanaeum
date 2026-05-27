import json
import os
import re
from datetime import datetime
import logging
import signal
import sys
import traceback
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
import xml.etree.ElementTree as ET
import csv
from pathlib import Path
import platform
import time
import queue
import chardet
from ratelimit import limits, sleep_and_retry
import certifi
try:
    from elasticsearch import Elasticsearch
    from elasticsearch.helpers import bulk
    from elasticsearch.connection import RequestsHttpConnection
    ELASTICSEARCH_AVAILABLE = True
except ImportError:
    ELASTICSEARCH_AVAILABLE = False
try:
    from requests_aws4auth import AWS4Auth
    AWS_AUTH_AVAILABLE = True
except ImportError:
    AWS_AUTH_AVAILABLE = False

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/app/logs/pipeline.log')
    ]
)
logger = logging.getLogger(__name__)

# Default Trellix/McAfee log paths
DEFAULT_LOG_PATHS = {
    "Windows": [
        os.path.expandvars(r"%ProgramData%\McAfee\Agent\Logs"),
        os.path.expandvars(r"%ProgramData%\McAfee\Endpoint Security\Logs"),
        os.path.expandvars(r"%ProgramData%\McAfee\Solidcore\Logs"),
        os.path.expandvars(r"%ProgramData%\Trellix\Agent\Logs"),
        os.path.expandvars(r"%ProgramData%\Trellix\Endpoint Security\Logs"),
        os.path.expandvars(r"%ProgramData%\Trellix\Solidcore\Logs"),
        os.path.expandvars(r"%TEMP%\McAfeeLogs"),
        os.path.expandvars(r"%TEMP%\TrellixLogs"),
        r"C:\Windows\Temp\McAfeeLogs",
        r"C:\Windows\Temp\TrellixLogs",
        r"C:\Windows\solidcore_setup.log",
        r"C:\Windows\Solidcore_Installer.log",
        r"C:\Windows\trellix_setup.log"
    ],
    "Linux": [
        "/var/McAfee/agent/logs",
        "/var/log/mcafee/solidcore",
        "/var/Trellix/agent/logs",
        "/var/log/trellix/solidcore",
        "/tmp/solidcoreS3_install.log",
        "/tmp/trellix_install.log"
    ],
    "Darwin": [
        "/var/McAfee/agent/logs",
        "/var/log/mcafee/solidcore",
        "/var/Trellix/agent/logs",
        "/var/log/trellix/solidcore"
    ]
}

# Discover Trellix/McAfee log paths
def discover_log_paths():
    platform_system = platform.system()
    discovered_paths = set(DEFAULT_LOG_PATHS.get(platform_system, []))
    search_roots = []

    if platform_system == "Windows":
        search_roots = [
            os.path.expandvars(r"%ProgramData%"),
            os.path.expandvars(r"%TEMP%"),
            r"C:\Windows\Temp"
        ]
    elif platform_system in ["Linux", "Darwin"]:
        search_roots = ["/var", "/var/log", "/tmp"]

    for root in search_roots:
        try:
            root_path = Path(root)
            if not root_path.exists() or not root_path.is_dir():
                continue
            for path in root_path.rglob("*"):
                if path.is_dir() and any(keyword in path.name.lower() for keyword in ["mcafee", "trellix"]):
                    if any(path.glob("*.log")) or any(path.glob("*.log.*")):
                        discovered_paths.add(str(path))
                elif path.is_file() and any(keyword in path.name.lower() for keyword in ["mcafee", "trellix"]) and path.suffix == ".log":
                    discovered_paths.add(str(path))
        except (PermissionError, OSError) as e:
            logger.warning(f"Unable to access {root}: {e}")
            continue

    valid_paths = []
    for path in discovered_paths:
        try:
            path_obj = Path(path)
            if path_obj.exists() and (path_obj.is_dir() or (path_obj.is_file() and path_obj.suffix == ".log")):
                if os.access(path, os.R_OK):
                    valid_paths.append(path)
                else:
                    logger.warning(f"No read permission for {path}")
        except Exception as e:
            logger.warning(f"Invalid path {path}: {e}")

    logger.info(f"Discovered {len(valid_paths)} log paths: {valid_paths}")
    return valid_paths

# Detect file encoding
def detect_encoding(file_path):
    try:
        with open(file_path, 'rb') as f:
            raw = f.read(10000)
            result = chardet.detect(raw)
            return result['encoding'] or 'utf-8'
    except Exception as e:
        logger.error(f"Error detecting encoding for {file_path}: {e}\n{traceback.format_exc()}")
        return 'utf-8'

# Validate Trellix log line
def validate_log_line(log_line, log_type):
    if not log_line.strip():
        return False
    if log_type == "text":
        patterns = [
            r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}Z\s+\|',  # Modern format
            r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+[IEW]',   # Legacy format
            r'^\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2} [AP]M' # Simple format
        ]
        return any(re.match(pattern, log_line) for pattern in patterns)
    elif log_type == "csv":
        return ',' in log_line
    elif log_type == "xml":
        try:
            ET.fromstring(log_line)
            return True
        except ET.ParseError:
            return False
    return False

# Parse Trellix text-based log line
def parse_text_log_line(log_line):
    try:
        # Modern pipe-separated format
        modern_pattern = r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}Z)\s+\|(?P<type>\S+)\|(?P<component>\S+)\s*\|(?P<process>\S+)\s*\|\s*(?P<pid>\d+)\s*\|(?P<tid>\d+)\s*\|(?P<category>\S+)\s*\|(?P<source>\S+)\s*\| (?P<message>.+)'
        match = re.match(modern_pattern, log_line)
        if match:
            return match.groupdict()

        # Legacy format
        legacy_pattern = r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<severity>[IEW])(?:\s+#(?P<thread>\d+))?\s+(?P<module>\S+)\s+(?P<message>.+)'
        match = re.match(legacy_pattern, log_line)
        if match:
            return match.groupdict()

        # Simple OnAccessScanLog format (updated for users with spaces, like NT AUTHORITY\SYSTEM)
        simple_pattern = r'(?P<date>\d{1,2}/\d{1,2}/\d{4})\s+(?P<time>\d{1,2}:\d{2}:\d{2} [AP]M)\s+(?P<action>.*?)\s+(?P<user>[^ ]+(?:\\[^ ]+)?)\s+(?P<path>.*?)\s+(?P<description>.*?)\s+(?P<detection>.+)'
        match = re.match(simple_pattern, log_line.strip())
        if match:
            gd = match.groupdict()
            # Assume year 20xx if not full
            year = gd['date'].split('/')[-1]
            if len(year) == 2:
                year = '20' + year
            month = gd['date'].split('/')[0].zfill(2)
            day = gd['date'].split('/')[1].zfill(2)
            gd['timestamp'] = f"{year}-{month}-{day} {gd['time']}"
            return gd

        return {}
    except Exception as e:
        logger.error(f"Error parsing text log line: {log_line}\n{e}\n{traceback.format_exc()}")
        return {}

# Parse Trellix log formats
def parse_log_line(log_line, log_type):
    parsed = {}
    try:
        if log_type == "text":
            parsed = parse_text_log_line(log_line)
        elif log_type == "csv":
            try:
                # Updated for unnamed fields: use csv.reader and assign default keys if needed
                reader = csv.reader([log_line])
                fields = next(reader, [])
                if fields:
                    # Assume first line is data, create dict with generic keys
                    parsed = {f"field_{i}": val for i, val in enumerate(fields)}
            except csv.Error as ce:
                logger.warning(f"Invalid CSV log line: {log_line}\n{ce}\n{traceback.format_exc()}")
        elif log_type == "xml":
            try:
                root = ET.fromstring(log_line)
                for elem in root.iter():
                    parsed[elem.tag] = elem.text
            except ET.ParseError as pe:
                logger.warning(f"Invalid XML log line: {log_line}\n{pe}\n{traceback.format_exc()}")
    except Exception as e:
        logger.error(f"Error parsing log line: {log_line}\n{e}\n{traceback.format_exc()}")
    return parsed

# Enhanced Transform to ECS schema (Elastic Common Schema)
def to_ecs(parsed_log, log_file):
    try:
        message = parsed_log.get("message", "")
        ecs_log = {
            "@timestamp": parsed_log.get("timestamp", datetime.utcnow().isoformat()),
            "ecs.version": "9.2.0",
            "event": {
                "original": message,
                "kind": "event",
                "category": ["system"],
                "type": ["info"],
                "module": "trellix_ens",
                "dataset": log_file.lower().replace('.log', ''),
                "action": parsed_log.get("action", "unknown")
            },
            "host": {
                "hostname": platform.node(),
                "os": {
                    "platform": platform.system(),
                    "version": platform.version()
                }
            },
            "log": {
                "level": parsed_log.get("type", parsed_log.get("severity", "info")).lower(),
                "logger": parsed_log.get("source", "")
            },
            "process": {
                "pid": parsed_log.get("pid"),
                "thread": {
                    "id": parsed_log.get("tid")
                },
                "name": parsed_log.get("process")
            },
            "trellix": parsed_log
        }

        # Enhanced message parsing for security events (updated keywords for action)
        lower_message = message.lower()
        if "trojan" in lower_message or "malware" in lower_message or "detected" in lower_message:
            ecs_log["event"]["category"] = ["malware"]
            ecs_log["event"]["type"] = ["detection"]
            ecs_log["event"]["kind"] = "alert"

            # Extract detection name
            detection_match = re.search(r'(?:Trojan named|Detection Name\s*:)\s*(\S+)', message, re.IGNORECASE)
            if detection_match:
                ecs_log["threat"] = {
                    "software": {
                        "type": "trojan" if "trojan" in lower_message else "malware",
                        "name": detection_match.group(1)
                    }
                }

            # Extract action (expanded keywords)
            action_keywords = {
                "deleted": ["deleted", "removed", "cleaned"],
                "blocked": ["blocked", "denied", "prevented"],
                "detected": ["detected", "found", "identified"]
            }
            for action, keys in action_keywords.items():
                if any(k in lower_message for k in keys):
                    ecs_log["event"]["action"] = action
                    break

        # Extract user
        user_match = re.search(r'(\S+\\?\S+)\s+ran', message)
        if user_match:
            ecs_log["user"] = {"name": user_match.group(1)}

        # Extract file path
        file_match = re.search(r'access\s+(\S+)', message)
        if file_match:
            ecs_log["file"] = {"path": file_match.group(1)}

        # Extract process if in message
        process_match = re.search(r'ran\s+(\S+)', message)
        if process_match and "process" not in ecs_log:
            ecs_log["process"]["name"] = process_match.group(1)

        return ecs_log
    except Exception as e:
        logger.error(f"Error transforming to ECS: {parsed_log}\n{e}\n{traceback.format_exc()}")
        return {"error": "Transformation failed", "original": parsed_log}

# Enhanced Transform to Splunk CIM (Common Information Model - Malware model)
def to_cim(parsed_log, log_file):
    try:
        message = parsed_log.get("message", "")
        cim_log = {
            "timestamp": parsed_log.get("timestamp", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
            "host": platform.node(),
            "source": f"trellix:{log_file}",
            "sourcetype": "trellix:ens:log",
            "vendor_product": "Trellix Endpoint Security",
            "action": "allowed",  # Default
            "dest": platform.node()
        }

        lower_message = message.lower()
        if "blocked" in lower_message:
            cim_log["action"] = "blocked"
        elif "deleted" in lower_message:
            cim_log["action"] = "deleted"
        elif "detected" in lower_message:
            cim_log["action"] = "detected"

        # Malware model fields
        if "trojan" in lower_message or "malware" in lower_message:
            detection_match = re.search(r'(?:Trojan named|Detection Name\s*:)\s*(\S+)', message, re.IGNORECASE)
            if detection_match:
                cim_log["signature"] = detection_match.group(1)

            file_match = re.search(r'access\s+(\S+)', message)
            if file_match:
                cim_log["file_path"] = file_match.group(1)
                cim_log["file_name"] = os.path.basename(file_match.group(1))

            user_match = re.search(r'(\S+\\?\S+)\s+ran', message)
            if user_match:
                cim_log["user"] = user_match.group(1)

        cim_log["event"] = parsed_log  # Keep original parsed data

        return cim_log
    except Exception as e:
        logger.error(f"Error transforming to CIM: {parsed_log}\n{e}\n{traceback.format_exc()}")
        return {"error": "Transformation failed", "original": parsed_log}

# Transform to Standard JSON
def to_standard(parsed_log, log_file, field_mappings):
    try:
        standard_log = {
            "timestamp": parsed_log.get("timestamp", datetime.utcnow().isoformat()),
            "source": f"trellix:{log_file.split('_')[0].lower()}",
            "host": platform.node(),
            "event_type": parsed_log.get("module", log_file.split('_')[0].lower()),
            "severity": parsed_log.get("severity", "INFO"),
            "details": parsed_log.get("message", "")
        }
        for src_field, dest_field in field_mappings.items():
            if src_field in parsed_log:
                standard_log[dest_field] = parsed_log[src_field]
        return standard_log
    except Exception as e:
        logger.error(f"Error transforming to standard JSON: {parsed_log}\n{e}\n{traceback.format_exc()}")
        return {"error": "Transformation failed", "original": parsed_log}

# Ship logs to SIEM with retry and rate limiting
@sleep_and_retry
@limits(calls=10, period=60)
def ship_to_siem(log_batch, siem_config):
    try:
        siem_type = siem_config.get("type")
        endpoint = siem_config.get("endpoint")
        token = siem_config.get("token")
        ca_cert = siem_config.get("ca_cert")
        ssl_verify = siem_config.get("ssl_verify", True)

        if not ssl_verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        session = requests.Session()
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))

        headers = {}
        if token:
            if siem_type == "splunk":
                headers["Authorization"] = f"Splunk {token}"
            else:
                headers["Authorization"] = f"Bearer {token}"

        verify = ca_cert if ca_cert else certifi.where()

        if siem_type == "splunk":
            wrappers = []
            for log in log_batch:
                wrapper = {
                    "event": log,
                    "time": datetime.fromisoformat(log.get("timestamp", datetime.utcnow().isoformat())).timestamp(),
                    "host": log.get("host"),
                    "source": log.get("source")
                }
                if "index" in siem_config:
                    wrapper["index"] = siem_config["index"]
                if "sourcetype" in siem_config:
                    wrapper["sourcetype"] = siem_config["sourcetype"]
                wrappers.append(wrapper)
            data = ''.join(json.dumps(w) + '\n' for w in wrappers)
            response = session.post(
                f"{endpoint}/services/collector/event",
                data=data,
                headers={**headers, "Content-Type": "application/json"},
                verify=verify,
                timeout=10
            )
            response.raise_for_status()
        elif siem_type in ["elastic", "opensearch"]:
            if not ELASTICSEARCH_AVAILABLE:
                raise ImportError("Elasticsearch library not installed. Install with `pip install elasticsearch`.")
            http_auth = None
            api_key = None
            basic_auth = None
            connection_class = None
            if "aws_region" in siem_config:
                if not AWS_AUTH_AVAILABLE:
                    raise ImportError("requests_aws4auth not installed. Install with `pip install requests-aws4auth`.")
                access_key = os.environ.get('AWS_ACCESS_KEY_ID')
                secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
                session_token = os.environ.get('AWS_SESSION_TOKEN')
                if not access_key or not secret_key:
                    raise ValueError("AWS credentials not found in environment variables")
                http_auth = AWS4Auth(access_key, secret_key, siem_config['aws_region'], 'es', session_token=session_token)
                connection_class = RequestsHttpConnection
            elif "username" in siem_config and "password" in siem_config and siem_config["username"] and siem_config["password"]:
                basic_auth = (siem_config["username"], siem_config["password"])
            elif token:
                api_key = token
            es_client = Elasticsearch(
                [endpoint],
                http_auth=http_auth,
                api_key=api_key,
                basic_auth=basic_auth,
                verify_certs=ssl_verify,
                ca_certs=verify,
                connection_class=connection_class,
                request_timeout=10
            )
            actions = [
                {
                    "_index": siem_config.get("index", "trellix_logs"),
                    "_source": log
                }
                for log in log_batch
            ]
            bulk(es_client, actions)
        else:  # standard
            response = session.post(
                endpoint,
                json=log_batch,
                headers=headers,
                verify=verify,
                timeout=10
            )
            response.raise_for_status()
        logger.info(f"Shipped {len(log_batch)} logs to {siem_type} at {endpoint}")
    except Exception as e:
        logger.error(f"Failed to ship logs to {siem_type} at {endpoint}: {e}\n{traceback.format_exc()}")

# Watchdog handler for log file changes
class LogFileHandler(FileSystemEventHandler):
    def __init__(self, config):
        self.config = config
        self.siems = config.get("siems", [])
        self.log_format = config.get("log_format", "text")
        self.global_batch_size = config.get("batch_size", 100)
        self.field_mappings = config.get("field_mappings", {})
        self.log_queue = queue.Queue(maxsize=1000)
        self.batches = {i: [] for i in range(len(self.siems))}
        self.processed_logs = 0
        self.error_count = 0

    def on_modified(self, event):
        if not event.is_directory and (event.src_path.endswith(".log") or re.match(r".*\.log\.\d+$", event.src_path)):
            self.process_log_file(event.src_path)

    def process_log_file(self, file_path):
        try:
            encoding = detect_encoding(file_path)
            with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                log_file = os.path.basename(file_path)
                for line_num, line in enumerate(f, start=1):
                    try:
                        if not validate_log_line(line.strip(), self.log_format):
                            self.error_count += 1
                            logger.warning(f"Invalid log line at {file_path}:{line_num}: {line.strip()}")
                            continue

                        parsed_log = parse_log_line(line.strip(), self.log_format)
                        if not parsed_log:
                            self.error_count += 1
                            continue

                        self.processed_logs += 1

                        for i, siem in enumerate(self.siems):
                            siem_type = siem.get("type")
                            if siem_type == "splunk":
                                transformed_log = to_cim(parsed_log, log_file)
                            elif siem_type in ["elastic", "opensearch"]:
                                transformed_log = to_ecs(parsed_log, log_file)
                            else:
                                transformed_log = to_standard(parsed_log, log_file, self.field_mappings)
                            if "error" in transformed_log:
                                self.error_count += 1
                                continue
                            self.batches[i].append(transformed_log)
                            batch_size = siem.get("batch_size", self.global_batch_size)
                            if len(self.batches[i]) >= batch_size:
                                try:
                                    self.log_queue.put((i, self.batches[i]), timeout=5)
                                    self.batches[i] = []
                                except queue.Full:
                                    logger.warning("Log queue full, waiting...")
                                    time.sleep(1)
                    except Exception as e:
                        logger.error(f"Error processing line {line_num} in {file_path}: {e}\n{traceback.format_exc()}")

                logger.info(f"Processed {self.processed_logs} logs, {self.error_count} errors from {file_path}")
        except Exception as e:
            self.error_count += 1
            logger.error(f"Error processing file {file_path}: {e}\n{traceback.format_exc()}")

def validate_config(config):
    try:
        if "siems" not in config or not isinstance(config["siems"], list) or not config["siems"]:
            raise ValueError("Config must include at least one SIEM in 'siems' list")
        for siem in config["siems"]:
            if "type" not in siem or "endpoint" not in siem:
                raise ValueError("Each SIEM must have 'type' and 'endpoint'")
            siem_type = siem["type"]
            if siem_type not in ["splunk", "elastic", "opensearch", "standard"]:
                raise ValueError(f"Invalid SIEM type: {siem_type}")
            if siem_type in ["elastic", "opensearch"] and "index" not in siem:
                raise ValueError(f"Index required for {siem_type}")
            if "ca_cert" in siem and siem["ca_cert"] and not os.path.isfile(siem["ca_cert"]):
                logger.warning(f"SIEM CA certificate file {siem['ca_cert']} does not exist. Set to null if using a trusted CA.")
            siem.setdefault("ssl_verify", True)
            siem.setdefault("index", "trellix_logs")
        if not config.get("log_paths"):
            config["log_paths"] = discover_log_paths()
        if not config.get("field_mappings"):
            config["field_mappings"] = {}
        if "log_format" not in config:
            raise ValueError("Missing required config field: log_format")
        if "batch_size" not in config:
            raise ValueError("Missing required config field: batch_size")
    except Exception as e:
        logger.error(f"Config validation failed: {e}\n{traceback.format_exc()}")
        raise

def load_config(config_path='/app/config.json'):
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        return config
    except Exception as e:
        logger.error(f"Failed to load config: {e}\n{traceback.format_exc()}")
        raise

def shutdown_handler(signum, frame):
    logger.info("Received shutdown signal, processing remaining logs...")
    observer.stop()
    handler = globals().get('handler')
    if handler:
        for i in range(len(handler.siems)):
            if handler.batches[i]:
                ship_to_siem(handler.batches[i], handler.siems[i])
    while not handler.log_queue.empty():
        try:
            siem_i, batch = handler.log_queue.get(timeout=5)
            ship_to_siem(batch, handler.siems[siem_i])
        except queue.Empty:
            pass
        except Exception as e:
            logger.error(f"Error during shutdown queue processing: {e}\n{traceback.format_exc()}")
    logger.info("Shutdown complete")
    sys.exit(0)

def main():
    global observer, handler
    try:
        config = load_config()
        validate_config(config)

        Path('/app/logs').mkdir(parents=True, exist_ok=True)

        log_paths = config["log_paths"]
        for log_path in log_paths:
            try:
                Path(log_path).mkdir(parents=True, exist_ok=True)
            except Exception as e:
                logger.warning(f"Failed to create log directory {log_path}: {e}\n{traceback.format_exc()}")

        observer = Observer()
        handler = LogFileHandler(config)

        def process_queue():
            while True:
                try:
                    siem_i, batch = handler.log_queue.get(timeout=5)
                    ship_to_siem(batch, handler.siems[siem_i])
                except queue.Empty:
                    logger.debug("Log queue empty, continuing to poll for new logs")
                except Exception as e:
                    logger.error(f"Error in queue processing thread: {e}\n{traceback.format_exc()}")
                time.sleep(1)

        import threading
        queue_thread = threading.Thread(target=process_queue, daemon=True)
        queue_thread.start()

        for log_path in log_paths:
            try:
                if os.path.exists(log_path):
                    observer.schedule(handler, log_path, recursive=True)
                    logger.info(f"Monitoring log directory: {log_path}")
                else:
                    logger.warning(f"Log path does not exist: {log_path}")
            except Exception as e:
                logger.warning(f"Failed to monitor log path {log_path}: {e}\n{traceback.format_exc()}")

        observer.start()
        signal.signal(signal.SIGTERM, shutdown_handler)
        signal.signal(signal.SIGINT, shutdown_handler)

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            shutdown_handler(signal.SIGINT, None)
    except Exception as e:
        logger.error(f"Fatal error: {e}\n{traceback.format_exc()}")
        raise
if __name__ == "__main__":
    main()