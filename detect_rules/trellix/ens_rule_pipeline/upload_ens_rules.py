import json
import os
import logging
import requests
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
from requests.exceptions import HTTPError, ConnectionError, Timeout, RequestException
from urllib3.util.retry import Retry
from pathlib import Path
import re
import signal
import sys
import time
import certifi
import yaml
import traceback

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/app/logs/rules_upload.log')
    ]
)
logger = logging.getLogger(__name__)

# Load configuration
def load_config(config_path='/app/config.json'):
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        validate_config(config)
        return config
    except FileNotFoundError:
        logger.error(f"Config file not found: {config_path}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in config file {config_path}: {e}")
        raise
    except Exception as e:
        logger.error(f"Failed to load config from {config_path}: {e}\n{traceback.format_exc()}")
        raise

# Validate configuration
def validate_config(config):
    required_fields = {
        "epo_server": str,
        "epo_username": str,
        "epo_password": str,
        "rules_dir": str,
        "markdown_rules_dir": str,
        "batch_size": int
    }
    for key, value_type in required_fields.items():
        if key not in config:
            raise ValueError(f"Missing required config field: {key}")
        if not isinstance(config[key], value_type):
            raise ValueError(f"Invalid type for {key}: expected {value_type}")
    if not re.match(r'^[a-zA-Z0-9.-]+$', config["epo_server"]):
        raise ValueError("Invalid ePO server hostname")
    config.setdefault("dry_run", True)
    config.setdefault("group_id", None)
    config.setdefault("ca_cert", None)
    if config["ca_cert"] and not os.path.isfile(config["ca_cert"]):
        logger.warning(f"CA certificate file {config['ca_cert']} does not exist. Set 'ca_cert: null' if using a trusted CA.")
    return config

# Discover markdown rule files
def discover_markdown_rules(markdown_dir):
    discovered_paths = set()
    try:
        markdown_path = Path(markdown_dir)
        if not markdown_path.exists() or not markdown_path.is_dir():
            logger.warning(f"Markdown rules directory {markdown_dir} does not exist")
            return discovered_paths
        for path in markdown_path.rglob("*.md"):
            if path.is_file() and os.access(path, os.R_OK):
                discovered_paths.add(str(path))
            else:
                logger.warning(f"No read permission for {path}")
    except Exception as e:
        logger.error(f"Error discovering markdown files in {markdown_dir}: {e}\n{traceback.format_exc()}")
    logger.info(f"Discovered {len(discovered_paths)} markdown files: {discovered_paths}")
    return discovered_paths

# Parse markdown file for rules
def parse_markdown_file(file_path):
    rules = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        # Extract metadata
        description_match = re.search(r'## Description\n(.*?)(?=\n##|\n$)', content, re.DOTALL)
        description = description_match.group(1).strip() if description_match else "No description"
        rule_class_match = re.search(r'## Rule Class\n(.*?)(?=\n##|\n$)', content, re.DOTALL)
        rule_class = rule_class_match.group(1).strip() if rule_class_match else "Process"
        notes_match = re.search(r'## Notes\n(.*?)(?=\n##|\n$)', content, re.DOTALL)
        notes = notes_match.group(1).strip() if notes_match else ""
        platforms_match = re.search(r'## Tested Platforms\n(.*?)(?=\n##|\n$)', content, re.DOTALL)
        tested_platforms = platforms_match.group(1).strip() if platforms_match else ""
        # Extract code blocks
        code_block_pattern = r'```(tcl|text|json|yaml)\n(.*?)\n```'
        matches = re.findall(code_block_pattern, content, re.DOTALL)
        for i, (lang, block) in enumerate(matches):
            try:
                if lang in ["json", "yaml"]:
                    rule_data = json.loads(block) if lang == "json" else yaml.safe_load(block)
                    if not isinstance(rule_data, list):
                        rule_data = [rule_data]
                    for rule in rule_data:
                        rule.setdefault("description", description)
                        rule.setdefault("rule_class", rule_class)
                        rule.setdefault("notes", notes)
                        rule.setdefault("tested_platforms", tested_platforms)
                    rules.extend(rule_data)
                elif lang in ["tcl", "text"]:
                    rule_type = "expert"
                    if rule_class.lower() in ["file"]:
                        rule_type = "access_protection"
                    elif rule_class.lower() in ["network"]:
                        rule_type = "firewall"
                    rule_data = {
                        "type": rule_type,
                        "name": f"{Path(file_path).stem}_{i}",
                        "content": block.strip() if rule_type == "expert" else None,
                        "action": "Block and Report",
                        "severity": "High",
                        "enabled": True,
                        "description": description,
                        "rule_class": rule_class,
                        "notes": notes,
                        "tested_platforms": tested_platforms
                    }
                    if rule_type == "access_protection":
                        # Simplified mapping for File-based rules
                        rule_data["executables"] = "**"
                        rule_data["target"] = {"type": "FILE", "value": "**"}
                        rule_data["subrule"] = {"include": {"object_name": "**"}}
                        rule_data["operations"] = ["CREATE", "WRITE"]
                    rules.append(rule_data)
            except json.JSONDecodeError as e:
                logger.error(f"JSON parsing error in code block {i} of {file_path}: {e}\n{traceback.format_exc()}")
                continue
            except yaml.YAMLError as e:
                logger.error(f"YAML parsing error in code block {i} of {file_path}: {e}\n{traceback.format_exc()}")
                continue
            except Exception as e:
                logger.error(f"Failed to parse {lang} code block {i} in {file_path}: {e}\n{traceback.format_exc()}")
                continue
    except FileNotFoundError:
        logger.error(f"Markdown file not found: {file_path}")
    except UnicodeDecodeError as e:
        logger.error(f"Encoding error reading {file_path}: {e}\n{traceback.format_exc()}")
    except Exception as e:
        logger.error(f"Failed to read markdown file {file_path}: {e}\n{traceback.format_exc()}")
    return rules

# Correct common rule issues
def correct_rule(rule, rule_type):
    corrected = rule.copy()
    try:
        if rule_type == "access_protection":
            corrected["operations"] = [op.upper() for op in rule.get("operations", [])]
            if "target" in corrected and "value" in corrected["target"]:
                corrected["target"]["value"] = corrected["target"]["value"].replace("/", "\\")
            if "subrule" in corrected and "include" in corrected["subrule"] and "object_name" in corrected["subrule"]["include"]:
                corrected["subrule"]["include"]["object_name"] = corrected["subrule"]["include"]["object_name"].replace("/", "\\")
            corrected.setdefault("severity", "Medium")
            corrected.setdefault("executables", "**")
            corrected.setdefault("target", {"type": "FILE", "value": "**"})
            corrected.setdefault("subrule", {"include": {"object_name": "**"}})
        elif rule_type == "expert":
            if "content" in corrected:
                corrected["content"] = " ".join(corrected["content"].split())
            corrected.setdefault("severity", "High")
            corrected.setdefault("action", "Block and Report")
        elif rule_type == "firewall":
            if "application" in corrected:
                corrected["application"] = corrected["application"].replace("/", "\\")
            corrected["port"] = str(corrected.get("port", ""))
            corrected.setdefault("direction", "both")
            corrected.setdefault("protocol", "TCP")
        corrected.setdefault("enabled", True)
    except Exception as e:
        logger.error(f"Error correcting rule {rule.get('name', 'unknown')}: {e}\n{traceback.format_exc()}")
    return corrected

# Validate rule syntax
def validate_rule(rule, rule_type):
    try:
        if rule_type == "access_protection":
            if not all(key in rule for key in ["name", "executables", "target", "subrule", "operations", "action"]):
                return False, "Missing required fields for Access Protection rule"
            if not rule["executables"]:
                return False, "Executables cannot be empty"
            if rule["target"].get("type") != "FILE":
                return False, "Access Protection target must be FILE"
            if not all(re.match(r"^[A-Z]+$", op) for op in rule["operations"]):
                return False, "Operations must be uppercase (e.g., CREATE, WRITE)"
        elif rule_type == "expert":
            if not rule.get("content"):
                return False, "Expert rule content is required"
            if not rule.get("name"):
                return False, "Expert rule name is required"
            if not re.match(r'Rule\s*{.*(?:Process|Initiator|Target)\s*{.*}.*}', rule["content"], re.DOTALL):
                return False, "Invalid Expert Rule syntax: Must contain Process, Initiator, or Target block"
        elif rule_type == "firewall":
            if not all(key in rule for key in ["name", "application", "direction", "protocol", "port", "action"]):
                return False, "Missing required fields for Firewall rule"
            if rule["direction"] not in ["inbound", "outbound", "both"]:
                return False, "Invalid direction: must be inbound, outbound, or both"
            if rule["protocol"] not in ["TCP", "UDP"]:
                return False, "Invalid protocol: must be TCP or UDP"
            if not re.match(r'^\d+$', str(rule["port"])) or int(rule["port"]) < 1 or int(rule["port"]) > 65535:
                return False, "Invalid port: must be 1-65535"
        else:
            return False, f"Unknown rule type: {rule_type}"
        return True, "Valid"
    except Exception as e:
        logger.error(f"Error validating rule {rule.get('name', 'unknown')}: {e}\n{traceback.format_exc()}")
        return False, f"Validation error: {e}"

# Convert rule to ePO API format
def to_epo_format(rule, rule_type):
    try:
        if rule_type == "access_protection":
            return {
                "type": "AccessProtectionRule",
                "name": rule["name"],
                "enabled": rule.get("enabled", True),
                "executables": rule["executables"],
                "target": {
                    "type": rule["target"]["type"],
                    "value": rule["target"]["value"]
                },
                "subrule": rule["subrule"],
                "operations": ",".join(rule["operations"]),
                "action": rule["action"],
                "severity": rule.get("severity", "Medium"),
                "description": rule.get("description", "No description")
            }
        elif rule_type == "expert":
            return {
                "type": "ExpertRule",
                "name": rule["name"],
                "enabled": rule.get("enabled", True),
                "content": rule["content"],
                "action": rule["action"],
                "severity": rule.get("severity", "High"),
                "description": rule.get("description", "No description")
            }
        elif rule_type == "firewall":
            return {
                "type": "FirewallRule",
                "name": rule["name"],
                "enabled": rule.get("enabled", True),
                "application": rule["application"],
                "direction": rule["direction"],
                "protocol": rule["protocol"],
                "port": rule["port"],
                "action": rule["action"],
                "description": rule.get("description", "No description")
            }
        return None  # For unknown rule types
    except Exception as e:
        logger.error(f"Error converting rule {rule.get('name', 'unknown')} to ePO format: {e}\n{traceback.format_exc()}")
        return None

# Test ePO API connectivity
def test_api_connectivity(config):
    url = f"https://{config['epo_server']}:8443/remote/system.ping"
    auth = HTTPBasicAuth(config["epo_username"], config["epo_password"])
    verify = config["ca_cert"] if config["ca_cert"] else certifi.where()
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount('https://', HTTPAdapter(max_retries=retries))
    try:
        response = session.get(url, auth=auth, verify=verify, timeout=30)
        response.raise_for_status()
        logger.info("ePO API connectivity test successful")
        return True, "API reachable"
    except HTTPError as e:
        logger.error(f"ePO API connectivity test failed with HTTP error: {e.response.status_code} - {e.response.text}")
        return False, str(e)
    except (ConnectionError, Timeout) as e:
        logger.error(f"ePO API connectivity test failed with connection/timeout error: {e}")
        return False, str(e)
    except RequestException as e:
        logger.error(f"ePO API connectivity test failed with request error: {e}")
        return False, str(e)
    except Exception as e:
        logger.error(f"Unexpected error in ePO API connectivity test: {e}\n{traceback.format_exc()}")
        return False, str(e)

# Upload rule to ePO
def upload_rule(rule_data, config, dry_run=False):
    url = f"https://{config['epo_server']}:8443/remote/policy.create"
    auth = HTTPBasicAuth(config["epo_username"], config["epo_password"])
    verify = config["ca_cert"] if config["ca_cert"] else certifi.where()
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount('https://', HTTPAdapter(max_retries=retries))
    try:
        if dry_run:
            logger.info(f"Dry-run: Would upload rule {rule_data['name']} to {url}")
            return True, "Dry-run successful"
        response = session.post(url, json=rule_data, auth=auth, verify=verify, timeout=30)
        response.raise_for_status()
        logger.info(f"Uploaded rule {rule_data['name']} to ePO")
        return True, "Rule uploaded successfully"
    except HTTPError as e:
        logger.error(f"Failed to upload rule {rule_data.get('name', 'unknown')} with HTTP error: {e.response.status_code} - {e.response.text}")
        return False, str(e)
    except (ConnectionError, Timeout) as e:
        logger.error(f"Failed to upload rule {rule_data.get('name', 'unknown')} with connection/timeout error: {e}")
        return False, str(e)
    except RequestException as e:
        logger.error(f"Failed to upload rule {rule_data.get('name', 'unknown')} with request error: {e}")
        return False, str(e)
    except Exception as e:
        logger.error(f"Unexpected error uploading rule {rule_data.get('name', 'unknown')}: {e}\n{traceback.format_exc()}")
        return False, str(e)

# Assign rule to group
def assign_rule_to_group(rule_name, group_id, config, dry_run=False):
    url = f"https://{config['epo_server']}:8443/remote/policy.assignToGroup"
    auth = HTTPBasicAuth(config["epo_username"], config["epo_password"])
    verify = config["ca_cert"] if config["ca_cert"] else certifi.where()
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount('https://', HTTPAdapter(max_retries=retries))
    payload = {
        "policyName": rule_name,
        "groupId": group_id
    }
    try:
        if dry_run:
            logger.info(f"Dry-run: Would assign rule {rule_name} to group {group_id}")
            return True, "Dry-run assignment successful"
        response = session.post(url, json=payload, auth=auth, verify=verify, timeout=30)
        response.raise_for_status()
        logger.info(f"Assigned rule {rule_name} to group {group_id}")
        return True, "Rule assigned successfully"
    except HTTPError as e:
        logger.error(f"Failed to assign rule {rule_name} to group {group_id} with HTTP error: {e.response.status_code} - {e.response.text}")
        return False, str(e)
    except (ConnectionError, Timeout) as e:
        logger.error(f"Failed to assign rule {rule_name} to group {group_id} with connection/timeout error: {e}")
        return False, str(e)
    except RequestException as e:
        logger.error(f"Failed to assign rule {rule_name} to group {group_id} with request error: {e}")
        return False, str(e)
    except Exception as e:
        logger.error(f"Unexpected error assigning rule {rule_name} to group {group_id}: {e}\n{traceback.format_exc()}")
        return False, str(e)

def main():
    processed_rules = 0
    corrected_rules = 0
    error_count = 0
    try:
        config = load_config()
        Path('/app/logs').mkdir(parents=True, exist_ok=True)
        Path(config["rules_dir"]).mkdir(parents=True, exist_ok=True)
        Path(config["markdown_rules_dir"]).mkdir(parents=True, exist_ok=True)
        # Test API connectivity during dry-run
        if config["dry_run"]:
            success, msg = test_api_connectivity(config)
            if not success:
                logger.error(f"Dry-run aborted: {msg}")
                sys.exit(1)
        # Load rules from JSON and markdown files
        rules = []
        # Process JSON rules
        for rule_file in Path(config["rules_dir"]).rglob("*.json"):
            try:
                with open(rule_file, 'r') as f:
                    file_rules = json.load(f)
                if not isinstance(file_rules, list):
                    file_rules = [file_rules]
                rules.extend(file_rules)
            except FileNotFoundError:
                error_count += 1
                logger.error(f"JSON rule file not found: {rule_file}")
                continue
            except json.JSONDecodeError as e:
                error_count += 1
                logger.error(f"Invalid JSON in rule file {rule_file}: {e}\n{traceback.format_exc()}")
                continue
            except Exception as e:
                error_count += 1
                logger.error(f"Failed to load JSON rule file {rule_file}: {e}\n{traceback.format_exc()}")
                continue
        # Process markdown rules
        for markdown_file in discover_markdown_rules(config["markdown_rules_dir"]):
            markdown_rules = parse_markdown_file(markdown_file)
            rules.extend(markdown_rules)
        # Process rules in batches
        batch_size = config["batch_size"]
        for i in range(0, len(rules), batch_size):
            batch = rules[i:i + batch_size]
            for rule in batch:
                try:
                    rule_type = rule.get("type")
                    if not rule_type:
                        error_count += 1
                        logger.error(f"Rule missing type: {rule.get('name', 'unknown')}")
                        continue
                    # Correct rule
                    corrected_rule = correct_rule(rule, rule_type)
                    if corrected_rule != rule:
                        corrected_rules += 1
                        logger.info(f"Corrected rule {rule.get('name', 'unknown')}")
                    # Validate rule
                    valid, message = validate_rule(corrected_rule, rule_type)
                    if not valid:
                        error_count += 1
                        logger.error(f"Invalid rule {corrected_rule.get('name', 'unknown')}: {message}")
                        continue
                    # Upload rule
                    epo_rule = to_epo_format(corrected_rule, rule_type)
                    if epo_rule is None:
                        error_count += 1
                        logger.error(f"Failed to convert rule {corrected_rule.get('name', 'unknown')} to ePO format: Unknown rule type")
                        continue
                    success, msg = upload_rule(epo_rule, config, config["dry_run"])
                    if not success:
                        error_count += 1
                        logger.error(f"Rule upload failed: {msg}")
                        continue
                    # Assign to group
                    if config["group_id"]:
                        success, msg = assign_rule_to_group(corrected_rule["name"], config["group_id"], config, config["dry_run"])
                        if not success:
                            error_count += 1
                            logger.error(f"Rule assignment failed: {msg}")
                    processed_rules += 1
                except Exception as e:
                    error_count += 1
                    logger.error(f"Error processing rule {rule.get('name', 'unknown')}: {e}\n{traceback.format_exc()}")
            time.sleep(1)  # Prevent overwhelming ePO
        logger.info(f"Processed {processed_rules} rules, corrected {corrected_rules}, {error_count} errors")
    except Exception as e:
        logger.error(f"Fatal error in main: {e}\n{traceback.format_exc()}")
        raise

def shutdown_handler(signum, frame):
    logger.info("Shutting down gracefully")
    logger.info(f"Final metrics: Processed {globals().get('processed_rules', 0)} rules, corrected {globals().get('corrected_rules', 0)}, {globals().get('error_count', 0)} errors")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)
    main()