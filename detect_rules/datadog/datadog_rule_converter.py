import yaml
import re
import json
import os
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from datadog_api_client import ApiClient, Configuration
from datadog_api_client.v2.api.security_monitoring import SecurityMonitoringApi
from datadog_api_client.v2.model.security_monitoring_rule_create_payload import SecurityMonitoringRuleCreatePayload
from jsonschema import validate, ValidationError
from collections import Counter
import time

# Configure logging
logging.basicConfig(
    filename='datadog_rule_conversion.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Datadog JSON schema for signal correlation rules
DATADOG_RULE_SCHEMA = {
    "type": "object",
    "required": ["data"],
    "properties": {
        "data": {
            "type": "object",
            "required": ["type", "attributes"],
            "properties": {
                "type": {"type": "string", "enum": ["signal_correlation"]},
                "attributes": {
                    "type": "object",
                    "required": ["name", "enabled", "cases", "group_by_fields", "distinct_fields", "correlation", "message", "severity", "tags", "options"],
                    "properties": {
                        "name": {"type": "string", "minLength": 1},
                        "enabled": {"type": "boolean"},
                        "cases": {
                            "type": "array",
                            "minItems": 1,
                            "items": {
                                "type": "object",
                                "required": ["name", "status", "query"],
                                "properties": {
                                    "name": {"type": "string", "minLength": 1},
                                    "status": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                                    "query": {"type": "string", "minLength": 1}
                                }
                            }
                        },
                        "group_by_fields": {"type": "array", "items": {"type": "string"}},
                        "distinct_fields": {"type": "array", "items": {"type": "string"}},
                        "correlation": {
                            "type": "object",
                            "required": ["expression", "timeframe"],
                            "properties": {
                                "expression": {"type": "string", "minLength": 1},
                                "timeframe": {"type": "string", "pattern": "^\\d+[smhd]$"}
                            }
                        },
                        "message": {"type": "string"},
                        "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                        "tags": {"type": "array", "items": {"type": "string"}},
                        "options": {
                            "type": "object",
                            "required": ["evaluation_window"],
                            "properties": {
                                "evaluation_window": {"type": "string", "pattern": "^\\d+[smhd]$"}
                            }
                        },
                        "rule_id": {"type": "string", "minLength": 1}
                    }
                }
            }
        }
    }
}

class ConversionMetricsLogger:
    """Track and save conversion metrics for DevOps pipeline."""
    def __init__(self):
        self.metrics = {
            "total_files": 0,
            "files_processed": 0,
            "files_failed": 0,
            "total_rules": 0,
            "rules_processed": 0,
            "rules_failed": 0,
            "case_counts": {},
            "failure_reasons": [],
            "conversion_duration_seconds": 0
        }
        self.start_time = time.time()

    def log_file(self, file_path, processed, failure_reason=None):
        self.metrics["total_files"] += 1
        if processed:
            self.metrics["files_processed"] += 1
        else:
            self.metrics["files_failed"] += 1
            if failure_reason:
                self.metrics["failure_reasons"].append({"file": str(file_path), "reason": failure_reason})

    def log_rule(self, file_path, processed, case_count, failure_reason=None):
        self.metrics["total_rules"] += 1
        self.metrics["case_counts"][str(file_path)] = self.metrics["case_counts"].get(str(file_path), 0) + case_count
        if processed:
            self.metrics["rules_processed"] += 1
        else:
            self.metrics["rules_failed"] += 1
            if failure_reason:
                self.metrics["failure_reasons"].append({"file": str(file_path), "reason": failure_reason})

    def save_metrics(self, output_path="conversion_metrics.json"):
        self.metrics["conversion_duration_seconds"] = time.time() - self.start_time
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.metrics, f, indent=2)

def parse_markdown_yaml(file_path):
    """Parse Markdown or YAML content, handling multiple YAML and SQL blocks."""
    logging.info(f"Parsing file: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        logging.error(f"Failed to read {file_path}: {str(e)}")
        return []

    if file_path.suffix in ['.yaml', '.yml']:
        try:
            rule_data = yaml.safe_load(content)
            if not rule_data or 'name' not in rule_data or 'type' not in rule_data:
                logging.warning(f"No valid rule data in {file_path}")
                return []
            return [rule_data]
        except yaml.YAMLError as e:
            logging.error(f"Invalid YAML in {file_path}: {str(e)}")
            return []

    yaml_pattern = r'```yaml\n([\s\S]*?)\n```'
    sql_pattern = r'```sql\n([\s\S]*?)\n```'
    yaml_matches = re.findall(yaml_pattern, content)
    sql_matches = re.findall(sql_pattern, content)

    if not yaml_matches and not sql_matches:
        logging.warning(f"No YAML or SQL blocks found in {file_path}")
        return []

    rule_data_list = []
    if yaml_matches:
        for yaml_content in yaml_matches:
            try:
                rule_data = yaml.safe_load(yaml_content)
                if not rule_data or 'name' not in rule_data or 'type' not in rule_data:
                    logging.warning(f"Invalid YAML block in {file_path}")
                    continue
                rule_data_list.append(rule_data)
            except yaml.YAMLError as e:
                logging.error(f"Invalid YAML block in {file_path}: {str(e)}")
                continue
    else:
        rule_data = {
            "name": file_path.stem.replace('_', ' ').title(),
            "type": "signal_correlation",
            "signal_correlation": {
                "group_by_fields": [],
                "distinct_fields": ["case_id"],
                "correlation": {"expression": "distinct_count >= 1", "timeframe": "1h"}
            },
            "message": f"Generated from {file_path}",
            "severity": "medium",
            "tags": [],
            "options": {"evaluation_window": "1h"},
            "cases": []
        }
        rule_data_list.append(rule_data)

    for rule_data in rule_data_list:
        if sql_matches:
            rule_data["cases"] = rule_data.get("cases", [])
            for j, sql_query in enumerate(sql_matches, 1):
                sql_query = sql_query.strip()
                if not sql_query:
                    logging.warning(f"Empty SQL block in {file_path}")
                    continue
                case = {
                    "name": f"Case {j}",
                    "status": rule_data.get("severity", "medium"),
                    "query": sql_query
                }
                rule_data_list.append(case)
            sql_matches = []
        if not rule_data.get("cases"):
            logging.warning(f"No valid cases in rule from {file_path}")
            rule_data_list.remove(rule_data)

    return rule_data_list

def mock_datadog_query_executor(query, file_path, case_name):
    """Mock Datadog query executor for deeper validation."""
    known_sources = {'vault', 'linux', 'email', 'cloudtrail'}
    operators = {'AND', 'OR', 'NOT'}
    aggregations = {'groupby', 'agg', 'filter', 'select', 'eval', 'mvexpand', 'timeslice'}

    # Tokenize query (simplified, not a full parser)
    tokens = re.split(r'\s+|\(|\)|,|:', query)
    tokens = [t for t in tokens if t]

    # Check source
    if not tokens[0].startswith('source:'):
        return False, f"Query missing 'source:' prefix in case {case_name} for {file_path}"
    source = tokens[0].replace('source:', '')
    if source not in known_sources:
        return False, f"Unknown source '{source}' in case {case_name} for {file_path}"

    # Check field references and operators
    for token in tokens:
        if token.startswith('@') and not re.match(r'@[a-zA-Z0-9._-]+$', token):
            return False, f"Invalid field reference '{token}' in case {case_name} for {file_path}"
        if token in operators:
            continue
        if token in aggregations:
            continue
        if token.startswith('(') or token.endswith(')') or token in {',', ':'}:
            continue
        if not re.match(r'[a-zA-Z0-9._*=/]+$', token):
            return False, f"Invalid token '{token}' in case {case_name} for {file_path}"

    # Check balanced parentheses
    paren_count = 0
    for char in query:
        if char == '(':
            paren_count += 1
        elif char == ')':
            paren_count -= 1
        if paren_count < 0:
            return False, f"Unbalanced parentheses in case {case_name} for {file_path}"
    if paren_count != 0:
        return False, f"Unbalanced parentheses in case {case_name} for {file_path}"

    # Check balanced quotes
    quote_count = Counter(query)
    if quote_count.get('"', 0) % 2 != 0 or quote_count.get("'", 0) % 2 != 0:
        return False, f"Unbalanced quotes in case {case_name} for {file_path}"

    # Check non-empty clauses
    for agg in ['filter', 'groupby', 'agg']:
        if f"{agg}(" in query:
            match = re.search(rf"{agg}\((.*?)\)", query)
            if match and not match.group(1).strip():
                return False, f"Empty {agg} clause in case {case_name} for {file_path}"

    return True, None

def validate_query_syntax(query, file_path, case_name):
    """Validate Datadog SQL query syntax."""
    if not query.startswith("source:"):
        return False, f"Query missing 'source:' prefix in case {case_name} for {file_path}"

    source_match = re.match(r"source:([a-zA-Z0-9_-]+)", query)
    if not source_match:
        return False, f"Invalid source in case {case_name} for {file_path}"

    datadog_syntax = re.search(r"(@[a-zA-Z0-9._-]+|\||groupby\(|agg\(|filter\()", query)
    if not datadog_syntax and not re.search(r"\b(source:[a-zA-Z0-9_-]+)\b", query):
        return False, f"Missing Datadog syntax (@field, |, groupby, agg, filter) in case {case_name} for {file_path}"

    return mock_datadog_query_executor(query, file_path, case_name)

def convert_to_datadog_json(rule_data, file_path):
    """Convert parsed rule data to Datadog JSON format."""
    if not rule_data:
        logging.warning(f"No rule data to convert from {file_path}")
        return None

    json_template = {
        "data": {
            "type": "signal_correlation",
            "attributes": {
                "name": rule_data.get('name', 'Unnamed Rule'),
                "enabled": rule_data.get('is_enabled', True),
                "cases": [],
                "group_by_fields": rule_data.get('signal_correlation', {}).get('group_by_fields', []),
                "distinct_fields": rule_data.get('signal_correlation', {}).get('distinct_fields', ["case_id"]),
                "correlation": {
                    "expression": rule_data.get('signal_correlation', {}).get('correlation', {}).get('expression', "distinct_count >= 1"),
                    "timeframe": rule_data.get('signal_correlation', {}).get('correlation', {}).get('timeframe', "1h")
                },
                "message": rule_data.get('message', ''),
                "severity": rule_data.get('severity', 'high'),
                "tags": rule_data.get('tags', []),
                "options": rule_data.get('options', {"evaluation_window": "1h"})
            }
        }
    }

    for case in rule_data.get('cases', []):
        valid, reason = validate_query_syntax(case.get('query', ''), file_path, case.get('name', 'Unnamed Case'))
        if not valid:
            logging.error(f"Skipping case due to invalid query: {reason}")
            return None
        json_case = {
            "name": case.get('name', ''),
            "status": case.get('status', 'medium'),
            "query": case.get('query', '')
        }
        json_template['data']['attributes']['cases'].append(json_case)

    if rule_data.get('signal_correlation', {}).get('rule_id'):
        json_template['data']['attributes']['rule_id'] = rule_data['signal_correlation']['rule_id']

    try:
        validate(instance=json_template, schema=DATADOG_RULE_SCHEMA)
    except ValidationError as e:
        logging.error(f"JSON schema validation failed for {file_path}: {str(e)}")
        return None

    return json_template

def save_json(json_data, file_path, rule_name, rule_names):
    """Save JSON to file with name-based filename, handling duplicates."""
    safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', rule_name.lower())
    base_name = safe_name
    suffix = 1
    while safe_name in rule_names:
        safe_name = f"{base_name}_{suffix}"
        suffix += 1
    rule_names.add(safe_name)
    output_file = Path("signal_correlation_rules") / f"{safe_name}.json"
    output_file.parent.mkdir(exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=2)
    logging.info(f"Saved JSON to {output_file}")
    return output_file

def import_to_datadog(json_data):
    """Import JSON rule to Datadog Security Monitoring API."""
    api_key = os.getenv("DD_API_KEY")
    app_key = os.getenv("DD_APP_KEY")
    dry_run = os.getenv("DD_DRY_RUN", "false").lower() == "true"

    if not api_key or not app_key:
        logging.error("Missing DD_API_KEY or DD_APP_KEY environment variables")
        return False, "Missing API credentials"

    if dry_run:
        logging.info("Dry-run mode: Skipping API import")
        return True, "Dry-run success"

    configuration = Configuration()
    configuration.api_key["apiKeyAuth"] = api_key
    configuration.api_key["appKeyAuth"] = app_key

    with ApiClient(configuration) as api_client:
        api_instance = SecurityMonitoringApi(api_client)
        try:
            rule_payload = SecurityMonitoringRuleCreatePayload(**json_data)
            response = api_instance.create_security_monitoring_rule(body=rule_payload)
            logging.info(f"Imported rule: {response.data.attributes.name}")
            return True, response.data.id
        except Exception as e:
            logging.error(f"Failed to import rule: {str(e)}")
            return False, str(e)

def process_file(file_path, rule_names, conversion_summary, import_summary, metrics_logger):
    """Process a single file and return results."""
    rule_data_list = parse_markdown_yaml(file_path)
    if not rule_data_list:
        metrics_logger.log_file(file_path, False, "No valid rules parsed")
        conversion_summary["failed"].append({"file": str(file_path), "reason": "No valid rules parsed"})
        return

    for rule_data in rule_data_list:
        json_data = convert_to_datadog_json(rule_data, file_path)
        if not json_data:
            metrics_logger.log_rule(file_path, False, 0, "JSON conversion failed")
            conversion_summary["failed"].append({"file": str(file_path), "reason": "JSON conversion failed"})
            continue

        case_count = len(json_data["data"]["attributes"]["cases"])
        output_file = save_json(json_data, file_path, rule_data["name"], rule_names)
        conversion_summary["successful"].append({"file": str(file_path), "output": str(output_file)})
        metrics_logger.log_rule(file_path, True, case_count)

        success, result = import_to_datadog(json_data)
        if success:
            import_summary["successful"].append({"file": str(file_path), "rule_id": result})
        else:
            import_summary["failed"].append({"file": str(file_path), "reason": result})

    metrics_logger.log_file(file_path, True)

def main():
    metrics_logger = ConversionMetricsLogger()
    rules_dir = Path("rules")
    output_dir = Path("signal_correlation_rules")
    output_dir.mkdir(exist_ok=True)
    rule_names = set()
    import_summary = {"successful": [], "failed": []}
    conversion_summary = {"successful": [], "failed": []}

    files = list(rules_dir.rglob('*.[mM][dD]')) + list(rules_dir.rglob('*.[yY][aA][mM][lL]'))
    if not files:
        logging.error("No Markdown or YAML files found in rules/ directory")
        metrics_logger.log_file(rules_dir, False, "No files found")
        metrics_logger.save_metrics()
        return

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [
            executor.submit(process_file, file_path, rule_names, conversion_summary, import_summary, metrics_logger)
            for file_path in files
        ]
        for future in futures:
            future.result()

    with open("conversion_summary.json", 'w', encoding='utf-8') as f:
        json.dump(conversion_summary, f, indent=2)
    with open("import_summary.json", 'w', encoding='utf-8') as f:
        json.dump(import_summary, f, indent=2)
    metrics_logger.save_metrics()

if __name__ == "__main__":
    main()