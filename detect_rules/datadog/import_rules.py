import os
import json
import logging
import yaml
import re
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datadog_api_client import ApiClient, Configuration
from datadog_api_client.v2.api.security_monitoring import SecurityMonitoringApi
from datadog_api_client.exceptions import ApiException
import urllib3
from jsonschema import validate, ValidationError
import hashlib
import unittest
import sys
from requests.exceptions import ConnectionError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging with rotation
from logging.handlers import RotatingFileHandler
logger = logging.getLogger(__name__)
handler = RotatingFileHandler('datadog_rule_conversion.log', maxBytes=10*1024*1024, backupCount=5)
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

# Datadog JSON schema
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

class DatadogRuleConverter:
    """Class to convert Datadog signal correlation rules from Markdown/YAML to JSON."""

    def __init__(self, api_key=None, app_key=None, site='us', disable_ssl=False):
        self.api_key = api_key or os.getenv('DD_API_KEY')
        self.app_key = app_key or os.getenv('DD_APP_KEY')
        self.site = site.lower()
        self.disable_ssl = disable_ssl or os.getenv('DD_DISABLE_SSL', 'false').lower() == 'true'
        self.output_dir = Path.cwd() / 'signal_correlation_rules'
        self.valid_sites = ['us', 'us3', 'us5', 'eu', 'ap1']

        if not self.api_key or not self.app_key:
            logger.error({"error": "Missing Datadog API or App key"})
            raise ValueError("DD_API_KEY and DD_APP_KEY must be set")
        if self.site not in self.valid_sites:
            logger.error({"error": f"Invalid Datadog site: {self.site}", "details": f"Valid sites: {self.valid_sites}"})
            raise ValueError(f"DD_SITE must be one of {self.valid_sites}")

        self.api_client = self._configure_datadog_client()
        self.output_dir.mkdir(exist_ok=True)

    def _configure_datadog_client(self):
        configuration = Configuration()
        configuration.api_key['apiKeyAuth'] = self.api_key.strip()
        configuration.api_key['appKeyAuth'] = self.app_key.strip()
        configuration.server_variables['site'] = self.site
        if self.disable_ssl:
            configuration.ssl_ca_cert = None
        return ApiClient(configuration)

    def parse_markdown_yaml(self, file_path, max_retries=3):
        for attempt in range(max_retries):
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()

                if file_path.suffix in ['.yaml', '.yml']:
                    rule_data = yaml.safe_load(content)
                    if not rule_data or 'name' not in rule_data or 'type' not in rule_data or 'cases' not in rule_data:
                        logger.error({"error": f"Invalid YAML in {file_path}", "details": "Missing required fields"})
                        return None
                    logger.info(f"Parsed YAML from {file_path}")
                    return rule_data
                else:
                    yaml_pattern = r'```yaml\n([\s\S]*?)\n```'
                    yaml_matches = re.findall(yaml_pattern, content)
                    if yaml_matches:
                        rule_data = yaml.safe_load(yaml_matches[0])
                        if not rule_data or 'name' not in rule_data or 'type' not in rule_data or 'cases' not in rule_data:
                            logger.error({"error": f"Invalid YAML in {file_path}", "details": "Missing required fields"})
                            return None
                        logger.info(f"Parsed YAML from Markdown in {file_path}")
                        return rule_data
                    logger.warning(f"No YAML content in {file_path}")
                    return None
            except (yaml.YAMLError, IOError) as e:
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                logger.error({"error": f"Failed to parse {file_path}", "details": str(e)})
                return None

    def convert_to_datadog_json(self, rule_data, file_path):
        if not rule_data:
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
            json_case = {
                "name": case.get('name', ''),
                "status": case.get('status', 'medium'),
                "query": case.get('query', '')
            }
            json_template['data']['attributes']['cases'].append(json_case)

        if rule_data.get('signal_correlation', {}).get('rule_id'):
            json_template['data']['attributes']['rule_id'] = rule_data['signal_correlation']['rule_id']

        return json_template

    def validate_json(self, json_data, file_path):
        try:
            validate(instance=json_data, schema=DATADOG_RULE_SCHEMA)
            logger.info(f"Validated JSON for {file_path}")
            return True
        except ValidationError as e:
            logger.error({"error": f"Invalid JSON schema for {file_path}", "details": str(e)})
            return False

    def save_json(self, json_data, file_path):
        safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', Path(file_path).stem)
        output_file = self.output_dir / f"{safe_name}.json"
        # Check directory permissions
        if not os.access(self.output_dir, os.W_OK):
            logger.error({"error": f"No write permission for directory {self.output_dir}"})
            return None
        for attempt in range(3):
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(json_data, f, indent=2)
                logger.info(f"Saved JSON to {output_file}")
                return output_file
            except IOError as e:
                if attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
                logger.error({"error": f"Failed to save JSON for {file_path}", "details": str(e)})
                return None

    def process_file(self, file_path):
        rule_data = self.parse_markdown_yaml(file_path)
        if rule_data:
            json_data = self.convert_to_datadog_json(rule_data, file_path)
            if json_data and self.validate_json(json_data, file_path):
                return self.save_json(json_data, file_path)
        return None

    def process_directory(self, directory):
        directory = Path(directory)
        success_count = 0
        failure_count = 0
        processed_files = []

        files = [f for f in directory.rglob('*') if f.suffix in ['.md', '.yaml', '.yml']]
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_file = {executor.submit(self.process_file, file_path): file_path for file_path in files}
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    if result:
                        processed_files.append(result)
                        success_count += 1
                    else:
                        failure_count += 1
                except Exception as e:
                    logger.error({"error": f"Error processing {file_path}", "details": str(e)})
                    failure_count += 1

        logger.info(f"Conversion completed: {success_count} files succeeded, {failure_count} files failed")
        return processed_files, success_count, failure_count

    def import_to_datadog(self, json_files, max_retries=3):
        success_count = 0
        failure_count = 0
        results = []

        for json_file in json_files:
            retry_count = 0
            with open(json_file, 'rb') as f:
                checksum = hashlib.sha256(f.read()).hexdigest()
            json_data = validate_json_file(json_file)
            if not json_data:
                results.append({"file": str(json_file), "status": "failed", "details": "Invalid JSON or schema"})
                failure_count += 1
                continue

            while retry_count <= max_retries:
                try:
                    with self.api_client:
                        api_instance = SecurityMonitoringApi(self.api_client)
                        response = api_instance.create_security_monitoring_rule(body=json_data)
                        logger.info(f"Imported {json_file}. Rule ID: {response.id}")
                        results.append({"file": str(json_file), "status": "success", "rule_id": response.id, "checksum": checksum})
                        success_count += 1
                        break
                except (ApiException, ConnectionError) as e:
                    if isinstance(e, ApiException) and e.status == 429:
                        retry_count += 1
                        wait_time = 2 ** retry_count
                        logger.warning(f"Rate limit for {json_file}. Retrying in {wait_time}s")
                        time.sleep(wait_time)
                    else:
                        logger.error({"error": f"Failed to import {json_file}", "details": str(e)})
                        results.append({"file": str(json_file), "status": "failed", "details": str(e), "checksum": checksum})
                        failure_count += 1
                        break

        return results, success_count, failure_count

    def import_all_json(self):
        json_files = list(self.output_dir.glob('*.json'))
        if not json_files:
            logger.warning("No JSON files in signal_correlation_rules")
            return [], 0, 0
        return self.import_to_datadog(json_files, max_retries=int(os.getenv('DD_MAX_RETRIES', 3)))

class TestDatadogRuleConverter(unittest.TestCase):
    def setUp(self):
        self.converter = DatadogRuleConverter(api_key="test", app_key="test", disable_ssl=True)
        self.sample_yaml = """
        name: Test Rule
        type: signal_correlation
        cases:
          - name: Test Case
            status: high
            query: test:query
        signal_correlation:
          group_by_fields:
            - host
          distinct_fields:
            - case_id
          correlation:
            expression: distinct_count >= 1
            timeframe: 1h
        message: Test message
        severity: high
        tags:
          - security:attack
        options:
          evaluation_window: 1h
        """
        self.invalid_yaml = """
        name: Invalid Rule
        type: signal_correlation
        cases:
          - name: Test Case
            status: invalid_status  # Invalid status
            query: test:query
        """

    def test_parse_yaml(self):
        with open("test.yaml", "w") as f:
            f.write(self.sample_yaml)
        rule_data = self.converter.parse_markdown_yaml("test.yaml")
        self.assertIsNotNone(rule_data)
        self.assertEqual(rule_data["name"], "Test Rule")
        os.remove("test.yaml")

    def test_parse_empty_yaml(self):
        with open("empty.yaml", "w") as f:
            f.write("")
        rule_data = self.converter.parse_markdown_yaml("empty.yaml")
        self.assertIsNone(rule_data)
        os.remove("empty.yaml")

    def test_parse_invalid_yaml(self):
        with open("invalid.yaml", "w") as f:
            f.write("invalid: : : yaml: :")
        rule_data = self.converter.parse_markdown_yaml("invalid.yaml")
        self.assertIsNone(rule_data)
        os.remove("invalid.yaml")

    def test_convert_to_json(self):
        rule_data = yaml.safe_load(self.sample_yaml)
        json_data = self.converter.convert_to_datadog_json(rule_data, "test.yaml")
        self.assertIsNotNone(json_data)
        self.assertEqual(json_data["data"]["attributes"]["name"], "Test Rule")

    def test_validate_json(self):
        rule_data = yaml.safe_load(self.sample_yaml)
        json_data = self.converter.convert_to_datadog_json(rule_data, "test.yaml")
        self.assertTrue(self.converter.validate_json(json_data, "test.yaml"))

    def test_validate_invalid_json(self):
        rule_data = yaml.safe_load(self.invalid_yaml)
        json_data = self.converter.convert_to_datadog_json(rule_data, "invalid.yaml")
        self.assertFalse(self.converter.validate_json(json_data, "invalid.yaml"))

def validate_json_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
        validate(instance=data, schema=DATADOG_RULE_SCHEMA)
        return data
    except (json.JSONDecodeError, ValidationError) as e:
        logger.error({"error": f"Invalid JSON in {file_path}", "details": str(e)})
        return None

def main():
    try:
        # Check for API keys before initializing
        api_key = os.getenv('DD_API_KEY')
        app_key = os.getenv('DD_APP_KEY')
        if not api_key or not app_key:
            logger.error("Missing DD_API_KEY or DD_APP_KEY environment variables. Please set them before running the script.")
            sys.exit(1)

        converter = DatadogRuleConverter()
        directory = Path.cwd()

        processed_files, convert_success, convert_failure = converter.process_directory(directory)
        imported_files, import_success, import_failure = converter.import_all_json()

        summary = {
            "total_files_converted": convert_success + convert_failure,
            "successful_conversions": convert_success,
            "failed_conversions": convert_failure,
            "converted_files": [str(f) for f in processed_files],
            "total_files_imported": import_success + import_failure,
            "successful_imports": import_success,
            "failed_imports": import_failure,
            "imported_files": [str(f) for f in imported_files]
        }
        with open('conversion_summary.json', 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)
        logger.info("Summary saved to conversion_summary.json")

    except Exception as e:
        logger.error({"error": "Script execution failed", "details": str(e)})
        raise
    finally:
        converter.api_client.close()

    return None

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        unittest.main(argv=[sys.argv[0]])
    else:
        main()