import yaml
import argparse
from opensearchpy import OpenSearch, NotFoundError, OpenSearchException
from opensearchpy.helpers import bulk
import boto3
from botocore.exceptions import ClientError
import logging
from logging.handlers import RotatingFileHandler
from typing import Dict, Optional, List, Set
import re
from pathlib import Path
import asyncio
from concurrent.futures import ThreadPoolExecutor
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import json
import uuid
from threading import Lock
from prometheus_client import Counter, Histogram, start_http_server
import time

# Configure logging with structured JSON format and rotation
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[
        logging.StreamHandler(),
        RotatingFileHandler('sigma_import.log', maxBytes=10*1024*1024, backupCount=5)  # 10MB per file, 5 backups
    ]
)
logger = logging.getLogger(__name__)

class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            'timestamp': self.formatTime(record, '%Y-%m-%dT%H:%M:%S%z'),
            'level': record.levelname,
            'name': record.name,
            'message': record.msg % record.args if record.args else record.msg,
            'file': record.pathname,
            'line': record.lineno
        }
        return json.dumps(log_entry)

logger.handlers[0].setFormatter(JsonFormatter())
logger.handlers[1].setFormatter(JsonFormatter())

# Prometheus metrics
IMPORT_SUCCESS = Counter('sigma_import_success_total', 'Total successful rule imports')
IMPORT_FAILURE = Counter('sigma_import_failure_total', 'Total failed rule imports')
IMPORT_DURATION = Histogram('sigma_import_duration_seconds', 'Rule import duration')

class SigmaRuleValidator:
    """Validates Sigma rule structure and content."""

    REQUIRED_FIELDS = {'title', 'status', 'description', 'logsource', 'detection'}
    LOGSOURCE_FIELDS = {'product'}
    VALID_STATUSES = {'experimental', 'test', 'stable'}
    VALID_CONDITION_OPERATORS = {'and', 'or', 'not', '1 of', 'all of'}

    def __init__(self, config: Dict):
        """Initialize validator with configuration."""
        self.aws_logsource_products = set(config.get('aws_logsource_products', ['windows', 'cloudtrail', 'dns', 'vpcflow', 's3']))
        self.valid_tag_prefixes = set(config.get('valid_tag_prefixes', ['attack.', 'threat_']))

    def validate_rule(self, rule: Dict, strict_tags: bool = True, is_aws: bool = False) -> tuple[bool, str]:
        try:
            missing_fields = self.REQUIRED_FIELDS - set(rule.keys())
            if missing_fields:
                return False, f"Missing required fields: {missing_fields}"

            if not isinstance(rule['logsource'], dict):
                return False, "logsource must be a dictionary"

            missing_logsource = self.LOGSOURCE_FIELDS - set(rule['logsource'].keys())
            if missing_logsource:
                return False, f"Missing logsource fields: {missing_logsource}"

            if is_aws and rule['logsource']['product'] not in self.aws_logsource_products:
                return False, f"Invalid logsource product for AWS: {rule['logsource']['product']}. Must be one of {self.aws_logsource_products}"

            if rule['status'] not in self.VALID_STATUSES:
                return False, f"Invalid status: {rule['status']}. Must be one of {self.VALID_STATUSES}"

            if 'id' in rule:
                uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
                if not uuid_pattern.match(rule['id']):
                    return False, f"Invalid UUID format for id: {rule['id']}"

            if not isinstance(rule['detection'], dict) or 'condition' not in rule['detection']:
                return False, "Invalid detection structure: missing or malformed condition"

            condition = str(rule['detection']['condition']).lower()
            if not any(op in condition for op in self.VALID_CONDITION_OPERATORS):
                return False, f"Invalid detection condition: {condition}. Must contain valid operators: {self.VALID_CONDITION_OPERATORS}"

            if 'tags' in rule and strict_tags:
                if not all(isinstance(tag, str) and any(tag.startswith(prefix) for prefix in self.valid_tag_prefixes) for tag in rule['tags']):
                    return False, f"Invalid tags: must start with one of {self.valid_tag_prefixes} in strict mode"

            return True, ""
        except Exception as e:
            return False, f"Validation error: {str(e)}"

class SigmaImporter:
    """Handles importing Sigma rules into OpenSearch or AWS OpenSearch."""

    def __init__(self, host: str, port: int, scheme: str, username: Optional[str], password: Optional[str],
                 verify_certs: bool, provider: str, aws_region: Optional[str] = None, max_workers: int = 4,
                 config_path: str = 'config.yaml', metrics_port: int = 8000):
        """Initialize OpenSearch client with connection parameters."""
        self.provider = provider.lower()
        self.is_aws = self.provider == 'aws'
        self.used_ids = set()
        self.id_lock = Lock()
        self.existing_ids = set()

        # Load configuration
        try:
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f) or {}
        except FileNotFoundError:
            logger.warning(f"Config file {config_path} not found. Using default configuration.")
            self.config = {}

        self.validator = SigmaRuleValidator(self.config)

        if self.is_aws:
            if not aws_region:
                raise ValueError("AWS region must be provided for AWS OpenSearch")
            if not verify_certs:
                logger.warning("SSL certificate verification is disabled. This is insecure for production environments.")

            session = boto3.Session()
            credentials = session.get_credentials()
            if not credentials:
                raise ValueError("AWS credentials not found. Ensure AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and optionally AWS_SESSION_TOKEN are set.")

            from opensearchpy import AWSV4SignerAuth
            auth = AWSV4SignerAuth(credentials, aws_region, service='aoss' if 'serverless' in host else 'es')
            self.client = OpenSearch(
                hosts=[{'host': host, 'port': port}],
                http_auth=auth,
                use_ssl=(scheme == 'https'),
                verify_certs=verify_certs,
                ssl_show_warn=not verify_certs,
                timeout=30,
                max_retries=5,
                retry_on_timeout=True
            )
        else:
            if not verify_certs and scheme == 'https':
                logger.warning("SSL certificate verification is disabled. This is insecure for production environments.")
            self.client = OpenSearch(
                hosts=[{'host': host, 'port': port}],
                http_auth=(username, password) if username and password else None,
                use_ssl=(scheme == 'https'),
                verify_certs=verify_certs,
                ssl_show_warn=not verify_certs,
                timeout=30,
                max_retries=5,
                retry_on_timeout=True
            )

        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        start_http_server(metrics_port)  # Start Prometheus metrics server

    async def fetch_existing_ids(self) -> Set[str]:
        """Fetch all existing rule IDs from OpenSearch in a single query."""
        try:
            query = {
                "query": {"match_all": {}},
                "_source": ["rule.id"]
            }
            response = await asyncio.get_event_loop().run_in_executor(
                self.executor,
                lambda: self.client.search(index='_plugins/_security_analytics/rules', body=query, size=10000)
            )
            return {hit['_source']['rule']['id'] for hit in response['hits']['hits'] if 'rule' in hit['_source'] and 'id' in hit['_source']['rule']}
        except NotFoundError:
            return set()
        except Exception as e:
            logger.error(f"Error fetching existing rule IDs: {str(e)}")
            return set()

    async def check_existing_rule(self, title: str, rule_id: str) -> bool:
        """Check if a rule with the given title or ID already exists in OpenSearch."""
        try:
            query = {
                "query": {
                    "bool": {
                        "should": [
                            {"term": {"rule.title.keyword": title}},
                            {"term": {"rule.id.keyword": rule_id}}
                        ],
                        "minimum_should_match": 1
                    }
                }
            }
            response = await asyncio.get_event_loop().run_in_executor(
                self.executor,
                lambda: self.client.search(index='_plugins/_security_analytics/rules', body=query)
            )
            return response['hits']['total']['value'] > 0
        except NotFoundError:
            return False
        except Exception as e:
            logger.error(f"Error checking for existing rule {title} (ID: {rule_id}): {str(e)}")
            return False

    def update_yaml_file(self, file_path: Path, rule_data: Dict, new_id: str, read_only: bool) -> bool:
        """Update the YAML file with a new ID if not read-only."""
        if read_only:
            logger.warning(f"Read-only mode enabled. Skipping YAML update for {file_path} with new ID: {new_id}")
            return False
        try:
            rule_data['id'] = new_id
            with file_path.open('w') as f:
                yaml.safe_dump(rule_data, f, sort_keys=False)
            logger.info(f"Updated {file_path} with new ID: {new_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to update {file_path} with new ID: {str(e)}")
            raise

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=4, max=15),
        retry=retry_if_exception_type((OpenSearchException, ConnectionError, ClientError))
    )
    async def import_rules_bulk(self, rules: List[Dict], file_paths: List[str], categories: List[str], dry_run: bool) -> List[tuple[bool, str]]:
        """Import multiple Sigma rules in a single bulk API call."""
        if dry_run:
            results = []
            for file_path, rule_data in zip(file_paths, rules):
                logger.info(f"Dry run: Would import rule from {file_path} with ID {rule_data['id']}")
                results.append((True, rule_data['id']))
            return results

        actions = []
        for rule_data, file_path, category in zip(rules, file_paths, categories):
            if self.is_aws:
                rule_data['index_mapping'] = {'logsource': rule_data['logsource']['product']}
            actions.append({
                '_op_type': 'create',
                '_index': '_plugins/_security_analytics/rules',
                '_source': rule_data
            })

        try:
            start_time = time.time()
            successes, errors = await asyncio.get_event_loop().run_in_executor(
                self.executor,
                lambda: bulk(self.client, actions, raise_on_error=False)
            )
            duration = time.time() - start_time
            IMPORT_DURATION.observe(duration)

            results = []
            for (success, info), file_path in zip(successes, file_paths):
                if success:
                    IMPORT_SUCCESS.inc()
                    logger.info(f"Successfully imported rule from {file_path} with ID {info['create']['_id']}")
                    results.append((True, info['create']['_id']))
                else:
                    IMPORT_FAILURE.inc()
                    logger.error(f"Failed to import rule from {file_path}: {info}")
                    results.append((False, ""))

            for error in errors:
                logger.error(f"Bulk import error: {error}")

            return results
        except Exception as e:
            logger.error(f"Error during bulk import: {str(e)}")
            raise

    async def process_yaml_file(self, file_path: Path, strict_tags: bool = True, dry_run: bool = False, read_only: bool = False) -> tuple[bool, str, Dict, str]:
        """Process a single YAML file containing a Sigma rule."""
        try:
            if self.is_aws and file_path.suffix.lower() not in {'.yaml', '.yml'}:
                logger.error(f"Invalid file extension for {file_path}. AWS OpenSearch requires .yaml or .yml files.")
                return False, "", {}, ""

            with file_path.open('r') as f:
                rule_data = yaml.safe_load(f)

            is_valid, error_msg = self.validator.validate_rule(rule_data, strict_tags, self.is_aws)
            if not is_valid:
                logger.error(f"Validation failed for {file_path}: {error_msg}")
                return False, "", {}, ""

            title = rule_data['title']
            category = rule_data['logsource']['product']

            with self.id_lock:
                if 'id' not in rule_data:
                    rule_data['id'] = str(uuid.uuid4())
                    logger.info(f"Generated new ID for {file_path}: {rule_data['id']}")
                    self.update_yaml_file(file_path, rule_data, rule_data['id'], read_only)
                elif rule_data['id'] in self.used_ids or rule_data['id'] in self.existing_ids:
                    old_id = rule_data['id']
                    rule_data['id'] = str(uuid.uuid4())
                    logger.info(f"Duplicate ID {old_id} detected for {file_path}. Replaced with new ID: {rule_data['id']}")
                    self.update_yaml_file(file_path, rule_data, rule_data['id'], read_only)
                self.used_ids.add(rule_data['id'])

            if not dry_run and await self.check_existing_rule(title, rule_data['id']):
                logger.warning(f"Rule '{title}' (ID: {rule_data['id']}) from {file_path} already exists in OpenSearch. Skipping.")
                return False, "", {}, ""

            return True, rule_data['id'], rule_data, category

        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML file {file_path}: {str(e)}")
            return False, "", {}, ""
        except Exception as e:
            logger.error(f"Unexpected error processing {file_path}: {str(e)}")
            return False, "", {}, ""

    async def import_directory(self, directory: str, strict_tags: bool = True, max_files: int = 1000,
                             dry_run: bool = False, read_only: bool = False, batch_size: int = 100) -> List[str]:
        """Recursively import all YAML files from a directory."""
        failed_files = []
        tasks = []
        file_count = 0

        if not dry_run:
            self.existing_ids = await self.fetch_existing_ids()
            logger.info(f"Fetched {len(self.existing_ids)} existing rule IDs from OpenSearch")

        for file_path in Path(directory).rglob('*.y*ml'):
            if file_count >= max_files:
                logger.warning(f"Reached maximum file limit of {max_files}. Stopping file discovery.")
                break
            tasks.append(self.process_yaml_file(file_path, strict_tags, dry_run, read_only))
            file_count += 1

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect valid rules for bulk import
        valid_rules = []
        valid_file_paths = []
        valid_categories = []
        for file_path, result in zip(Path(directory).rglob('*.y*ml'), results):
            if not isinstance(result, tuple) or not result[0]:
                failed_files.append(str(file_path))
            else:
                _, _, rule_data, category = result
                if rule_data:
                    valid_rules.append(rule_data)
                    valid_file_paths.append(str(file_path))
                    valid_categories.append(category)

        # Perform bulk import
        if valid_rules and not dry_run:
            for i in range(0, len(valid_rules), batch_size):
                batch_rules = valid_rules[i:i + batch_size]
                batch_files = valid_file_paths[i:i + batch_size]
                batch_categories = valid_categories[i:i + batch_size]
                batch_results = await self.import_rules_bulk(batch_rules, batch_files, batch_categories, dry_run)
                for file_path, (success, _) in zip(batch_files, batch_results):
                    if not success:
                        failed_files.append(file_path)
        elif valid_rules and dry_run:
            for file_path, rule_data in zip(valid_file_paths, valid_rules):
                logger.info(f"Dry run: Would import rule from {file_path} with ID {rule_data['id']}")

        return failed_files

    def __del__(self):
        """Ensure ThreadPoolExecutor is properly shut down."""
        self.executor.shutdown(wait=True)

async def main():
    """Main function to parse arguments and run the Sigma rule import process."""
    parser = argparse.ArgumentParser(description="Import Sigma rules into OpenSearch or AWS OpenSearch Security Analytics.")
    parser.add_argument('--host', default='localhost', help="OpenSearch host")
    parser.add_argument('--port', default=9200, type=int, help="OpenSearch port")
    parser.add_argument('--scheme', default='http', choices=['http', 'https'], help="Connection scheme")
    parser.add_argument('--username', help="OpenSearch username (for generic OpenSearch)")
    parser.add_argument('--password', help="OpenSearch password (for generic OpenSearch)")
    parser.add_argument('--verify-certs', action='store_true', help="Verify SSL certificates")
    parser.add_argument('--directory', default='.', help="Directory to scan for YAML files")
    parser.add_argument('--strict-tags', action='store_true', default=True, help="Enforce strict tag naming")
    parser.add_argument('--max-workers', type=int, default=4, help="Maximum number of worker threads")
    parser.add_argument('--max-files', type=int, default=1000, help="Maximum number of files to process")
    parser.add_argument('--provider', choices=['opensearch', 'aws'], default='opensearch', help="OpenSearch provider (opensearch or aws)")
    parser.add_argument('--aws-region', help="AWS region (required for AWS OpenSearch)")
    parser.add_argument('--dry-run', action='store_true', help="Simulate imports without modifying OpenSearch or YAML files")
    parser.add_argument('--read-only', action='store_true', help="Prevent YAML file updates (e.g., for ID generation)")
    parser.add_argument('--config', default='config.yaml', help="Path to configuration file")
    parser.add_argument('--metrics-port', type=int, default=8000, help="Port for Prometheus metrics endpoint")
    parser.add_argument('--batch-size', type=int, default=100, help="Number of rules per bulk import")

    args = parser.parse_args()

    importer = SigmaImporter(
        args.host, args.port, args.scheme,
        args.username, args.password, args.verify_certs,
        args.provider, args.aws_region, args.max_workers,
        args.config, args.metrics_port
    )

    failed_files = await importer.import_directory(
        args.directory, args.strict_tags, args.max_files, args.dry_run, args.read_only, args.batch_size
    )

    if failed_files:
        logger.error(f"Failed to import {len(failed_files)} files: {failed_files}")
        exit(1)
    else:
        logger.info("All rules processed successfully" + (" (dry run)" if args.dry_run else ""))

if __name__ == "__main__":
    asyncio.run(main())