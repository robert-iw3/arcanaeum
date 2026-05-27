import os
import json
import re
import uuid
import logging
import sys
from typing import Dict, Optional, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from azure.identity import DefaultAzureCredential
from azure.mgmt.loganalytics import LogAnalyticsManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.core.exceptions import HttpResponseError
import prometheus_client as prom
from prometheus_client import Counter, Histogram, Gauge
from cachetools import TTLCache
import html
from retry import retry
import multiprocessing

# Configure structured JSON logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("sentinel_pipeline.log")
    ]
)
logger = logging.getLogger(__name__)

# Prometheus metrics
PIPELINE_SUCCESS = Counter('pipeline_queries_imported_total', 'Total queries successfully imported', ['query_type'])
PIPELINE_FAILURES = Counter('pipeline_queries_failed_total', 'Total queries failed to import', ['query_type'])
PIPELINE_DURATION = Histogram('pipeline_execution_seconds', 'Pipeline execution time', ['stage'])
KQL_VALIDATION_SUCCESS = Counter('kql_validation_success_total', 'Total KQL queries validated successfully', ['rule'])
KQL_VALIDATION_FAILURES = Counter('kql_validation_failed_total', 'Total KQL queries failed validation', ['rule'])
QUERIES_PROCESSED = Gauge('queries_processed', 'Number of queries processed in current run')
CACHE_HITS = Counter('kql_cache_hits_total', 'Total cache hits for KQL validation')
CACHE_MISSES = Counter('kql_cache_misses_total', 'Total cache misses for KQL validation')
METADATA_PARSING_ERRORS = Counter('metadata_parsing_errors_total', 'Total metadata parsing errors', ['file'])

class SentinelPipeline:
    """Optimized pipeline for importing KQL queries into Azure Sentinel."""

    def __init__(self, config: Dict[str, str], max_workers: Optional[int] = None, cache_ttl: int = 3600, batch_size: int = 100):
        """Initialize pipeline with configuration, metrics, and caching."""
        self.config = self._validate_config(config)
        self.credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        self.log_analytics_client = LogAnalyticsManagementClient(self.credential, self.config["subscription_id"])
        self.resource_client = ResourceManagementClient(self.credential, self.config["subscription_id"])
        self.import_dir = os.path.join(os.getcwd(), "import")
        self.saved_search_category = "Hunting Queries"
        self.saved_search_version = 2
        self.max_workers = max_workers or max(1, multiprocessing.cpu_count() // 2)
        self.kql_cache = TTLCache(maxsize=500, ttl=cache_ttl)
        self.batch_size = batch_size
        QUERIES_PROCESSED.set(0)

    def _validate_config(self, config: Dict[str, str]) -> Dict[str, str]:
        """Validate and sanitize configuration parameters."""
        required_keys = ["subscription_id", "resource_group_name", "workspace_name", "location", "query_pack_name"]
        sanitized_config = {}
        for key in required_keys:
            value = config.get(key)
            if not value:
                logger.error({"event": "config_validation_failed", "key": key, "error": "Missing configuration"})
                raise ValueError(f"Missing configuration: {key}")
            sanitized_config[key] = html.escape(str(value))
        return sanitized_config

    def validate_kql_query(self, query: str, file_path: str) -> Tuple[bool, str]:
        """Validate KQL query against Microsoft Sentinel best practices."""
        query = query.strip()
        if not query:
            KQL_VALIDATION_FAILURES.labels(rule="empty_query").inc()
            logger.warning({"event": "kql_validation_failed", "file": file_path, "rule": "empty_query"})
            return False, "Query is empty"

        if len(query) > 10000:  # Prevent excessive query length
            KQL_VALIDATION_FAILURES.labels(rule="query_too_long").inc()
            logger.warning({"event": "kql_validation_failed", "file": file_path, "rule": "query_too_long", "message": "Query exceeds 10KB"})
            return False, "Query exceeds 10KB"

        # Basic tokenizer for syntax checking
        def check_balanced_parentheses(query: str) -> bool:
            count = 0
            for char in query:
                if char == '(': count += 1
                elif char == ')': count -= 1
                if count < 0: return False
            return count == 0

        rules = {
            "valid_start": {
                "pattern": r'^\s*(let|union|\w+\s*(\||\s|$))',
                "message": "Query must start with 'let', 'union', or a table reference"
            },
            "time_filter": {
                "pattern": r'TimeGenerated\s*[>=]\s*ago\s*\(\w+\)',
                "message": "Query must include a time filter (e.g., TimeGenerated > ago(1d))"
            },
            "no_deprecated": {
                "pattern": r'\bsearch\b|\bwhere\s*\*\s*contains\b',
                "message": "Query contains deprecated operators (search or where * contains)"
            },
            "valid_table": {
                "pattern": r'^\s*\w+\s*\|',
                "message": "Query must reference a valid table"
            },
            "no_malicious": {
                "pattern": r'(\bexecute\b|\bpowershell\b|\bscript\b)',
                "message": "Query contains potentially malicious patterns"
            }
        }

        if not check_balanced_parentheses(query):
            KQL_VALIDATION_FAILURES.labels(rule="unbalanced_parentheses").inc()
            logger.warning({"event": "kql_validation_failed", "file": file_path, "rule": "unbalanced_parentheses", "message": "Unbalanced parentheses"})
            return False, "Unbalanced parentheses"

        for rule_name, rule in rules.items():
            if rule_name == "valid_table" and not re.search(rules["valid_start"]["pattern"], query, re.IGNORECASE):
                continue  # Skip if query doesn't start with a table
            if rule_name == "no_malicious":
                if re.search(rule["pattern"], query, re.IGNORECASE):
                    KQL_VALIDATION_FAILURES.labels(rule=rule_name).inc()
                    logger.warning({"event": "kql_validation_failed", "file": file_path, "rule": rule_name, "message": rule["message"]})
                    return False, rule["message"]
            else:
                if not re.search(rule["pattern"], query, re.IGNORECASE):
                    KQL_VALIDATION_FAILURES.labels(rule=rule_name).inc()
                    logger.warning({"event": "kql_validation_failed", "file": file_path, "rule": rule_name, "message": rule["message"]})
                    return False, rule["message"]

        lines = query.split('\n')
        has_where = any(re.search(r'\bwhere\b', line, re.IGNORECASE) for line in lines[:5])
        if not has_where:
            logger.warning({"event": "kql_performance_warning", "file": file_path, "message": "No early where clause detected"})

        has_limit = re.search(r'\b(top|limit)\b', query, re.IGNORECASE)
        if not has_limit:
            logger.warning({"event": "kql_performance_warning", "file": file_path, "message": "No top/limit clause detected"})

        KQL_VALIDATION_SUCCESS.labels(rule="all").inc()
        logger.info({"event": "kql_validation_success", "file": file_path})
        return True, "Valid KQL query"

    def parse_kql_file(self, file_path: str) -> Tuple[Dict, str, Dict]:
        """Parse and validate KQL file with multi-line metadata support."""
        file_path = os.path.abspath(file_path)
        if len(file_path) > 1024:
            METADATA_PARSING_ERRORS.labels(file=file_path).inc()
            logger.error({"event": "invalid_file_path", "file": file_path, "error": "Path too long"})
            raise ValueError("File path too long")

        if file_path in self.kql_cache:
            CACHE_HITS.inc()
            logger.debug({"event": "cache_hit", "file": file_path})
            return self.kql_cache[file_path]

        CACHE_MISSES.inc()
        metadata = {"displayName": None, "description": "", "source_file": file_path}
        tags = {}
        query_lines = []
        metadata_regex = re.compile(r'//\s*(?P<key>[A-Za-z\s]+):\s*(?P<value>.*)')
        in_metadata_section = True
        metadata_size = 0
        max_metadata_size = 1024
        current_key = None

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line_stripped = line.strip()
                    metadata_size += len(line_stripped)
                    if metadata_size > max_metadata_size:
                        METADATA_PARSING_ERRORS.labels(file=file_path).inc()
                        logger.error({"event": "metadata_too_large", "file": file_path, "error": "Metadata exceeds 1KB"})
                        raise ValueError("Metadata exceeds 1KB limit")

                    if in_metadata_section and not line_stripped.startswith('//') and line_stripped:
                        in_metadata_section = False
                    if in_metadata_section and line_stripped.startswith('//'):
                        match = metadata_regex.match(line_stripped)
                        if match:
                            current_key = match.group('key').strip().lower()
                            value = html.escape(match.group('value').strip())
                            if len(value) > 512:
                                METADATA_PARSING_ERRORS.labels(file=file_path).inc()
                                logger.error({"event": "invalid_metadata", "file": file_path, "key": current_key, "error": "Metadata value too long"})
                                raise ValueError(f"Metadata value for {current_key} too long")
                            if current_key == 'name':
                                metadata['displayName'] = value
                            elif current_key == 'description':
                                metadata['description'] = value
                            else:
                                tags[current_key] = [v.strip() for v in value.split(',') if len(v.strip()) <= 128]
                        elif current_key and line_stripped.startswith('//'):
                            # Continue previous metadata key (multi-line)
                            value = html.escape(line_stripped[2:].strip())
                            if len(value) > 512:
                                METADATA_PARSING_ERRORS.labels(file=file_path).inc()
                                logger.error({"event": "invalid_metadata", "file": file_path, "key": current_key, "error": "Metadata continuation line too long"})
                                raise ValueError(f"Metadata continuation line for {current_key} too long")
                            if current_key == 'description':
                                metadata['description'] += ' ' + value
                            elif current_key in tags:
                                tags[current_key].append(value)
                            else:
                                metadata['description'] += (' ' + value) if metadata['description'] else value
                        else:
                            # General comment, append to description
                            desc_line = html.escape(line_stripped[2:].strip())
                            if len(desc_line) > 512:
                                METADATA_PARSING_ERRORS.labels(file=file_path).inc()
                                logger.error({"event": "invalid_metadata", "file": file_path, "error": "Description line too long"})
                                raise ValueError("Description line too long")
                            metadata['description'] += (' ' + desc_line) if metadata['description'] else desc_line
                    else:
                        query_lines.append(html.escape(line))
            query = ''.join(query_lines).strip()
            is_valid, validation_message = self.validate_kql_query(query, file_path)
            if not is_valid:
                raise ValueError(validation_message)
            self.kql_cache[file_path] = (metadata, query, tags)
            logger.info({"event": "file_parsed", "file": file_path})
            return metadata, query, tags
        except (IOError, UnicodeDecodeError) as e:
            METADATA_PARSING_ERRORS.labels(file=file_path).inc()
            logger.error({"event": "file_io_error", "file": file_path, "error": str(e)})
            raise

    def create_query_resource_json(self, metadata: Dict, query: str, tags: Dict) -> Dict:
        """Construct JSON payload for a query resource."""
        display_name = metadata.get('displayName') or re.sub(
            r'[^a-zA-Z0-9\s-]', '', os.path.splitext(os.path.basename(metadata['source_file']))[0]
        ).replace('-', ' ').replace('_', ' ').title()

        return {
            "type": "queries",
            "apiVersion": "2025-02-01",
            "name": str(uuid.uuid4()),
            "dependsOn": [f"[resourceId('Microsoft.OperationalInsights/queryPacks', '{self.config['query_pack_name']}')]"],
            "properties": {
                "displayName": display_name,
                "description": metadata.get('description') or "No description provided.",
                "body": query,
                "related": {
                    "categories": [self.saved_search_category],
                    "resourceTypes": ["Microsoft.Security/securitySolutions"]
                },
                "tags": tags
            }
        }

    def create_arm_template(self, query_resource: Dict) -> Dict:
        """Construct ARM template for a query resource."""
        return {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": [{
                "type": "Microsoft.OperationalInsights/queryPacks",
                "apiVersion": "2025-02-01",
                "name": self.config["query_pack_name"],
                "location": self.config["location"],
                "properties": {},
                "resources": [query_resource]
            }]
        }

    @retry((HttpResponseError, Exception), tries=3, delay=2, backoff=2, exceptions_to_check=(lambda e: getattr(e, 'status_code', None) == 429))
    def check_or_create_workspace(self) -> bool:
        """Check or create Log Analytics workspace with retry for throttling."""
        with PIPELINE_DURATION.labels(stage="workspace_setup").time():
            try:
                self.log_analytics_client.workspaces.get(self.config["resource_group_name"], self.config["workspace_name"])
                logger.info({"event": "workspace_found", "workspace": self.config["workspace_name"]})
                return True
            except HttpResponseError as e:
                if e.status_code == 404:
                    logger.info({"event": "workspace_not_found", "workspace": self.config["workspace_name"], "action": "creating"})
                    if not self.resource_client.resource_groups.check_existence(self.config["resource_group_name"]):
                        self.resource_client.resource_groups.create_or_update(
                            self.config["resource_group_name"], {'location': self.config["location"]}
                        )
                    workspace_info = {'location': self.config["location"], 'sku': {'name': 'PerGB2018'}}
                    creation_poller = self.log_analytics_client.workspaces.begin_create_or_update(
                        self.config["resource_group_name"], self.config["workspace_name"], workspace_info
                    )
                    creation_poller.result()
                    logger.info({"event": "workspace_created", "workspace": self.config["workspace_name"]})
                    return True
                if e.status_code == 429:
                    logger.warning({"event": "workspace_check_throttled", "error": str(e)})
                    raise
                logger.error({"event": "workspace_check_failed", "error": str(e)})
                raise

    @retry((HttpResponseError, Exception), tries=3, delay=2, backoff=2, exceptions_to_check=(lambda e: getattr(e, 'status_code', None) == 429))
    def import_query(self, json_file_path: str) -> bool:
        """Import a single JSON query into Sentinel with retry for throttling."""
        with PIPELINE_DURATION.labels(stage="query_import").time():
            try:
                with open(json_file_path, 'r', encoding='utf-8') as file:
                    saved_search_payload = json.load(file)
                properties = saved_search_payload['resources'][0]['resources'][0]['properties']
                properties['category'] = self.saved_search_category
                properties['version'] = self.saved_search_version
                display_name = properties['displayName']
                query_type = re.sub(r'[^a-zA-Z0-9]', '', display_name.lower())[:60]
                saved_search_id = query_type or f"savedsearch-{str(uuid.uuid4())[:8]}"

                self.log_analytics_client.saved_searches.create_or_update(
                    resource_group_name=self.config["resource_group_name"],
                    workspace_name=self.config["workspace_name"],
                    saved_search_id=saved_search_id,
                    parameters=properties
                )
                PIPELINE_SUCCESS.labels(query_type=query_type).inc()
                logger.info({"event": "query_imported", "query": display_name, "category": self.saved_search_category})
                return True
            except (IOError, json.JSONDecodeError) as e:
                PIPELINE_FAILURES.labels(query_type=query_type).inc()
                logger.error({"event": "query_import_failed", "file": json_file_path, "error": str(e)})
                return False

    def process_directory(self, input_dir: str) -> List[str]:
        """Process KQL files in directory with batching."""
        with PIPELINE_DURATION.labels(stage="kql_processing").time():
            os.makedirs(self.import_dir, exist_ok=True)
            json_files = []
            kql_files = [
                os.path.join(root, file_name)
                for root, _, files in os.walk(input_dir)
                for file_name in files if file_name.endswith('.kql')
            ]

            def process_file(kql_file_path: str):
                try:
                    metadata, query, tags = self.parse_kql_file(kql_file_path)
                    query_resource = self.create_query_resource_json(metadata, query, tags)
                    arm_template = self.create_arm_template(query_resource)
                    output_filename = re.sub(r'[^a-zA-Z0-9\s-]', '', query_resource['properties']['displayName']).replace(' ', '-')
                    output_path = os.path.join(self.import_dir, f"{output_filename}.json")
                    with open(output_path, 'w', encoding='utf-8') as f:
                        json.dump(arm_template, f, indent=2)
                    QUERIES_PROCESSED.inc()
                    logger.info({"event": "file_converted", "input": kql_file_path, "output": output_path})
                    return output_path
                except Exception as e:
                    logger.error({"event": "file_processing_error", "file": kql_file_path, "error": str(e)})
                    return None

            for i in range(0, len(kql_files), self.batch_size):
                batch = kql_files[i:i + self.batch_size]
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    futures = [executor.submit(process_file, kql_file) for kql_file in batch]
                    json_files.extend([f.result() for f in as_completed(futures) if f.result()])

            return json_files

    @PIPELINE_DURATION.labels(stage="full_pipeline").time()
    def run(self, input_dir: str = '.'):
        """Execute the pipeline."""
        try:
            if not self.check_or_create_workspace():
                logger.critical({"event": "pipeline_failed", "error": "Workspace setup failed"})
                return
            json_files = self.process_directory(input_dir)
            if not json_files:
                logger.warning({"event": "no_files_processed", "directory": input_dir})
                return
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = [executor.submit(self.import_query, json_file) for json_file in json_files]
                successes = sum(1 for f in as_completed(futures) if f.result())
            logger.info({"event": "pipeline_completed", "successes": successes, "total": len(json_files)})
        except Exception as e:
            logger.critical({"event": "pipeline_failed", "error": str(e)})

if __name__ == "__main__":
    prom.start_http_server(8000)
    config = {
        key: os.getenv(key) for key in [
            "SUBSCRIPTION_ID", "RESOURCE_GROUP_NAME", "WORKSPACE_NAME",
            "AZURE_LOCATION", "QUERY_PACK_NAME"
        ]
    }
    config["location"] = config.get("AZURE_LOCATION", "eastus2")
    config["query_pack_name"] = config.get("QUERY_PACK_NAME", "DefaultQueryPack")
    pipeline = SentinelPipeline(config)
    pipeline.run()