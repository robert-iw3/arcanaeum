import os
import re
import json
import argparse
import logging
from pathlib import Path
import uuid
from typing import Dict, List, Optional
import gzip
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import yaml
import charset_normalizer
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from tenacity import retry, stop_after_attempt, wait_exponential
import html
from urllib.parse import urlparse
try:
    from elasticsearch import Elasticsearch
    ELASTICSEARCH_AVAILABLE = True
except ImportError:
    ELASTICSEARCH_AVAILABLE = False

# ECS field sets and fields (based on ECS 9.1.0)
ECS_FIELDS = {
    # Base field set
    '@timestamp', 'ecs.version', 'message', 'tags', 'labels',
    # Event field set
    'event.action', 'event.category', 'event.code', 'event.created', 'event.dataset',
    'event.duration', 'event.end', 'event.hash', 'event.id', 'event.ingested',
    'event.kind', 'event.module', 'event.original', 'event.outcome', 'event.provider',
    'event.reference', 'event.risk_score', 'event.sequence', 'event.severity', 'event.start',
    'event.timezone', 'event.type',
    # Host field set
    'host.architecture', 'host.hostname', 'host.id', 'host.ip', 'host.mac',
    'host.name', 'host.os.family', 'host.os.full', 'host.os.kernel', 'host.os.name',
    'host.os.platform', 'host.os.type', 'host.os.version', 'host.type',
    # Source field set
    'source.ip', 'source.port', 'source.mac', 'source.address', 'source.bytes',
    'source.packets', 'source.domain', 'source.geo.city_name', 'source.geo.continent_name',
    'source.geo.country_name', 'source.geo.region_name', 'source.geo.location',
    # Destination field set
    'destination.ip', 'destination.port', 'destination.mac', 'destination.address',
    'destination.bytes', 'destination.packets', 'destination.domain', 'destination.geo.city_name',
    'destination.geo.continent_name', 'destination.geo.country_name', 'destination.geo.region_name',
    'destination.geo.location',
    # Network field set
    'network.bytes', 'network.community_id', 'network.direction', 'network.iana_number',
    'network.name', 'network.packets', 'network.protocol', 'network.transport', 'network.type',
    # Process field set
    'process.args', 'process.executable', 'process.name', 'process.pid', 'process.ppid',
    'process.start', 'process.thread.id', 'process.title', 'process.working_directory',
    # User field set
    'user.id', 'user.name', 'user.full_name', 'user.email', 'user.group.id', 'user.group.name',
    # HTTP field set
    'http.request.method', 'http.request.referrer', 'http.response.status_code',
    'http.response.body.bytes', 'http.version',
    # URL field set
    'url.domain', 'url.path', 'url.query', 'url.scheme', 'url.port',
    # Winlog field set
    'winlog.event_id', 'winlog.channel', 'winlog.event_data.*', 'winlog.computer_name',
    'winlog.opcode', 'winlog.task', 'winlog.user.name',
    # TLS field set
    'tls.server_name', 'tls.version', 'tls.cipher',
    # Additional field sets (partial)
    'agent.id', 'agent.name', 'agent.type', 'agent.version', 'container.id', 'container.image.name',
    'container.name', 'file.name', 'file.path', 'file.size', 'log.level', 'log.logger'
}

# Common non-ECS to ECS field mappings
FIELD_MAPPINGS = {
    'hostname': 'host.name',
    'host': 'host.name',
    'server': 'host.name',
    'client_ip': 'source.ip',
    'src_ip': 'source.ip',
    'source_ip': 'source.ip',
    'dst_ip': 'destination.ip',
    'dest_ip': 'destination.ip',
    'destination_ip': 'destination.ip',
    'src_port': 'source.port',
    'dst_port': 'destination.port',
    'username': 'user.name',
    'user': 'user.name',
    'event_id': 'winlog.event_id',
    'channel': 'winlog.channel',
    'method': 'http.request.method',
    'status_code': 'http.response.status_code',
    'referrer': 'http.request.referrer',
    'bytes': 'network.bytes',
    'protocol': 'network.protocol',
    'action': 'event.action',
    'category': 'event.category',
    'timestamp': '@timestamp',
    'event_time': 'event.created',
    'computer_name': 'winlog.computer_name',
    'process_name': 'process.name',
    'pid': 'process.pid',
    'ppid': 'process.ppid'
}

# ECS data types for validation
ECS_DATA_TYPES = {
    '@timestamp': 'date',
    'ecs.version': 'keyword',
    'message': 'text',
    'tags': 'keyword',
    'labels': 'object',
    'event.action': 'keyword',
    'event.category': 'keyword',
    'event.code': 'keyword',
    'event.original': 'text',
    'host.name': 'keyword',
    'source.ip': 'ip',
    'destination.ip': 'ip',
    'source.port': 'long',
    'destination.port': 'long',
    'user.name': 'keyword',
    'winlog.event_id': 'keyword',
    'winlog.channel': 'keyword',
    'http.request.method': 'keyword',
    'http.response.status_code': 'long',
    'network.bytes': 'long',
    'network.protocol': 'keyword'
}

# MITRE ATT&CK matrices
MITRE_MATRICES = {
    'enterprise': 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json',
    'mobile': 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json',
    'ics': 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json'
}

# Cache for MITRE ATT&CK data
MITRE_CACHE = {}

def fetch_mitre_data(matrix: str) -> Dict:
    """Fetch and cache MITRE ATT&CK data for a given matrix."""
    if matrix not in MITRE_MATRICES:
        logging.warning(f"Invalid MITRE matrix: {matrix}. Supported: {list(MITRE_MATRICES.keys())}")
        return {}

    if matrix in MITRE_CACHE:
        return MITRE_CACHE[matrix]

    try:
        session = create_session_with_retries()
        response = session.get(MITRE_MATRICES[matrix], timeout=10)
        response.raise_for_status()
        data = response.json()
        MITRE_CACHE[matrix] = data
        return data
    except Exception as e:
        logging.error(f"Failed to fetch MITRE {matrix} data: {e}")
        return {}

def get_mitre_tactic(matrix: str, tactic_id: str) -> Optional[Dict]:
    """Get tactic details from MITRE ATT&CK data."""
    data = fetch_mitre_data(matrix)
    if not data:
        return None

    for obj in data.get('objects', []):
        if obj.get('type') == 'x-mitre-tactic' and obj.get('x_mitre_shortname') == tactic_id:
            return {
                'id': tactic_id,
                'name': obj.get('name', 'Unknown Tactic'),
                'reference': obj.get('external_references', [{}])[0].get('url', f"https://attack.mitre.org/tactics/{tactic_id}/")
            }
    return None

def get_mitre_technique(matrix: str, technique_id: str) -> Optional[Dict]:
    """Get technique details from MITRE ATT&CK data."""
    data = fetch_mitre_data(matrix)
    if not data:
        return None

    for obj in data.get('objects', []):
        if obj.get('type') == 'attack-pattern' and obj.get('external_references', [{}])[0].get('external_id') == technique_id:
            return {
                'id': technique_id,
                'name': obj.get('name', 'Unknown Technique'),
                'reference': obj.get('external_references', [{}])[0].get('url', f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/")
            }
    return None

def setup_logging(verbose: bool = False) -> None:
    """Set up logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s',
        level=level,
        handlers=[
            logging.FileHandler('import/final/pipeline.log'),
            logging.StreamHandler()
        ]
    )

def load_config(config_path: str) -> Dict:
    """Load configuration from YAML file."""
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f) or {}
            return config
        return {}
    except Exception as e:
        logging.error(f"Error loading config file '{config_path}': {e}")
        return {}

def validate_url(url: str) -> bool:
    """Validate API endpoint URL."""
    try:
        parsed = urlparse(url)
        return all([parsed.scheme in ('http', 'https'), parsed.netloc])
    except Exception:
        return False

def validate_esql_query(query: str) -> bool:
    """Validate if the ESQL query adheres to ECS schema and syntax."""
    try:
        fields = set(re.findall(r'\b(?:\w+\.)+\w+\b', query))
        ecs_valid = all(field in ECS_FIELDS or field.startswith('winlog.event_data.') or field.startswith('labels.') for field in fields)
        syntax_valid = (
            re.match(r'^\s*from\s+\S+', query, re.IGNORECASE) and
            '|' in query and
            any(keyword in query.lower() for keyword in ['where', 'eval', 'stats', 'keep'])
        )
        return ecs_valid and syntax_valid
    except Exception as e:
        logging.error(f"Error validating ESQL query: {e}")
        return False

def fix_esql_query(query: str) -> Dict:
    """Transform non-ECS compliant fields to ECS schema and preserve original query."""
    original_query = query
    modified_query = query

    # Apply direct field mappings
    for non_ecs, ecs_field in FIELD_MAPPINGS.items():
        modified_query = re.sub(rf'\b{re.escape(non_ecs)}\b(?=\s*=\s*|\s*LIKE\s*|\s*IN\s*|\s*IS\s*)', ecs_field, modified_query, flags=re.IGNORECASE)

    # Keyword-based transformation for unmapped fields
    fields = set(re.findall(r'\b(?:\w+\.)+\w+\b', modified_query))
    for field in fields:
        if field not in ECS_FIELDS and not field.startswith('winlog.event_data.') and not field.startswith('labels.'):
            last_part = field.split('.')[-1].lower()
            # Map based on common keywords
            if 'ip' in last_part:
                if 'src' in field.lower() or 'source' in field.lower():
                    modified_query = re.sub(rf'\b{re.escape(field)}\b', 'source.ip', modified_query)
                elif 'dst' in field.lower() or 'dest' in field.lower() or 'destination' in field.lower():
                    modified_query = re.sub(rf'\b{re.escape(field)}\b', 'destination.ip', modified_query)
                else:
                    modified_query = re.sub(rf'\b{re.escape(field)}\b', f'labels.{field}', modified_query)
            elif 'port' in last_part:
                if 'src' in field.lower() or 'source' in field.lower():
                    modified_query = re.sub(rf'\b{re.escape(field)}\b', 'source.port', modified_query)
                elif 'dst' in field.lower() or 'dest' in field.lower() or 'destination' in field.lower():
                    modified_query = re.sub(rf'\b{re.escape(field)}\b', 'destination.port', modified_query)
                else:
                    modified_query = re.sub(rf'\b{re.escape(field)}\b', f'labels.{field}', modified_query)
            elif 'user' in last_part or 'username' in last_part:
                modified_query = re.sub(rf'\b{re.escape(field)}\b', 'user.name', modified_query)
            elif 'host' in last_part or 'hostname' in last_part:
                modified_query = re.sub(rf'\b{re.escape(field)}\b', 'host.name', modified_query)
            else:
                # Fallback to custom labels
                modified_query = re.sub(rf'\b{re.escape(field)}\b', f'labels.{field}', modified_query)

    # Validate transformed fields' data types
    fields = set(re.findall(r'\b(?:\w+\.)+\w+\b', modified_query))
    for field in fields:
        if field in ECS_DATA_TYPES:
            # Placeholder for data type validation (requires query value analysis, not implemented here)
            pass

    return {
        'query': modified_query,
        'original_query': original_query
    }

def validate_mitre_id(tactic_id: str, is_technique: bool = False) -> bool:
    """Validate MITRE ATT&CK tactic or technique ID format."""
    if is_technique:
        return bool(re.match(r'^T[0-9]{4}(\.[0-9]{3})?$', tactic_id))
    return bool(re.match(r'^TA[0-9]{4}$', tactic_id))

def extract_metadata_from_markdown(content: str, file_path: Path) -> Dict:
    """Extract rule metadata from markdown frontmatter or headers."""
    metadata = {
        "name": f"ESQL Rule from {file_path.name}",
        "description": f"Auto-generated ESQL rule from {file_path.name}",
        "severity": "medium",
        "tags": ["Auto-generated", "ESQL"],
        "threat": []
    }

    frontmatter_match = re.match(r'^---\n(.*?)\n---\n', content, re.DOTALL)
    matrix = 'enterprise'  # Default matrix
    if frontmatter_match:
        try:
            frontmatter = yaml.safe_load(frontmatter_match.group(1))
            metadata.update({
                "name": frontmatter.get("name", metadata["name"]),
                "description": frontmatter.get("description", metadata["description"]),
                "severity": frontmatter.get("severity", metadata["severity"]),
                "tags": frontmatter.get("tags", metadata["tags"])
            })
            matrix = frontmatter.get("matrix", "enterprise").lower()
            if matrix not in MITRE_MATRICES:
                logging.warning(f"Invalid MITRE matrix '{matrix}' in {file_path}. Defaulting to 'enterprise'.")
                matrix = 'enterprise'
            # Parse MITRE ATT&CK threat information
            if "tactics" in frontmatter:
                threat = []
                for tactic in frontmatter.get("tactics", []):
                    tactic_id = tactic.get("id")
                    if not tactic_id or not validate_mitre_id(tactic_id):
                        logging.warning(f"Invalid MITRE tactic ID '{tactic_id}' in {file_path}")
                        continue
                    tactic_data = get_mitre_tactic(matrix, tactic_id)
                    if not tactic_data:
                        logging.warning(f"MITRE tactic '{tactic_id}' not found in {matrix} matrix for {file_path}")
                        continue
                    tactic_entry = {
                        "framework": "MITRE ATT&CK",
                        "tactic": tactic_data,
                        "technique": []
                    }
                    for technique in tactic.get("techniques", []):
                        technique_id = technique.get("id")
                        if not technique_id or not validate_mitre_id(technique_id, is_technique=True):
                            logging.warning(f"Invalid MITRE technique ID '{technique_id}' in {file_path}")
                            continue
                        technique_data = get_mitre_technique(matrix, technique_id)
                        if technique_data:
                            tactic_entry["technique"].append(technique_data)
                        else:
                            logging.warning(f"MITRE technique '{technique_id}' not found in {matrix} matrix for {file_path}")
                    if tactic_entry["technique"] or not tactic.get("techniques"):
                        threat.append(tactic_entry)
                metadata["threat"] = threat
        except Exception as e:
            logging.warning(f"Error parsing frontmatter in {file_path}: {e}")

    if not frontmatter_match or not metadata["threat"]:
        # Try parsing from markdown headers
        threat_section = re.search(r'^##+\s+MITRE ATT&CK\s*\n+(.+?)(?:\n##|$)', content, re.MULTILINE | re.DOTALL)
        if threat_section:
            threat_content = threat_section.group(1).strip()
            matrix_match = re.search(r'- Matrix: (\w+)', threat_content)
            if matrix_match:
                matrix = matrix_match.group(1).lower()
                if matrix not in MITRE_MATRICES:
                    logging.warning(f"Invalid MITRE matrix '{matrix}' in {file_path}. Defaulting to 'enterprise'.")
                    matrix = 'enterprise'
            tactic_matches = re.findall(r'- Tactic: (TA[0-9]{4})(?:, Techniques: (T[0-9]{4}(?:\.[0-9]{3})?(?:,\s*T[0-9]{4}(?:\.[0-9]{3})?)*))?', threat_content)
            threat = []
            for tactic_id, techniques_str in tactic_matches:
                if not validate_mitre_id(tactic_id):
                    logging.warning(f"Invalid MITRE tactic ID '{tactic_id}' in {file_path}")
                    continue
                tactic_data = get_mitre_tactic(matrix, tactic_id)
                if not tactic_data:
                    logging.warning(f"MITRE tactic '{tactic_id}' not found in {matrix} matrix for {file_path}")
                    continue
                tactic_entry = {
                    "framework": "MITRE ATT&CK",
                    "tactic": tactic_data,
                    "technique": []
                }
                if techniques_str:
                    technique_ids = [tid.strip() for tid in techniques_str.split(',') if tid.strip()]
                    for technique_id in technique_ids:
                        if not validate_mitre_id(technique_id, is_technique=True):
                            logging.warning(f"Invalid MITRE technique ID '{technique_id}' in {file_path}")
                            continue
                        technique_data = get_mitre_technique(matrix, technique_id)
                        if technique_data:
                            tactic_entry["technique"].append(technique_data)
                        else:
                            logging.warning(f"MITRE technique '{technique_id}' not found in {matrix} matrix for {file_path}")
                threat.append(tactic_entry)
            metadata["threat"] = threat

    return metadata

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
def extract_esql_from_markdown(file_path: Path) -> List[Dict]:
    """Extract ESQL queries from markdown files within ```sql``` blocks."""
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read()
            if not raw_data:
                logging.warning(f"File {file_path} is empty")
                return []
            detected = charset_normalizer.detect(raw_data)
            encoding = detected['encoding'] or 'utf-8'

        with open(file_path, 'r', encoding=encoding) as f:
            content = html.escape(f.read(1024*1024))  # Limit to 1MB chunks

        metadata = extract_metadata_from_markdown(content, file_path)
        sql_blocks = re.findall(r'```sql\n(.*?)```', content, re.DOTALL)
        rules = []

        for query in sql_blocks:
            query = query.strip()
            if not query:
                continue

            if not validate_esql_query(query):
                logging.warning(f"Non-ECS compliant query in {file_path}. Attempting to fix.")
                query_data = fix_esql_query(query)
                query = query_data['query']
                original_query = query_data['original_query']
            else:
                original_query = query

            rule_id = str(uuid.uuid4())
            rule = {
                "rule_id": rule_id,
                "name": metadata["name"],
                "description": metadata["description"],
                "severity": metadata["severity"],
                "enabled": True,
                "language": "esql",
                "query": query.strip(),
                "type": "esql",
                "threat": metadata["threat"] or [],
                "interval": "5m",
                "from": "now-5m",
                "max_signals": 100,
                "risk_score": 50,
                "output_index": ".alerts-security.alerts-default",
                "meta": {
                    "original_query": original_query
                },
                "version": 1,
                "references": [],
                "tags": metadata["tags"],
                "actions": [],
                "throttle": "no_throttle",
                "custom_query_fields": [],
                "event_group": "",
                "ecs_version": "9.1.0"
            }
            rules.append(rule)

        return rules
    except Exception as e:
        logging.error(f"Error processing markdown file {file_path}: {e}")
        return []

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
def process_markdown_file(file_path: Path, output_dir: Path) -> bool:
    """Process a single markdown file and save as JSON."""
    rules = extract_esql_from_markdown(file_path)
    if not rules:
        logging.warning(f"No valid ESQL queries found in {file_path}")
        return False

    output_dir.mkdir(parents=True, exist_ok=True)
    for rule in rules:
        output_file = output_dir / f"{rule['rule_id']}.json"
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(rule, f, indent=2, ensure_ascii=False)
            logging.info(f"Saved rule {rule['rule_id']} to {output_file}")
        except Exception as e:
            logging.error(f"Error saving JSON for rule {rule['rule_id']}: {e}")
            return False
    return True

def create_session_with_retries(retries: int = 3) -> requests.Session:
    """Create a requests session with retry logic."""
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=0.3,
        status_forcelist=(429, 500, 502, 503, 504)
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def import_to_kibana(file_path: Path, filename: str, api_endpoint: str, api_key: str, ca_cert_path: Optional[str] = None, overwrite: bool = False, batch_size: Optional[int] = None) -> bool:
    """Import NDJSON file to Kibana with mandatory TLS certificate verification."""
    if not validate_url(api_endpoint):
        logging.error(f"Invalid Kibana URL: {api_endpoint}")
        return False

    logging.info(f"Importing file to Kibana: {filename}")
    if not file_path.exists():
        logging.error(f"File '{filename}' not found.")
        return False

    is_compressed = str(file_path).endswith('.gz')
    open_func = gzip.open if is_compressed else open

    try:
        session = create_session_with_retries()
        verify = ca_cert_path if ca_cert_path and os.path.exists(ca_cert_path) else True
        if ca_cert_path and not os.path.exists(ca_cert_path):
            logging.warning(f"CA certificate path {ca_cert_path} does not exist; falling back to default verification.")

        if batch_size:
            records = []
            with open_func(file_path, 'rt', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        records.append(line)
                        if len(records) >= batch_size:
                            files = {'file': ('batch.ndjson', '\n'.join(records).encode('utf-8'), 'application/x-ndjson')}
                            headers = {"Authorization": f"ApiKey {api_key}", "kbn-xsrf": "true"}
                            params = {'overwrite': 'true'} if overwrite else {}
                            response = session.post(api_endpoint, headers=headers, files=files, params=params, verify=verify)
                            response.raise_for_status()
                            logging.debug(f"Batch of {len(records)} records sent successfully.")
                            records = []
                if records:
                    files = {'file': ('batch.ndjson', '\n'.join(records).encode('utf-8'), 'application/x-ndjson')}
                    response = session.post(api_endpoint, headers=headers, files=files, params=params, verify=verify)
                    response.raise_for_status()
        else:
            with open_func(file_path, 'rb') as f:
                files = {'file': (filename, f, 'application/x-ndjson')}
                headers = {"Authorization": f"ApiKey {api_key}", "kbn-xsrf": "true"}
                params = {'overwrite': 'true'} if overwrite else {}
                response = session.post(api_endpoint, headers=headers, files=files, params=params, verify=verify)
                response.raise_for_status()

        logging.info(f"Successfully imported {filename}. Response: {response.json()}")
        return True
    except requests.exceptions.SSLError as err:
        logging.error(f"SSL verification error importing {filename}: {err}. Ensure valid CA certificate is provided via --ca-cert-path or CA_CERT_PATH.")
        return False
    except requests.exceptions.HTTPError as err:
        logging.error(f"HTTP Error importing {filename}: {err}")
        try:
            logging.error(f"Response content: {response.json()}")
        except ValueError:
            logging.error(f"Response content: {response.text}")
        return False
    except requests.exceptions.RequestException as err:
        logging.error(f"Error importing {filename}: {err}")
        return False

def import_to_elasticsearch(file_path: Path, filename: str, es_client: Elasticsearch, index: str, batch_size: Optional[int] = None) -> bool:
    """Import NDJSON file to Elasticsearch."""
    if not ELASTICSEARCH_AVAILABLE:
        logging.error("Elasticsearch library not installed. Install with `pip install elasticsearch`.")
        return False

    logging.info(f"Importing file to Elasticsearch: {filename}")
    if not file_path.exists():
        logging.error(f"File '{filename}' not found.")
        return False

    is_compressed = str(file_path).endswith('.gz')
    open_func = gzip.open if is_compressed else open

    try:
        if batch_size:
            records = []
            with open_func(file_path, 'rt', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        record = json.loads(line)
                        records.append({"index": {"_index": index}, "source": record})
                        if len(records) >= batch_size:
                            response = es_client.bulk(body=[item for pair in records for item in pair])
                            if response['errors']:
                                logging.error(f"Error in bulk import: {response}")
                                return False
                            logging.debug(f"Batch of {len(records)} records sent successfully.")
                            records = []
                if records:
                    response = es_client.bulk(body=[item for pair in records for item in pair])
                    if response['errors']:
                        logging.error(f"Error in bulk import: {response}")
                        return False
        else:
            with open_func(file_path, 'rt', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        record = json.loads(line)
                        es_client.index(index=index, body=record)

        logging.info(f"Successfully imported {filename} to Elasticsearch.")
        return True
    except Exception as e:
        logging.error(f"Error importing {filename} to Elasticsearch: {e}")
        return False

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
def merge_to_ndjson(input_dir: Path, output_dir: Path, output_filename: str = "combined_esql_rules.ndjson", compress: bool = False, max_workers: int = 1) -> bool:
    """Merge JSON rules into a single NDJSON file."""
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file_path = output_dir / (f"{output_filename}.gz" if compress else output_filename)

    json_files = sorted([f for f in input_dir.glob("*.json") if f.is_file()])
    if not json_files:
        logging.warning(f"No JSON files found in {input_dir}")
        return False

    open_func = gzip.open if compress else open
    lock = threading.Lock()

    with open_func(output_file_path, 'wt', encoding='utf-8') as outfile:
        if max_workers > 1:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_file = {executor.submit(process_json_file, f): f for f in json_files}
                for future in as_completed(future_to_file):
                    result = future.result()
                    if result:
                        with lock:
                            outfile.write(result)
        else:
            for json_file in json_files:
                result = process_json_file(json_file)
                if result:
                    outfile.write(result)

    logging.info(f"Created NDJSON file at {output_file_path}")
    return validate_ndjson(output_file_path, compress)

def process_json_file(json_file: Path) -> Optional[str]:
    """Process a single JSON file to NDJSON line."""
    try:
        with open(json_file, 'rb') as f:
            raw_data = f.read()
            if not raw_data:
                logging.warning(f"File '{json_file}' is empty. Skipping.")
                return None
            detected = charset_normalizer.detect(raw_data)
            encoding = detected['encoding'] or 'utf-8'
        with open(json_file, 'r', encoding=encoding) as infile:
            data = json.load(infile)
        return json.dumps(data, separators=(',', ':'), ensure_ascii=False) + '\n'
    except Exception as e:
        logging.error(f"Error processing JSON file {json_file}: {e}")
        return None

def validate_ndjson(file_path: Path, is_compressed: bool = False) -> bool:
    """Validate NDJSON file format."""
    open_func = gzip.open if is_compressed else open
    i = 0
    try:
        with open_func(file_path, 'rt', encoding='utf-8') as f:
            for i, line in enumerate(f, 1):
                if line.strip():
                    json.loads(line)
        logging.info(f"NDJSON file '{file_path}' is valid.")
        return True
    except json.JSONDecodeError as e:
        logging.error(f"Invalid NDJSON in '{file_path}' at line {i}: {e}")
        return False
    except Exception as e:
        logging.error(f"Error validating NDJSON file '{file_path}': {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Process markdown files with ESQL queries and generate NDJSON for Kibana/Elasticsearch.")
    parser.add_argument('--base-dir', default=os.getcwd(), help="Base directory to search for markdown files")
    parser.add_argument('--rules-dir', default="import/rules-editing", help="Directory for JSON rule files")
    parser.add_argument('--output-dir', default="import/final", help="Directory for final NDJSON file")
    parser.add_argument('--output-file', default="combined_esql_rules.ndjson", help="Output NDJSON filename")
    parser.add_argument('--config', default="config.yaml", help="Path to configuration file")
    parser.add_argument('--compress', action='store_true', help="Compress output to .ndjson.gz")
    parser.add_argument('--max-workers', type=int, default=4, help="Number of parallel workers")
    parser.add_argument('--verbose', action='store_true', help="Enable verbose logging")
    parser.add_argument('--kibana-url', default=os.getenv('KIBANA_URL'), help="Kibana URL for direct import")
    parser.add_argument('--api-key', default=os.getenv('KIBANA_API_KEY'), help="Kibana API key for direct import")
    parser.add_argument('--es-host', default=os.getenv('ES_HOST'), help="Elasticsearch host for direct import")
    parser.add_argument('--es-index', default='kibana-saved-objects', help="Elasticsearch index for imports")
    parser.add_argument('--stream-to', choices=['kibana', 'elasticsearch'], default='kibana', help="Import to Kibana or Elasticsearch")
    parser.add_argument('--overwrite', action='store_true', help="Overwrite existing objects")
    parser.add_argument('--ca-cert-path', default=os.getenv('CA_CERT_PATH'), help="Path to CA certificate for TLS verification")

    args = parser.parse_args()
    setup_logging(args.verbose)

    config = load_config(args.config)
    args.kibana_url = args.kibana_url or config.get('kibana_url')
    args.api_key = args.api_key or config.get('api_key')
    args.es_host = args.es_host or config.get('es_host')
    args.es_index = args.es_index or config.get('es_index')
    args.stream_to = args.stream_to or config.get('stream_to', 'kibana')
    args.overwrite = args.overwrite or config.get('overwrite', False)
    args.ca_cert_path = args.ca_cert_path or config.get('ca_cert_path')

    if config.get('no_verify_ssl', False) or os.getenv('NO_VERIFY_SSL', 'false').lower() == 'true':
        logging.error("Disabling TLS certificate verification is not allowed. Use a valid certificate or CA bundle.")
        sys.exit(1)

    if args.stream_to == 'kibana' and (not args.kibana_url or not args.api_key):
        logging.error("Kibana URL and API key must be provided via --kibana-url/--api-key, environment variables, or config file.")
        sys.exit(1)
    if args.stream_to == 'elasticsearch' and not args.es_host:
        logging.error("Elasticsearch host must be provided via --es-host, environment variable ES_HOST, or config file.")
        sys.exit(1)
    if args.stream_to == 'elasticsearch' and not ELASTICSEARCH_AVAILABLE:
        logging.error("Elasticsearch library not installed. Install with `pip install elasticsearch`.")
        sys.exit(1)

    base_dir = Path(args.base_dir).resolve()
    rules_dir = Path(args.rules_dir).resolve()
    output_dir = Path(args.output_dir).resolve()

    markdown_files = list(base_dir.rglob("*.md"))
    if not markdown_files:
        logging.error(f"No markdown files found in {base_dir}")
        sys.exit(1)

    logging.info(f"Found {len(markdown_files)} markdown files")

    with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        futures = [executor.submit(process_markdown_file, f, rules_dir) for f in markdown_files]
        for future in as_completed(futures):
            future.result()

    if not merge_to_ndjson(rules_dir, output_dir, args.output_file, args.compress, args.max_workers):
        logging.error("Failed to create NDJSON file")
        sys.exit(1)

    output_file_path = output_dir / (f"{args.output_file}.gz" if args.compress else args.output_file)
    if args.stream_to == 'kibana' and args.kibana_url and args.api_key:
        api_endpoint = f"{args.kibana_url.rstrip('/')}/api/saved_objects/_import"
        if not import_to_kibana(output_file_path, args.output_file, api_endpoint, args.api_key, args.ca_cert_path, args.overwrite, config.get('batch_size', 1000)):
            logging.error("Failed to import NDJSON to Kibana")
            sys.exit(1)
    elif args.stream_to == 'elasticsearch' and args.es_host:
        es_client = Elasticsearch([args.es_host], verify_certs=True, ca_certs=args.ca_cert_path)
        if not import_to_elasticsearch(output_file_path, args.output_file, es_client, args.es_index, config.get('batch_size', 1000)):
            logging.error("Failed to import NDJSON to Elasticsearch")
            sys.exit(1)

    logging.info("Pipeline completed successfully")

if __name__ == "__main__":
    main()