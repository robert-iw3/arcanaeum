import os
import requests
import argparse
import logging
from pathlib import Path
from tqdm import tqdm
import gzip
import json
import sys
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import yaml
import hashlib
try:
    from elasticsearch import Elasticsearch
    ELASTICSEARCH_AVAILABLE = True
except ImportError:
    ELASTICSEARCH_AVAILABLE = False

def setup_logging(verbose=False):
    """Set up logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s',
        level=level
    )

def create_session_with_retries(retries=3, backoff_factor=0.3, status_forcelist=(429, 500, 502, 503, 504)):
    """Create a requests session with retry logic."""
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def validate_ndjson(file_path, is_compressed=False):
    """Validate that a file is a valid NDJSON file."""
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
        logging.error(f"Invalid NDJSON in '{file_path}' at line {i if i else 'unknown'}: {e}")
        return False
    except Exception as e:
        logging.error(f"Error validating NDJSON file '{file_path}': {e}")
        return False

def get_file_hash(file_path):
    """Calculate MD5 hash of a file for incremental processing."""
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def import_to_kibana(file_path, filename, api_endpoint, api_key, overwrite=False, verify_ssl=True, dry_run=False, session=None, batch_size=None):
    """Import a single .ndjson or .ndjson.gz file into Kibana, with optional batching."""
    logging.info(f"{'[DRY RUN] ' if dry_run else ''}Importing file to Kibana: {filename}")

    if dry_run:
        logging.info(f"[DRY RUN] Would send {filename} to {api_endpoint}")
        return True

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
                        records.append(line)
                        if len(records) >= batch_size:
                            files = {'file': ('batch.ndjson', '\n'.join(records).encode('utf-8'), 'application/x-ndjson')}
                            headers = {"Authorization": f"ApiKey {api_key}", "kbn-xsrf": "true"}
                            params = {'overwrite': 'true'} if overwrite else {}
                            response = session.post(api_endpoint, headers=headers, files=files, params=params, verify=verify_ssl)
                            response.raise_for_status()
                            logging.debug(f"Batch of {len(records)} records sent successfully.")
                            records = []
                if records:  # Send remaining records
                    files = {'file': ('batch.ndjson', '\n'.join(records).encode('utf-8'), 'application/x-ndjson')}
                    response = session.post(api_endpoint, headers=headers, files=files, params=params, verify=verify_ssl)
                    response.raise_for_status()
        else:
            with open_func(file_path, 'rb') as f:
                files = {'file': (filename, f, 'application/x-ndjson')}
                headers = {"Authorization": f"ApiKey {api_key}", "kbn-xsrf": "true"}
                params = {'overwrite': 'true'} if overwrite else {}
                response = session.post(api_endpoint, headers=headers, files=files, params=params, verify=verify_ssl)
                response.raise_for_status()

        logging.info(f"Successfully imported {filename}. Response: {response.json()}")
        return True
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

def import_to_elasticsearch(file_path, filename, es_client, index, dry_run=False, batch_size=None):
    """Import a single .ndjson or .ndjson.gz file to Elasticsearch, with optional batching."""
    logging.info(f"{'[DRY RUN] ' if dry_run else ''}Importing file to Elasticsearch: {filename}")

    if not ELASTICSEARCH_AVAILABLE:
        logging.error("Elasticsearch library not installed. Install with `pip install elasticsearch`.")
        return False

    if dry_run:
        logging.info(f"[DRY RUN] Would send {filename} to Elasticsearch index '{index}'")
        return True

    if not file_path.exists():
        logging.error(f"File '{filename}' not found.")
        return False

    is_compressed = str(file_path).endswith('.gz')
    open_func = gzip.open if is_compressed else open

    try:
        if batch_size:
            actions = []
            with open_func(file_path, 'rt', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        doc = json.loads(line)
                        actions.append({"index": {"_index": index}})
                        actions.append(doc)
                        if len(actions) >= 2 * batch_size:
                            es_client.bulk(body=actions)
                            logging.debug(f"Batch of {len(actions)//2} records sent to Elasticsearch.")
                            actions = []
                if actions:
                    es_client.bulk(body=actions)
        else:
            actions = []
            with open_func(file_path, 'rt', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        doc = json.loads(line)
                        actions.append({"index": {"_index": index}})
                        actions.append(doc)
            es_client.bulk(body=actions)

        logging.info(f"Successfully imported {filename} to Elasticsearch index '{index}'.")
        return True
    except Exception as e:
        logging.error(f"Error importing {filename} to Elasticsearch: {e}")
        return False

def import_ndjson_files(
    input_directory,
    api_endpoint=None,
    api_key=None,
    es_host=None,
    es_index=None,
    stream_to='kibana',
    overwrite=False,
    verify_ssl=True,
    pattern="*.ndjson*",
    validate=False,
    dry_run=False,
    max_retries=3,
    batch_size=None
):
    """Import .ndjson and .ndjson.gz files to Kibana or Elasticsearch."""
    input_dir = Path(input_directory).resolve()
    metadata_file = input_dir / "import_metadata.json"
    processed_files = {}
    if metadata_file.exists():
        try:
            with open(metadata_file, 'r', encoding='utf-8') as f:
                processed_files = json.load(f)
        except Exception as e:
            logging.warning(f"Error loading metadata file: {e}. Proceeding without incremental processing.")

    if not input_dir.is_dir():
        logging.error(f"Input directory '{input_dir}' does not exist.")
        return False

    files = sorted([f for f in input_dir.glob(pattern) if f.is_file() and f.suffix in ('.ndjson', '.gz')])
    if not files:
        logging.warning(f"No files matching '{pattern}' found in '{input_dir}'.")
        return False

    # Filter out previously processed files
    new_files = []
    for f in files:
        file_hash = get_file_hash(f)
        if file_hash != processed_files.get(str(f)):
            new_files.append(f)
        else:
            logging.info(f"Skipping previously processed file: {f.name}")
    files = new_files

    if not files:
        logging.info("No new files to process.")
        return True

    logging.info(f"Found {len(files)} new NDJSON files to process in '{input_dir}'.")

    session = create_session_with_retries(retries=max_retries) if stream_to == 'kibana' else None
    es_client = Elasticsearch([es_host]) if stream_to == 'elasticsearch' and es_host else None

    if stream_to == 'elasticsearch' and not es_client:
        logging.error("Elasticsearch host must be provided for Elasticsearch imports.")
        return False

    success_count = 0
    for file_path in tqdm(files, desc="Importing NDJSON files"):
        filename = file_path.name
        if validate:
            is_compressed = filename.endswith('.gz')
            if not validate_ndjson(file_path, is_compressed):
                logging.error(f"Skipping invalid file '{filename}'.")
                continue

        success = False
        if stream_to == 'kibana':
            success = import_to_kibana(
                file_path, filename, api_endpoint, api_key, overwrite, verify_ssl, dry_run, session, batch_size
            )
        elif stream_to == 'elasticsearch':
            success = import_to_elasticsearch(file_path, filename, es_client, es_index, dry_run, batch_size)

        if success and not dry_run:
            processed_files[str(file_path)] = get_file_hash(file_path)
            success_count += 1

    if not dry_run:
        try:
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump(processed_files, f, indent=2)
            logging.info(f"Updated metadata file at '{metadata_file}'.")
        except Exception as e:
            logging.error(f"Error saving metadata file: {e}")

    logging.info(f"Imported {success_count}/{len(files)} files successfully.")
    return success_count == len(files)

def main():
    parser = argparse.ArgumentParser(description="Import NDJSON files into Kibana or Elasticsearch.")
    parser.add_argument('--input-dir', default=os.path.join(os.getcwd(), "final"), help="Directory containing NDJSON files")
    parser.add_argument('--kibana-url', default=os.getenv('KIBANA_URL'), help="Kibana base URL (e.g., http://localhost:5601)")
    parser.add_argument('--api-key', default=os.getenv('KIBANA_API_KEY'), help="Kibana API key")
    parser.add_argument('--es-host', default=os.getenv('ES_HOST'), help="Elasticsearch host (e.g., http://localhost:9200)")
    parser.add_argument('--es-index', default='kibana-saved-objects', help="Elasticsearch index for imports")
    parser.add_argument('--stream-to', choices=['kibana', 'elasticsearch'], default='kibana', help="Import to Kibana or Elasticsearch")
    parser.add_argument('--overwrite', action='store_true', help="Overwrite existing objects in Kibana")
    parser.add_argument('--no-verify-ssl', action='store_true', help="Disable SSL verification (insecure)")
    parser.add_argument('--pattern', default='*.ndjson*', help="Glob pattern for NDJSON files (e.g., '*.ndjson', '*.ndjson.gz')")
    parser.add_argument('--validate', action='store_true', help="Validate NDJSON files before importing")
    parser.add_argument('--dry-run', action='store_true', help="Simulate imports without making API calls")
    parser.add_argument('--max-retries', type=int, default=3, help="Number of retries for failed requests")
    parser.add_argument('--batch-size', type=int, help="Number of NDJSON records per batch (default: whole file)")
    parser.add_argument('--config', help="Path to YAML config file")
    parser.add_argument('--verbose', action='store_true', help="Enable verbose logging")

    args = parser.parse_args()

    setup_logging(args.verbose)

    # Load config file if provided
    if args.config:
        try:
            with open(args.config, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f) or {}
            args.kibana_url = config.get('kibana_url', args.kibana_url)
            args.api_key = config.get('api_key', args.api_key)
            args.es_host = config.get('es_host', args.es_host)
            args.es_index = config.get('es_index', args.es_index)
            args.stream_to = config.get('stream_to', args.stream_to)
            args.overwrite = config.get('overwrite', args.overwrite)
            args.no_verify_ssl = config.get('no_verify_ssl', args.no_verify_ssl)
            args.pattern = config.get('pattern', args.pattern)
            args.validate = config.get('validate', args.validate)
            args.dry_run = config.get('dry_run', args.dry_run)
            args.max_retries = config.get('max_retries', args.max_retries)
            args.batch_size = config.get('batch_size', args.batch_size)
        except Exception as e:
            logging.error(f"Error loading config file '{args.config}': {e}")
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

    api_endpoint = f"{args.kibana_url.rstrip('/')}/api/saved_objects/_import" if args.kibana_url else None
    success = import_ndjson_files(
        args.input_dir,
        api_endpoint,
        args.api_key,
        args.es_host,
        args.es_index,
        args.stream_to,
        args.overwrite,
        not args.no_verify_ssl,
        args.pattern,
        args.validate,
        args.dry_run,
        args.max_retries,
        args.batch_size
    )
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()