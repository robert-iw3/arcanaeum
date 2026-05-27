import os
import requests
import urllib3
from google.oauth2 import service_account
import google.auth.transport.requests
import glob
import re
from typing import List, Dict, Optional
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('yara_pipeline.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Suppress insecure request warnings in production
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class YaraLValidationError(Exception):
    """Custom exception for YARA-L validation errors"""
    pass

class YaraLPipeline:
    def __init__(self, config_path: str = "config.yaml"):
        """Initialize pipeline with configuration"""
        self.config = self._load_config(config_path)
        self.auth_headers = None
        self.max_workers = self.config.get('max_workers', 5)

    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                required_keys = ['chronicle_api_url', 'credentials_file', 'auth_scope', 'rules_dir']
                for key in required_keys:
                    if key not in config:
                        raise ValueError(f"Missing required config key: {key}")
                return config
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise

    def _validate_yaral_rule(self, rule_content: str, file_path: str) -> bool:
        """Validate YARA-L rule structure"""
        try:
            # Basic structural checks
            if not rule_content.strip():
                raise YaraLValidationError(f"Empty rule file: {file_path}")

            # Check for required sections
            required_sections = ['meta:', 'events:', 'condition:']
            for section in required_sections:
                if section not in rule_content:
                    raise YaraLValidationError(f"Missing {section} section in {file_path}")

            # Validate rule name
            rule_name_match = re.match(r'rule\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*{', rule_content)
            if not rule_name_match:
                raise YaraLValidationError(f"Invalid rule name format in {file_path}")

            # Check for valid meta fields
            meta_match = re.search(r'meta:\s*([\s\S]*?)(events:|condition:)', rule_content)
            if meta_match:
                meta_content = meta_match.group(1)
                required_meta = ['author', 'date', 'description']
                for field in required_meta:
                    if field not in meta_content:
                        logger.warning(f"Missing recommended meta field '{field}' in {file_path}")

            return True
        except YaraLValidationError as e:
            logger.error(f"Validation failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected validation error in {file_path}: {e}")
            return False

    def _get_auth_headers(self) -> Optional[Dict]:
        """Generate authentication headers using service account"""
        try:
            credentials = service_account.Credentials.from_service_account_file(
                self.config['credentials_file'],
                scopes=[self.config['auth_scope']]
            )
            auth_request = google.auth.transport.requests.Request()
            credentials.refresh(auth_request)
            return {
                "Authorization": f"Bearer {credentials.token}",
                "Content-Type": "application/json",
                "User-Agent": "YaraLPipeline/1.0"
            }
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return None

    def _find_yaral_files(self) -> List[str]:
        """Find all .yaral files recursively"""
        rules_dir = self.config['rules_dir']
        yaral_files = glob.glob(os.path.join(rules_dir, "**", "*.yaral"), recursive=True)
        logger.info(f"Found {len(yaral_files)} YARA-L files in {rules_dir}")
        return yaral_files

    def _upload_yaral_rule(self, file_path: str) -> bool:
        """Upload a single YARA-L rule to Chronicle API"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                rule_content = f.read()

            if not self._validate_yaral_rule(rule_content, file_path):
                return False

            url = f"{self.config['chronicle_api_url']}/rules"
            payload = {"ruleText": rule_content}

            response = requests.post(url, headers=self.auth_headers, json=payload, timeout=10)
            response.raise_for_status()

            rule_id = response.json().get('ruleId', 'unknown')
            logger.info(f"Successfully uploaded rule from {file_path} with ID: {rule_id}")
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to upload rule {file_path}: {e}")
            if hasattr(e, 'response') and e.response:
                logger.error(f"Response content: {e.response.text}")
            return False
        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}")
            return False

    def run_pipeline(self) -> Dict[str, int]:
        """Run the pipeline to process and upload all YARA-L rules"""
        self.auth_headers = self._get_auth_headers()
        if not self.auth_headers:
            logger.error("Pipeline aborted due to authentication failure")
            return {"success": 0, "failed": 0}

        yaral_files = self._find_yaral_files()
        if not yaral_files:
            logger.warning(f"No .yaral files found in {self.config['rules_dir']}")
            return {"success": 0, "failed": 0}

        success_count = 0
        failed_count = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {executor.submit(self._upload_yaral_rule, file_path): file_path
                            for file_path in yaral_files}

            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    if future.result():
                        success_count += 1
                    else:
                        failed_count += 1
                except Exception as e:
                    logger.error(f"Exception processing {file_path}: {e}")
                    failed_count += 1

        logger.info(f"Pipeline completed: {success_count} rules uploaded successfully, {failed_count} failed")
        return {"success": success_count, "failed": failed_count}

if __name__ == "__main__":
    pipeline = YaraLPipeline()
    results = pipeline.run_pipeline()
    logger.info(f"Final results: {results}")