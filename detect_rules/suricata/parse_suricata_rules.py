import os
import re
import yaml
from datetime import datetime
import logging
import glob
from typing import List, Dict, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SuricataRuleParser:
    def __init__(self, input_dir: str = "./custom", output_dir: str = "./transformed_rules"):
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.dataset_config: List[Dict] = []
        self.validated_rules: List[str] = []
        self.used_sids: set = set()
        self.sid_counter: int = 1000000  # Start SIDs from 1,000,000

    def validate_rule_syntax(self, rule: str, filename: str) -> bool:
        """Validate Suricata rule syntax based on best practices"""
        try:
            # Remove comments
            rule = re.sub(r'#.*$', '', rule, flags=re.MULTILINE).strip()
            if not rule:
                return False

            # Check for rule start
            if not rule.startswith(('alert', '#alert')):
                logger.error(f"Invalid rule start in {filename}: Rule must start with 'alert'")
                return False

            # Check for required fields
            required_fields = ['msg', 'sid', 'rev', 'classtype']
            for field in required_fields:
                if f'{field}:' not in rule:
                    logger.error(f"Missing required field '{field}' in {filename}")
                    return False

            # Validate SID
            sid_match = re.search(r'sid:(\d+);', rule)
            if not sid_match:
                logger.error(f"Invalid SID in {filename}: SID must be numeric")
                return False
            sid = int(sid_match.group(1))
            if sid in self.used_sids:
                logger.error(f"Duplicate SID {sid} in {filename}")
                return False

            # Validate metadata
            metadata_match = re.search(r'metadata:([^;]+);', rule)
            if metadata_match:
                metadata = metadata_match.group(1).strip()
                if not re.match(r'^[a-zA-Z0-9_, =]+$', metadata):
                    logger.warning(f"Potentially invalid metadata format in {filename}")

            # Check for performance issues
            if 'pcre:' in rule and 'fast_pattern' not in rule:
                logger.warning(f"PCRE used without fast_pattern in {filename}, consider optimizing")

            # Check for semicolon termination
            if not rule.endswith(';'):
                logger.error(f"Rule in {filename} does not end with semicolon")
                return False

            return True
        except Exception as e:
            logger.error(f"Error validating rule in {filename}: {str(e)}")
            return False

    def transform_rule(self, rule: str, filename: str) -> Optional[str]:
        """Transform rule into structured format with new SID"""
        try:
            # Generate new SID
            while str(self.sid_counter) in self.used_sids:
                self.sid_counter += 1
            new_sid = str(self.sid_counter)
            self.used_sids.add(new_sid)

            # Parse metadata
            metadata_match = re.search(r'metadata:([^;]+);', rule)
            metadata = {}
            if metadata_match:
                metadata_str = metadata_match.group(1).strip()
                items = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', metadata_str)
                for item in items:
                    item = item.strip()
                    if '=' in item:
                        key, value = item.split('=', 1)
                        metadata[key.strip()] = value.strip()
                    else:
                        metadata[item] = True

            # Ensure required metadata fields
            if 'created_at' not in metadata:
                metadata['created_at'] = datetime.now().strftime('%Y_%m_%d')
            if 'updated_at' not in metadata:
                metadata['updated_at'] = datetime.now().strftime('%Y_%m_%d')

            # Reconstruct metadata string
            metadata_str = ', '.join([f"{k}={v}" if v is not True else k for k, v in metadata.items()])

            # Replace SID and metadata
            rule = re.sub(r'sid:\d+;', f'sid:{new_sid};', rule)
            rule = re.sub(r'metadata:[^;]+;', f'metadata:{metadata_str};', rule)

            # Extract and validate dataset
            dataset_match = re.search(r'dataset:([^;]+);', rule)
            if dataset_match:
                dataset_name = dataset_match.group(1).strip()
                dataset_type = 'ip' if 'ip' in dataset_name.lower() else 'string'
                self.dataset_config.append({
                    'name': dataset_name,
                    'type': dataset_type,
                    'file': f'./datasets/{dataset_name}.list',
                    'memcap': '10mb',
                    'hashsize': 1024
                })

            return rule
        except Exception as e:
            logger.error(f"Error transforming rule in {filename}: {str(e)}")
            return None

    def generate_config(self) -> None:
        """Generate Suricata configuration for datasets"""
        try:
            config = {'datasets': self.dataset_config}
            os.makedirs(os.path.join(self.output_dir, 'datasets'), exist_ok=True)
            with open(os.path.join(self.output_dir, 'suricata_datasets.yaml'), 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
            logger.info("Generated Suricata dataset configuration")
        except Exception as e:
            logger.error(f"Error generating config: {str(e)}")

    def split_rules(self, content: str) -> List[str]:
        """Split content into individual rules"""
        rules = []
        current_rule = []
        in_rule = False

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('alert') and not in_rule:
                in_rule = True
                current_rule = [line]
            elif in_rule:
                current_rule.append(line)
                if line.endswith(';'):
                    rules.append('\n'.join(current_rule))
                    in_rule = False
                    current_rule = []

        if current_rule and in_rule:
            rules.append('\n'.join(current_rule))
        return rules

    def process_rules(self) -> None:
        """Process all rules in the input directory"""
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            file_list = list(glob.glob(f"{self.input_dir}/**/*.rules", recursive=True))
            logger.info(f"Found {len(file_list)} rule files")

            for filepath in file_list:
                logger.info(f"Processing file: {filepath}")
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                    rules = self.split_rules(content)

                    transformed_rules = []
                    for rule in rules:
                        if not rule.strip():
                            continue
                        if self.validate_rule_syntax(rule, filepath):
                            transformed_rule = self.transform_rule(rule, filepath)
                            if transformed_rule:
                                transformed_rules.append(transformed_rule)
                                self.validated_rules.append(transformed_rule)

                    # Write transformed rules
                    output_file = os.path.join(self.output_dir, os.path.basename(filepath))
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write('\n\n'.join(transformed_rules))
                    logger.info(f"Transformed rules written to {output_file}")
                except Exception as e:
                    logger.error(f"Error processing {filepath}: {str(e)}")

            self.generate_config()
        except Exception as e:
            logger.error(f"Error in process_rules: {str(e)}")
            raise

    def run_pipeline(self) -> None:
        """Execute the rule processing pipeline"""
        try:
            logger.info("Starting Suricata rule processing pipeline")
            self.process_rules()
            logger.info("Pipeline completed successfully")
        except Exception as e:
            logger.error(f"Pipeline failed: {str(e)}")
            raise

if __name__ == "__main__":
    parser = SuricataRuleParser()
    parser.run_pipeline()