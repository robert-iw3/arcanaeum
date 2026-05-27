import os
import re
import yaml
import json
import logging
import datetime
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Tuple
from static_code_analyzer.languages import LanguagePatterns

logging.basicConfig(filename='/app/logs/analyzer.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class Scanner:
    def __init__(self, config_path: str):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        self.patterns = LanguagePatterns(self.config)
        self.excluded_dirs = self.config.get('excluded_dirs', [])
        self.extensions = self.config.get('extensions', [])
        self.max_workers = self.config.get('max_workers', 4)
        self.chunk_size = self.config.get('chunk_size', 1048576)
        self.cve_patterns = self.config.get('cve_patterns', [])

    def scan_file(self, file_path: str) -> List[Dict]:
        results = []
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in self.extensions:
            return results

        language = {
            '.py': 'python',
            '.java': 'java',
            '.js': 'javascript',
            '.go': 'go',
            '.rb': 'ruby',
            '.rs': 'rust',
            '.php': 'php',
            '.cpp': 'cpp',
            '.c': 'c',
            '.json': 'json',
            '.xml': 'xml',
        }.get(ext, 'universal')

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                patterns = self.patterns.get_patterns(language)
                for pattern, func_name, description in patterns:
                    for match in pattern.finditer(content):
                        line_no = content[:match.start()].count('\n') + 1
                        result = {
                            'file': file_path,
                            'line': line_no,
                            'function': func_name,
                            'description': description,
                            'category': next((cf['category'] for cf in self.config['custom_functions'] if cf['function'] == func_name), 'security'),
                            'severity': next((cf['severity'] for cf in self.config['custom_functions'] if cf['function'] == func_name), 'High'),
                            'owasp_category': next((cf['owasp_category'] for cf in self.config['custom_functions'] if cf['function'] == func_name), 'A03:2021'),
                            'language': language,
                            'timestamp': datetime.datetime.now().isoformat(),
                            'scan_id': str(uuid.uuid4()),
                            'confidence': 'High' if language != 'universal' else 'Medium',
                        }
                        results.append(result)
                        logging.info(f"Detected vulnerability: {result['description']} in {file_path} at line {line_no}")

            # CVE scanning for JSON (SBOM) files
            if ext == '.json':
                try:
                    data = json.loads(content)
                    for cve in self.cve_patterns:
                        if 'dependencies' in data:
                            for dep in data['dependencies']:
                                if dep.get('name') == cve['dependency'] and dep.get('version') < cve['version']:
                                    result = {
                                        'file': file_path,
                                        'line': 0,
                                        'function': f"{cve['dependency']}@{dep.get('version')}",
                                        'description': cve['description'],
                                        'category': 'dependency',
                                        'severity': cve['severity'],
                                        'owasp_category': 'A06:2021',
                                        'language': language,
                                        'timestamp': datetime.datetime.now().isoformat(),
                                        'scan_id': str(uuid.uuid4()),
                                        'confidence': 'High',
                                    }
                                    results.append(result)
                                    logging.info(f"Detected CVE: {cve['cve']} in {file_path}")
                except json.JSONDecodeError:
                    logging.warning(f"Invalid JSON in {file_path}")

        except Exception as e:
            logging.error(f"Error scanning {file_path}: {str(e)}")

        return results

    def scan_directory(self, directory: str, output_file: str) -> Dict:
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for root, dirs, files in os.walk(directory):
                dirs[:] = [d for d in dirs if d not in self.excluded_dirs]
                for file in files:
                    if any(file.endswith(ext) for ext in self.extensions):
                        file_path = os.path.join(root, file)
                        results.extend(executor.submit(self.scan_file, file_path).result())

        summary = {
            'total_files': len([f for r, _, fs in os.walk(directory) for f in fs if any(f.endswith(ext) for ext in self.extensions)]),
            'files_scanned': len(set(r['file'] for r in results)),
            'vulnerabilities': len(results),
            'scan_start': datetime.datetime.now().isoformat(),
            'scan_end': datetime.datetime.now().isoformat(),
            'by_owasp': {},
            'by_severity': {},
            'by_category': {},
            'by_language': {},
            'cve_matches': [r for r in results if r['category'] == 'dependency'],
        }

        for r in results:
            summary['by_owasp'][r['owasp_category']] = summary['by_owasp'].get(r['owasp_category'], 0) + 1
            summary['by_severity'][r['severity']] = summary['by_severity'].get(r['severity'], 0) + 1
            summary['by_category'][r['category']] = summary['by_category'].get(r['category'], 0) + 1
            summary['by_language'][r['language']] = summary['by_language'].get(r['language'], 0) + 1

        output = {'results': results, 'summary': summary}
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)
        logging.info(f"Scan completed, results written to {output_file}")
        return output