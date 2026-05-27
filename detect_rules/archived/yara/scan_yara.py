import yara
import logging
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import argparse
import hashlib
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing
import psutil
from tqdm import tqdm
import re
try:
    import chardet
except ImportError as e:
    print(f"Missing dependency: {e}. Please install 'chardet'.")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Dependency version checks
REQUIRED_VERSIONS = {
    'yara-python': '4.5.1',
    'chardet': '5.2.0',
    'psutil': '6.0.0',
    'tqdm': '4.66.5'
}

def check_dependencies():
    """
    Verify required package versions.
    """
    import pkg_resources
    for pkg, required_version in REQUIRED_VERSIONS.items():
        try:
            installed_version = pkg_resources.get_distribution(pkg).version
            if installed_version != required_version:
                logger.warning(f"{pkg} version {installed_version} installed, but {required_version} required.")
        except pkg_resources.DistributionNotFound:
            logger.error(f"{pkg} not installed. Please install version {required_version}.")
            sys.exit(1)

class YaraScanner:
    def __init__(self, timeout: int = 30, chunk_size: int = None, max_strings: int = 10000):
        """
        Initialize the YARA scanner with configuration options.
        """
        check_dependencies()
        self.timeout = timeout
        self.chunk_size = chunk_size or self._get_dynamic_chunk_size()
        self.max_strings = max_strings
        self.max_workers = self._get_dynamic_workers()
        self.file_cache: Dict[str, float] = {}  # {hash: mtime}
        self.error_report = []

    def _get_dynamic_workers(self) -> int:
        """
        Adjust max_workers based on CPU and memory availability.
        """
        cpu_count = max(1, multiprocessing.cpu_count() - 1)
        mem = psutil.virtual_memory()
        mem_available = mem.available / (1024 ** 3)  # GB
        return max(1, min(4, int(cpu_count * (mem_available / 8))))

    def _get_dynamic_chunk_size(self, files: List[Path] = None) -> int:
        """
        Adjust chunk_size based on memory and average file size.
        """
        mem = psutil.virtual_memory()
        mem_available = mem.available / (1024 ** 2)  # MB
        if files:
            total_size = sum(f.stat().st_size for f in files if f.exists()) / (1024 ** 2)
            avg_file_size = total_size / max(1, len(files))
            chunk_size = max(10, min(1000, int(mem_available / max(1, avg_file_size))))
        else:
            chunk_size = 1000
        return chunk_size

    def _sanitize_path(self, path: Path, base_path: Path) -> Optional[Path]:
        """
        Validate and sanitize file paths to prevent directory traversal.
        """
        try:
            resolved_path = path.resolve()
            base_resolved = base_path.resolve()
            if not resolved_path.is_relative_to(base_resolved):
                logger.error(f"Invalid path {path}: Outside base directory {base_path}")
                self.error_report.append({'file': str(path), 'error': f"Path outside base directory {base_path}", 'type': 'PathError'})
                return None
            return resolved_path
        except Exception as e:
            logger.error(f"Error resolving path {path}: {e}")
            self.error_report.append({'file': str(path), 'error': str(e), 'type': 'PathResolutionError'})
            return None

    def _check_output_file(self, output_file: Path) -> bool:
        """
        Check if output file is writable, prompting for overwrite.
        """
        if output_file.exists():
            logger.warning(f"Output file {output_file} exists.")
            if sys.stdin.isatty():
                response = input(f"Overwrite {output_file}? (y/n): ").strip().lower()
                if response != 'y':
                    logger.info("Aborting scan to avoid overwriting output file.")
                    return False
            else:
                logger.warning("Non-interactive mode: Will not overwrite existing file.")
                return False
        try:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'a') as f:
                pass
            return True
        except OSError as e:
            logger.error(f"Cannot write to {output_file}: {e}")
            self.error_report.append({'file': str(output_file), 'error': str(e), 'type': 'OutputFileError'})
            return False

    def get_file_hash(self, file_path: Path) -> Tuple[str, float]:
        """
        Calculate SHA256 hash and mtime of a file.
        """
        sanitized_path = self._sanitize_path(file_path, file_path.parent)
        if not sanitized_path:
            return "", 0.0
        try:
            sha256 = hashlib.sha256()
            with open(sanitized_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)
            return sha256.hexdigest(), sanitized_path.stat().st_mtime
        except Exception as e:
            logger.error(f"Failed to hash {sanitized_path}: {e}")
            self.error_report.append({'file': str(sanitized_path), 'error': str(e), 'type': 'HashError'})
            return "", 0.0

    def check_rule_complexity(self, rules: yara.Rules) -> List[Dict]:
        """
        Check rule complexity to prevent resource-intensive rules.
        Returns list of complexity issues.
        """
        issues = []
        max_regex_size = 1000  # Max chars in a regex pattern
        try:
            for rule in rules:
                string_count = 0
                for string in rule.strings:
                    string_count += 1
                    if string_count > self.max_strings:
                        issues.append({
                            'rule': rule.identifier,
                            'error': f"Too many strings ({string_count} > {self.max_strings})",
                            'type': 'ComplexityError'
                        })
                        break
                    if string.is_regex:
                        pattern = string.identifier
                        if len(pattern) > max_regex_size:
                            issues.append({
                                'rule': rule.identifier,
                                'error': f"Regex pattern too long ({len(pattern)} > {max_regex_size})",
                                'type': 'ComplexityError'
                            })
                        try:
                            re.compile(pattern)  # Check regex validity
                        except re.error as e:
                            issues.append({
                                'rule': rule.identifier,
                                'error': f"Invalid regex pattern: {e}",
                                'type': 'RegexError'
                            })
        except Exception as e:
            logger.error(f"Error checking rule complexity: {e}")
            self.error_report.append({'error': str(e), 'type': 'ComplexityCheckError'})
        return issues

    def scan_file(self, file_path: Path, rules: yara.Rules, timeout: int) -> List[Dict]:
        """
        Scan a single file with YARA rules and return matches.
        """
        sanitized_path = self._sanitize_path(file_path, file_path.parent)
        if not sanitized_path:
            return []
        try:
            with open(sanitized_path, 'rb') as f:
                raw_content = f.read()
                if not raw_content:
                    logger.debug(f"Empty file: {sanitized_path}")
                    return []
                encoding = chardet.detect(raw_content)['encoding'] or 'utf-8'
            content = raw_content.decode(encoding, errors='ignore')
            matches = rules.match(data=content, timeout=timeout)
            result = []
            for match in matches:
                result.append({
                    'file': str(sanitized_path),
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': [(s.identifier, s.matches) for s in match.strings]
                })
            return result
        except yara.TimeoutError:
            logger.warning(f"Timeout scanning {sanitized_path}")
            self.error_report.append({'file': str(sanitized_path), 'error': 'Scan timeout', 'type': 'TimeoutError'})
            return []
        except Exception as e:
            logger.error(f"Error scanning {sanitized_path}: {e}")
            self.error_report.append({'file': str(sanitized_path), 'error': str(e), 'type': 'ScanError'})
            return []

    def scan_directory(self, dir_path: Path, rules: yara.Rules, extensions: Optional[List[str]] = None) -> List[Dict]:
        """
        Scan all files in a directory with YARA rules.
        """
        sanitized_dir = self._sanitize_path(dir_path, dir_path)
        if not sanitized_dir:
            return []

        files = []
        for ext in extensions or ['*']:
            files.extend(sanitized_dir.rglob(f'*.{ext}' if ext != '*' else '*'))
        files = [f for f in files if f.is_file() and self._sanitize_path(f, sanitized_dir)]

        if not files:
            logger.debug(f"No files to scan in {sanitized_dir}")
            return []

        # Update chunk_size based on files
        self.chunk_size = self._get_dynamic_chunk_size(files)
        logger.info(f"Scanning {len(files)} files in {sanitized_dir} with chunk size {self.chunk_size}")

        # Check rule complexity
        complexity_issues = self.check_rule_complexity(rules)
        self.error_report.extend(complexity_issues)
        if complexity_issues:
            logger.warning(f"Rule complexity issues detected: {len(complexity_issues)} issues")
            # Adjust timeout based on complexity
            string_counts = [issue.get('string_count', 0) for issue in complexity_issues if 'string_count' in issue]
            max_strings = max(string_counts, default=0)
            timeout = self.timeout * (1 + max_strings // self.max_strings) if max_strings else self.timeout
        else:
            timeout = self.timeout

        matches = []
        with tqdm(total=len(files), desc=f"Scanning {sanitized_dir.name}", unit="file") as pbar:
            for i in range(0, len(files), self.chunk_size):
                chunk = files[i:i + self.chunk_size]
                with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
                    future_to_file = {executor.submit(self.scan_file, file_path, rules, timeout): file_path for file_path in chunk}
                    for future in tqdm(as_completed(future_to_file), total=len(chunk), desc="Chunk", unit="file", leave=False):
                        file_path = future_to_file[future]
                        try:
                            result = future.result()
                            matches.extend(result)
                        except Exception as e:
                            logger.error(f"Error scanning {file_path}: {e}")
                            self.error_report.append({'file': str(file_path), 'error': str(e), 'type': 'ChunkScanError'})
                        pbar.update(1)
        return matches

    def scan(self, target_path: str, rules_file: str, output_file: str, extensions: Optional[List[str]] = None) -> Path:
        """
        Scan a file or directory with YARA rules and save results to output file.
        """
        target_path = Path(target_path)
        rules_file = Path(rules_file)
        output_file = Path(output_file)

        sanitized_target = self._sanitize_path(target_path, target_path)
        sanitized_rules = self._sanitize_path(rules_file, rules_file.parent)
        if not sanitized_target or not sanitized_rules:
            raise FileNotFoundError("Invalid target or rules file path")
        if not self._check_output_file(output_file):
            raise PermissionError(f"Cannot write to output file {output_file}")

        if not sanitized_rules.exists():
            logger.error(f"Rules file {sanitized_rules} does not exist")
            self.error_report.append({'file': str(sanitized_rules), 'error': 'Rules file not found', 'type': 'RulesFileError'})
            raise FileNotFoundError(f"Rules file {sanitized_rules} not found")

        try:
            rules = yara.compile(filepath=str(sanitized_rules))
        except yara.Error as e:
            logger.error(f"Failed to load rules from {sanitized_rules}: {e}")
            self.error_report.append({'file': str(sanitized_rules), 'error': str(e), 'type': 'RulesLoadError'})
            raise ValueError(f"Failed to load rules: {e}")

        self.error_report = []
        matches = []

        if sanitized_target.is_file():
            file_hash, mtime = self.get_file_hash(sanitized_target)
            if file_hash in self.file_cache and self.file_cache[file_hash] == mtime:
                logger.debug(f"Skipping unchanged file: {sanitized_target}")
            else:
                matches.extend(self.scan_file(sanitized_target, rules, self.timeout))
                if file_hash:
                    self.file_cache[file_hash] = mtime
        else:
            matches.extend(self.scan_directory(sanitized_target, rules, extensions))

        if matches:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(matches, f, indent=2)
            logger.info(f"Scan results saved to {output_file}")
        else:
            logger.warning("No matches found during scan")
            self.error_report.append({'file': str(sanitized_target), 'error': 'No matches found', 'type': 'NoMatches'})

        if self.error_report:
            error_report_file = output_file.parent / f"{output_file.stem}_error_report.json"
            with open(error_report_file, 'w', encoding='utf-8') as f:
                json.dump(self.error_report, f, indent=2)
            logger.info(f"Error report saved to {error_report_file}")

        return output_file

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan files or directories with YARA rules")
    parser.add_argument("target_path", help="File or directory to scan")
    parser.add_argument("rules_file", help="Compiled YARA rules file (e.g., all_rules.yar)")
    parser.add_argument("output_file", help="Output file for scan results (JSON)")
    parser.add_argument("--extensions", nargs='*', help="File extensions to scan (e.g., txt pdf)")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout per file scan (seconds)")
    parser.add_argument("--chunk-size", type=int, help="Files per scan chunk")
    parser.add_argument("--max-strings", type=int, default=10000, help="Max strings per rule")
    parser.add_argument("--log-level", default="INFO", help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    args = parser.parse_args()

    logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))
    scanner = YaraScanner(timeout=args.timeout, chunk_size=args.chunk_size, max_strings=args.max_strings)
    try:
        scanner.scan(args.target_path, args.rules_file, args.output_file, args.extensions)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        exit(1)