import os
import yara
import logging
import sys
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing
import tempfile
try:
    import chardet
    import psutil
except ImportError as e:
    print(f"Missing dependency: {e}. Please install 'chardet' and 'psutil'.")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Dependency version checks
REQUIRED_VERSIONS = {
    'yara-python': '4.5.1',
    'chardet': '5.2.0',
    'psutil': '6.0.0'
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

class YaraCompiler:
    def __init__(self, max_strings: int = 10000, max_match_data: int = 1024, chunk_size: int = 100, max_rule_lines: int = 1000, max_include_depth: int = 10):
        """
        Initialize YARA compiler with configuration options.
        """
        check_dependencies()
        self.max_strings = max_strings
        self.max_match_data = max_match_data
        self.chunk_size = chunk_size
        self.max_rule_lines = max_rule_lines
        self.max_include_depth = max_include_depth
        self.supported_modules = {'pe', 'hash', 'cuckoo', 'magic', 'elf', 'math'}
        self.compiled_rules_cache: Dict[str, str] = {}
        self.pre_validation_cache: Dict[str, List[Dict]] = {}
        self.max_workers = self._get_dynamic_workers()
        self.error_report = []
        self.valid_operators = {
            'and', 'or', 'not', '==', '!=', '<', '>', '<=', '>=', '+', '-', '*', '/', '%', '&', '|', '^', '~', '>>', '<<'
        }
        self.macro_definitions: Dict[str, str] = {}

    def _get_dynamic_workers(self) -> int:
        """
        Adjust max_workers based on CPU and memory availability.
        """
        cpu_count = max(1, multiprocessing.cpu_count() - 1)
        mem = psutil.virtual_memory()
        mem_available = mem.available / (1024 ** 3)  # GB
        return max(1, min(4, int(cpu_count * (mem_available / 8))))  # Scale with memory

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
        Check if output file exists and is writable, prompting for overwrite.
        """
        if output_file.exists():
            logger.warning(f"Output file {output_file} exists.")
            if sys.stdin.isatty():
                response = input(f"Overwrite {output_file}? (y/n): ").strip().lower()
                if response != 'y':
                    logger.info("Aborting compilation to avoid overwriting output file.")
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

    def get_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of a file."""
        sanitized_path = self._sanitize_path(file_path, file_path.parent)
        if not sanitized_path:
            return ""
        try:
            sha256 = hashlib.sha256()
            with open(sanitized_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            logger.error(f"Failed to hash {sanitized_path}: {e}")
            self.error_report.append({'file': str(sanitized_path), 'error': str(e), 'type': 'HashError'})
            return ""

    def pre_validate_yara_rule(self, content: str, rule_file: Path) -> List[Dict]:
        """
        Pre-validates YARA rule content for common errors.
        Returns a list of issues found.
        """
        if not content.strip():
            self.error_report.append({'file': str(rule_file), 'error': "Empty rule file", 'type': 'EmptyFileError'})
            return [{'file': str(rule_file), 'error': "Empty rule file", 'type': 'EmptyFileError'}]
        if len(content.splitlines()) > self.max_rule_lines:
            self.error_report.append({'file': str(rule_file), 'error': f"Rule exceeds max lines ({self.max_rule_lines})", 'type': 'RuleSizeError'})
            return [{'file': str(rule_file), 'error': f"Rule exceeds max lines ({self.max_rule_lines})", 'type': 'RuleSizeError'}]

        issues = []
        lines = content.splitlines()

        brace_count = 0
        for i, line in enumerate(lines, 1):
            brace_count += line.count('{') - line.count('}')
            if brace_count < 0:
                issues.append({'file': str(rule_file), 'line': i, 'error': 'Unmatched closing brace', 'type': 'BraceError'})
                break
        if brace_count > 0:
            issues.append({'file': str(rule_file), 'line': len(lines), 'error': 'Unmatched opening brace', 'type': 'BraceError'})

        rule_name_pattern = re.compile(r'rule\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*{')
        for i, line in enumerate(lines, 1):
            match = rule_name_pattern.match(line)
            if match and not match.group(1).isidentifier():
                issues.append({'file': str(rule_file), 'line': i, 'error': f"Invalid rule name: {match.group(1)}", 'type': 'RuleNameError'})

        string_pattern = re.compile(r'\$[a-zA-Z_][a-zA-Z0-9_]*\s*=')
        string_ids = {match.group(0).split('=')[0].strip() for match in string_pattern.finditer(content)}

        macro_pattern = re.compile(r'^\s*define\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.*?)$', re.MULTILINE)
        for match in macro_pattern.finditer(content):
            macro_name = match.group(1)
            macro_value = match.group(2).strip()
            macro_line = content[:match.start()].count('\n') + 1
            if not macro_name.isidentifier():
                issues.append({'file': str(rule_file), 'line': macro_line, 'error': f"Invalid macro name: {macro_name}", 'type': 'MacroError'})
            else:
                self.macro_definitions[macro_name] = macro_value
                tokens = re.split(r'\s+', macro_value)
                for token in tokens:
                    if token and token not in self.valid_operators and not re.match(r'[a-zA-Z_][a-zA-Z0-9_]*|[0-9]+', token):
                        issues.append({'file': str(rule_file), 'line': macro_line, 'error': f"Invalid token in macro {macro_name}: {token}", 'type': 'MacroValueError'})

        condition_pattern = re.compile(r'condition:\s*(.*?)(?=\n\s*})', re.DOTALL)
        match = condition_pattern.search(content)
        if match:
            condition = match.group(1).strip()
            condition_start_line = content[:match.start()].count('\n') + 1
            paren_count = 0
            for i, char in enumerate(condition, 1):
                if char == '(':
                    paren_count += 1
                elif char == ')':
                    paren_count -= 1
                if paren_count < 0:
                    issues.append({'file': str(rule_file), 'line': condition_start_line, 'error': 'Unmatched closing parenthesis in condition', 'type': 'ConditionError'})
                    break
            if paren_count > 0:
                issues.append({'file': str(rule_file), 'line': condition_start_line, 'error': 'Unmatched opening parenthesis in condition', 'type': 'ConditionError'})

            tokens = re.split(r'[\s\(\)\+\-\*/%\&\|\^\~]', condition)
            for token in tokens:
                if token.startswith('$') and token not in string_ids:
                    issues.append({'file': str(rule_file), 'line': condition_start_line, 'error': f"Undefined string reference: {token}", 'type': 'ConditionError'})
                if '.' in token and token.split('.')[0] not in self.supported_modules and token not in self.macro_definitions:
                    issues.append({'file': str(rule_file), 'line': condition_start_line, 'error': f"Invalid module reference: {token}", 'type': 'ConditionError'})

        return issues

    def validate_yara_rule(self, rule_file: Path) -> bool:
        """
        Validates the syntax of a single YARA rule file.
        Returns True if valid, False if invalid.
        """
        sanitized_path = self._sanitize_path(rule_file, rule_file.parent)
        if not sanitized_path:
            return False
        try:
            yara.compile(filepath=str(sanitized_path), error_on_warning=False)
            logger.debug(f"Valid YARA rule: {sanitized_path}")
            return True
        except yara.SyntaxError as e:
            logger.error(f"Syntax error in {sanitized_path}: {e}")
            self.error_report.append({'file': str(sanitized_path), 'error': str(e), 'type': 'SyntaxError'})
            return False
        except yara.WarningError as e:
            logger.warning(f"Warning in {sanitized_path}: {e}")
            self.error_report.append({'file': str(sanitized_path), 'warning': str(e), 'type': 'Warning'})
            return True
        except Exception as e:
            logger.error(f"Unexpected error validating {sanitized_path}: {e}")
            self.error_report.append({'file': str(sanitized_path), 'error': str(e), 'type': 'Unexpected'})
            return False

    def detect_required_modules(self, content: str) -> Set[str]:
        """Detects required YARA modules based on rule content."""
        modules = set()
        for module in self.supported_modules:
            if f'import "{module}"' not in content and module in content.lower():
                modules.add(module)
        return modules

    def resolve_includes(self, content: str, base_path: Path, visited: Set[str] = None, depth: int = 0) -> str:
        """Resolves external include directives recursively, preventing circular includes."""
        if depth > self.max_include_depth:
            logger.error(f"Maximum include depth exceeded in {base_path}")
            self.error_report.append({'file': base_path.name, 'error': f"Maximum include depth ({self.max_include_depth}) exceeded", 'type': 'IncludeDepthError'})
            return content

        if not content.strip():
            logger.warning(f"Empty content in {base_path}")
            self.error_report.append({'file': base_path.name, 'error': "Empty include file", 'type': 'EmptyFileError'})
            return content

        if visited is None:
            visited = set()

        content_hash = hashlib.sha256(content.encode('utf-8', errors='ignore')).hexdigest()
        if content_hash in visited:
            logger.warning(f"Circular include detected in content hash {content_hash}")
            self.error_report.append({'file': base_path.name, 'error': f"Circular include detected: {content_hash}", 'type': 'CircularInclude'})
            return content

        visited.add(content_hash)
        lines = content.splitlines()
        resolved_content = []
        include_pattern = re.compile(r'^\s*include\s*"(.*?)"\s*$')

        for line in lines:
            match = include_pattern.match(line)
            if match:
                include_file = base_path / match.group(1)
                sanitized_include = self._sanitize_path(include_file, base_path)
                if not sanitized_include:
                    resolved_content.append(line)
                    continue
                if sanitized_include.exists():
                    try:
                        with open(sanitized_include, 'rb') as f:
                            raw_content = f.read()
                            if not raw_content:
                                logger.warning(f"Empty include file: {sanitized_include}")
                                self.error_report.append({'file': str(sanitized_include), 'error': 'Empty include file', 'type': 'EmptyFileError'})
                                resolved_content.append(line)
                                continue
                            encoding = chardet.detect(raw_content)['encoding'] or 'utf-8'
                        included_content = raw_content.decode(encoding, errors='ignore')
                        issues = self.pre_validate_yara_rule(included_content, sanitized_include)
                        self.error_report.extend(issues)
                        resolved_content.append(self.resolve_includes(included_content, sanitized_include.parent, visited, depth + 1))
                    except Exception as e:
                        logger.warning(f"Failed to read include file {sanitized_include}: {e}")
                        self.error_report.append({'file': str(sanitized_include), 'error': str(e), 'type': 'IncludeError'})
                        resolved_content.append(line)
                else:
                    logger.warning(f"Include file not found: {sanitized_include}")
                    self.error_report.append({'file': str(sanitized_include), 'error': 'File not found', 'type': 'IncludeError'})
                    resolved_content.append(line)
            else:
                resolved_content.append(line)
        return '\n'.join(resolved_content)

    def correct_yara_rule(self, rule_file: Path) -> Tuple[Optional[str], bool]:
        """
        Attempts to correct common YARA rule syntax issues.
        Returns (corrected content or None, success flag).
        """
        sanitized_path = self._sanitize_path(rule_file, rule_file.parent)
        if not sanitized_path:
            return None, False
        try:
            with open(sanitized_path, 'rb') as f:
                raw_content = f.read()
                if not raw_content:
                    logger.error(f"Empty file: {sanitized_path}")
                    self.error_report.append({'file': str(sanitized_path), 'error': 'Empty file', 'type': 'EmptyFileError'})
                    return None, False
                encoding = chardet.detect(raw_content)['encoding'] or 'utf-8'
            content = raw_content.decode(encoding, errors='ignore')

            file_hash = self.get_file_hash(sanitized_path)
            if file_hash in self.pre_validation_cache:
                self.error_report.extend(self.pre_validation_cache[file_hash])
            else:
                issues = self.pre_validate_yara_rule(content, sanitized_path)
                self.error_report.extend(issues)
                self.pre_validation_cache[file_hash] = issues

            content = self.resolve_includes(content, sanitized_path.parent)

            required_modules = self.detect_required_modules(content)
            imports = [f'import "{module}"\n' for module in required_modules]
            corrected_content = ''.join(imports) + content

            rule_names = re.findall(r'rule\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*{', content)
            if len(rule_names) != len(set(rule_names)):
                logger.warning(f"Duplicate rule names in {sanitized_path}. Renaming...")
                for name in set(rule_names):
                    if rule_names.count(name) > 1:
                        for i in range(1, rule_names.count(name)):
                            corrected_content = re.sub(
                                rf'rule\s+{name}\s*{{',
                                f'rule {name}_{i} {{',
                                corrected_content,
                                count=1
                            )

            condition_pattern = re.compile(r'condition:\s*(.*?)(?=\n\s*})', re.DOTALL)
            match = condition_pattern.search(corrected_content)
            if match:
                condition = match.group(1).strip()
                condition_start_line = content[:match.start()].count('\n') + 1
                paren_count = condition.count('(') - condition.count(')')
                if paren_count != 0:
                    logger.warning(f"Unbalanced parentheses in condition of {sanitized_path} at line {condition_start_line}. Attempting fix...")
                    self.error_report.append({'file': str(sanitized_path), 'line': condition_start_line, 'error': 'Unbalanced parentheses in condition', 'type': 'ConditionError'})
                    if paren_count > 0:
                        corrected_content = corrected_content.replace(condition, condition + ')' * paren_count)
                    else:
                        corrected_content = corrected_content.replace(condition, '(' * abs(paren_count) + condition)

            macro_pattern = re.compile(r'^\s*define\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.*?)$', re.MULTILINE)
            for match in macro_pattern.finditer(corrected_content):
                macro_name = match.group(1)
                macro_value = match.group(2).strip()
                macro_line = corrected_content[:match.start()].count('\n') + 1
                if not macro_name.isidentifier():
                    logger.warning(f"Invalid macro name {macro_name} at line {macro_line} in {sanitized_path}")
                    self.error_report.append({'file': str(sanitized_path), 'line': macro_line, 'error': f"Invalid macro name: {macro_name}", 'type': 'MacroError'})
                    corrected_content = re.sub(
                        rf'^\s*define\s+{macro_name}\s*=.*$',
                        f'// Invalid macro: {match.group(0)}',
                        corrected_content,
                        count=1,
                        flags=re.MULTILINE
                    )
                else:
                    tokens = re.split(r'[\s\(\)\+\-\*/%\&\|\^\~]', macro_value)
                    for token in tokens:
                        if token and token not in self.valid_operators and not re.match(r'[a-zA-Z_][a-zA-Z0-9_]*|[0-9]+', token):
                            logger.warning(f"Invalid token in macro {macro_name} at line {macro_line}: {token}")
                            self.error_report.append({'file': str(sanitized_path), 'line': macro_line, 'error': f"Invalid token in macro {macro_name}: {token}", 'type': 'MacroValueError'})
                            corrected_content = re.sub(
                                rf'^\s*define\s+{macro_name}\s*=.*$',
                                f'// Invalid macro value: {match.group(0)}',
                                corrected_content,
                                count=1,
                                flags=re.MULTILINE
                            )

            temp_path = None
            try:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', encoding='utf-8', delete=False) as temp_file:
                    temp_path = Path(temp_file.name)
                    temp_file.write(corrected_content)

                if self.validate_yara_rule(temp_path):
                    logger.info(f"Corrected rule: {sanitized_path}")
                    return corrected_content, True
                else:
                    logger.warning(f"Could not correct rule: {sanitized_path}. Commenting out rule.")
                    self.error_report.append({'file': str(sanitized_path), 'error': 'Failed to correct rule syntax', 'type': 'CorrectionFailed'})
                    lines = corrected_content.splitlines()
                    corrected_lines = []
                    in_rule = False
                    rule_start_line = 0
                    for i, line in enumerate(lines, 1):
                        if re.match(r'rule\s+[a-zA-Z_][a-zA-Z0-9_]*\s*{', line):
                            in_rule = True
                        if in_rule:
                            corrected_lines.append(f"// {line}")
                            if line.strip() == '}':
                                in_rule = False
                        else:
                            corrected_lines.append(line)
                    corrected_content = '\n'.join(corrected_lines)
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', encoding='utf-8', delete=False) as temp_file:
                        temp_path = Path(temp_file.name)
                        temp_file.write(corrected_content)
                    if self.validate_yara_rule(temp_path):
                        logger.info(f"Commented out problematic rule sections in {sanitized_path}")
                        return corrected_content, True
                    logger.error(f"Failed to correct {sanitized_path} even after commenting out")
                    self.error_report.append({'file': str(sanitized_path), 'error': 'Failed to correct rule even after commenting out', 'type': 'FinalCorrectionFailed'})
                    return None, False
            finally:
                if temp_path and temp_path.exists():
                    try:
                        temp_path.unlink()
                    except Exception as e:
                        logger.warning(f"Failed to clean up temporary file {temp_path}: {e}")
        except Exception as e:
            logger.error(f"Error correcting {sanitized_path}: {e}")
            self.error_report.append({'file': str(sanitized_path), 'error': str(e), 'type': 'CorrectionError'})
            return None, False

    def compile_directory(self, dir_path: Path, output_path: Path) -> List[Path]:
        """
        Compiles all .yar/.yara files in a directory into chunked namespaced rule files.
        Returns paths to compiled files.
        """
        sanitized_dir = self._sanitize_path(dir_path, dir_path)
        if not sanitized_dir:
            return []
        dir_name = sanitized_dir.name.replace('-', '_').replace(' ', '_')
        yara_files = list(sanitized_dir.glob('*.yar')) + list(sanitized_dir.glob('*.yara'))

        if not yara_files:
            logger.debug(f"No YARA files in {sanitized_dir}")
            return []

        logger.info(f"Processing directory: {sanitized_dir}")
        compiled_rules = []
        rule_hashes = set()

        rule_contents = []
        for rule_file in yara_files:
            rule_hash = self.get_file_hash(rule_file)
            if not rule_hash:
                continue
            if rule_hash in self.pre_validation_cache:
                self.error_report.extend(self.pre_validation_cache[rule_hash])
                continue
            try:
                with open(rule_file, 'rb') as f:
                    raw_content = f.read()
                    if not raw_content:
                        logger.warning(f"Empty file: {rule_file}")
                        self.error_report.append({'file': str(rule_file), 'error': 'Empty file', 'type': 'EmptyFileError'})
                        continue
                    encoding = chardet.detect(raw_content)['encoding'] or 'utf-8'
                content = raw_content.decode(encoding, errors='ignore')
                rule_contents.append((rule_file, content, rule_hash))
            except Exception as e:
                logger.error(f"Error reading {rule_file}: {e}")
                self.error_report.append({'file': str(rule_file), 'error': str(e), 'type': 'ReadError'})
                continue

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {executor.submit(self.pre_validate_yara_rule, content, rule_file): (rule_file, rule_hash)
                             for rule_file, content, rule_hash in rule_contents}
            for future in as_completed(future_to_file):
                rule_file, rule_hash = future_to_file[future]
                try:
                    issues = future.result()
                    self.error_report.extend(issues)
                    self.pre_validation_cache[rule_hash] = issues
                except Exception as e:
                    logger.error(f"Error pre-validating {rule_file}: {e}")
                    self.error_report.append({'file': str(rule_file), 'error': str(e), 'type': 'PreValidationError'})

        for rule_file, content, rule_hash in rule_contents:
            if rule_hash in self.compiled_rules_cache:
                logger.debug(f"Skipping unchanged file: {rule_file}")
                continue
            if rule_hash in rule_hashes:
                logger.warning(f"Skipping duplicate file: {rule_file}")
                continue
            rule_hashes.add(rule_hash)

            if self.validate_yara_rule(rule_file):
                compiled_rules.append(content)
            else:
                logger.warning(f"Invalid rule detected: {rule_file}. Attempting correction.")
                corrected_rule, success = self.correct_yara_rule(rule_file)
                if success and corrected_rule:
                    compiled_rules.append(corrected_rule)
            self.compiled_rules_cache[rule_hash] = str(rule_file)

        if not compiled_rules:
            logger.warning(f"No valid rules to compile in {sanitized_dir}")
            return []

        output_files = []
        for i in range(0, len(compiled_rules), self.chunk_size):
            chunk = compiled_rules[i:i + self.chunk_size]
            output_file = output_path / f"{dir_name}_compiled_chunk_{i // self.chunk_size}.yar"
            if not self._check_output_file(output_file):
                continue
            namespace = f"namespace {dir_name}_chunk_{i // self.chunk_size} {{\n{'\n\n'.join(chunk)}\n}}"

            try:
                yara.compile(
                    source=namespace,
                    error_on_warning=False,
                    max_strings_per_rule=self.max_strings,
                    max_match_data=self.max_match_data
                )
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(namespace)
                logger.info(f"Compiled rules chunk for {dir_name} to {output_file}")
                output_files.append(output_file)
            except yara.Error as e:
                logger.error(f"Failed to compile rules chunk for {dir_name}: {e}")
                self.error_report.append({'file': str(output_file), 'error': str(e), 'type': 'ChunkCompilationError'})
                continue

        return output_files

    def compile_yara_rules(self, root_dir: str, output_dir: str, rule_filter: Optional[List[str]] = None) -> Path:
        """
        Compiles all .yar/.yara files in the root directory and subdirectories.
        Supports filtering by directory names and generates an error report.
        """
        root_path = Path(root_dir)
        sanitized_root = self._sanitize_path(root_path, root_path)
        if not sanitized_root:
            raise FileNotFoundError(f"Root directory {root_dir} not found")
        output_path = Path(output_dir)
        if not self._check_output_file(output_path / "all_rules.yar"):
            raise PermissionError(f"Cannot write to output directory {output_dir}")

        self.error_report = []
        self.macro_definitions = {}
        include_content = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_dir = {}
            for dirpath, _, _ in os.walk(sanitized_root):
                dir_path = Path(dirpath)
                sanitized_dir = self._sanitize_path(dir_path, sanitized_root)
                if not sanitized_dir:
                    continue
                if rule_filter and sanitized_dir.name not in rule_filter:
                    logger.debug(f"Skipping directory {sanitized_dir} due to rule filter")
                    continue
                future = executor.submit(self.compile_directory, sanitized_dir, output_path)
                future_to_dir[future] = sanitized_dir

            for future in as_completed(future_to_dir):
                dir_path = future_to_dir[future]
                try:
                    output_files = future.result()
                    for output_file in output_files:
                        rel_path = os.path.relpath(output_file, output_path)
                        include_content.append(f'include "./{rel_path}"')
                except Exception as e:
                    logger.error(f"Error compiling directory {dir_path}: {e}")
                    self.error_report.append({'file': str(dir_path), 'error': str(e), 'type': 'DirectoryCompilationError'})

        if not include_content:
            logger.warning("No rules were compiled. Check directory contents and filters.")
            self.error_report.append({'file': str(sanitized_root), 'error': 'No rules compiled', 'type': 'NoRulesError'})

        include_file = output_path / "all_rules.yar"
        with open(include_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted(include_content)))
        logger.info(f"Generated include file: {include_file}")

        if self.error_report:
            report_file = output_path / "compilation_error_report.json"
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(self.error_report, f, indent=2)
            logger.info(f"Generated error report: {report_file}")

        return include_file

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Compile YARA rules from directories")
    parser.add_argument("root_dir", help="Root directory containing YARA rules")
    parser.add_argument("output_dir", help="Output directory for compiled rules")
    parser.add_argument("--max-strings", type=int, default=10000, help="Max strings per rule")
    parser.add_argument("--max-match-data", type=int, default=1024, help="Max match data size")
    parser.add_argument("--chunk-size", type=int, default=100, help="Rules per chunked file")
    parser.add_argument("--max-rule-lines", type=int, default=1000, help="Max lines per rule file")
    parser.add_argument("--max-include-depth", type=int, default=10, help="Max include recursion depth")
    parser.add_argument("--rule-filter", nargs='*', help="Filter directories to compile")
    parser.add_argument("--log-level", default="INFO", help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    args = parser.parse_args()

    logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))
    compiler = YaraCompiler(
        max_strings=args.max_strings,
        max_match_data=args.max_match_data,
        chunk_size=args.chunk_size,
        max_rule_lines=args.max_rule_lines,
        max_include_depth=args.max_include_depth
    )
    try:
        compiler.compile_yara_rules(args.root_dir, args.output_dir, args.rule_filter)
    except Exception as e:
        logger.error(f"Compilation failed: {e}")
        exit(1)