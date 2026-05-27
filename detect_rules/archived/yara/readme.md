# YARA Rule Compilation and Scanning Toolkit

This toolkit provides Python scripts and an Ansible playbook to compile and scan YARA rules across directories and subdirectories. It supports advanced validation, correction, and selective scanning of rules, optimized for large-scale rule sets.

## Prerequisites
- Python 3.6+
- `yara-python` library (`pip install -r requirements.txt`)
- Ansible (for automation playbook)
- YARA rule files (`.yar` or `.yara`)
- python-magic requires libmagic on Linux (e.g., apt-get install libmagic-dev)

## Scripts
1. **compile_yara_rules.py**
   - Compiles `.yar`/`.yara` files from a directory structure into chunked, namespaced rule files.
   - Generates an `all_rules.yar` include file and an error report (`compilation_error_report.json`).
   - Features:
     - **Parallel Pre-Validation**: Validates rules concurrently for common errors (e.g., missing braces, invalid rule names).
     - **Advanced Syntax Correction**: Fixes missing imports, duplicate rule names, unbalanced parentheses, invalid operators, and invalid string/module references.
     - **Complex Macro Support**: Validates and corrects YARA macros (`define`), including macro value validation.
     - **Include Resolution**: Resolves include directives and handles circular includes.
     - **Memory Management**: Chunks rules to manage memory for large sets.
     - **Selective Compilation**: Supports filtering by directory names.
     - **Detailed Error Reporting**: Generates reports with line numbers for uncorrectable rules and issues.

2. **scan_yara_rules.py**
   - Scans directories using compiled YARA rules.
   - Features:
     - Selective rule filtering.
     - Batch processing and multithreading.
     - Outputs results to log, JSON, or CSV.
     - Configurable file size and timeout limits.

3. **yara_automation.yml**
   - Ansible playbook to automate rule compilation and scanning.
   - Configurable via variables for directories, output formats, and filters.

## Usage
### Required Libraries
```bash
pip install -r requirements.txt
```

### Compile Rules
```bash
python compile_yara_rules.py /path/to/yara/rules /path/to/output \
  --max-strings 10000 \
  --max-match-data 1024 \
  --chunk-size 100 \
  --rule-filter dir1 dir2 \
  --log-level DEBUG
```
- Compiles rules into `/path/to/output/<dir_name>_compiled_chunk_<n>.yar`.
- Generates `/path/to/output/all_rules.yar` and `/path/to/output/compilation_error_report.json`.

### Scan Directory
```bash
python scan_yara_rules.py /path/to/scan /path/to/output/all_rules.yar \
  --max-file-size 10485760 \
  --timeout 60 \
  --batch-size 100 \
  --output-format json \
  --output-file results.json \
  --rule-filter dir1_compiled_chunk_0.yar \
  --log-level INFO
```
- Scans files and saves results to `results.json`.
- Use `--rule-filter` to select specific rule files.

### Run Ansible Playbook
1. Update variables in `yara_automation.yml`:
   ```yaml
   yara_root_dir: "/path/to/yara/rules"
   output_dir: "/path/to/output"
   scan_dir: "/path/to/scan"
   output_format: "json"
   output_file: "/path/to/output/scan_results.json"
   rule_filter: ["dir1", "dir2"]
   ```
2. Run the playbook:
   ```bash
   ansible-playbook yara_automation.yml
   ```

## Configuration Options
- **compile_yara_rules.py**:
  - `--max-strings`: Max strings per rule (default: 10000).
  - `--max-match-data`: Max match data size (default: 1024).
  - `--chunk-size`: Rules per chunked file (default: 100).
  - `--rule-filter`: List of directory names to compile.
  - `--log-level`: Logging verbosity (DEBUG, INFO, WARNING, ERROR).

- **scan_yara_rules.py**:
  - `--max-workers`: Number of concurrent workers (default: CPU cores - 1).
  - `--max-file-size`: Max file size to scan (default: 10MB).
  - `--timeout`: Scan timeout per file (default: 60s).
  - `--batch-size`: Files per batch (default: 100).
  - `--output-format`: Output format (log, json, csv).
  - `--output-file`: File for json/csv output.
  - `--rule-filter`: List of rule file names to include.
  - `--log-level`: Logging verbosity.

## Notes
- Ensure sufficient memory for large rule sets; adjust `chunk-size` if needed.
- Use `--rule-filter` to reduce scan scope and improve performance.
- Check `compilation_error_report.json` for detailed errors, warnings, and line numbers for uncorrectable rules.
- Invalid macros and conditions are commented out to allow compilation; review error report for details.
- Pre-validation is performed in parallel to optimize performance for large rule sets.

## Troubleshooting
- **Syntax Errors**: Check `compilation_error_report.json` for specific errors, warnings, and line numbers.
- **Memory Issues**: Reduce `chunk-size` or increase system memory.
- **Missing Modules**: Ensure required YARA modules (e.g., `pe`, `hash`) are supported.
- **Invalid Macros/Conditions**: Invalid macro values or condition references are commented out; review error report for details.