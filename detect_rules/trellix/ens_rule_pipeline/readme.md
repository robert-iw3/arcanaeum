# Trellix ENS Rule Upload Pipeline

## Overview
This project provides a Python-based pipeline to upload Trellix Endpoint Security (ENS) rules to an ePO server. It processes rules from JSON files in `/app/rules` and markdown files in `/app/rules_markdown`, validates their syntax, corrects common issues, and uploads them via the ePO API. The pipeline runs in a Docker container and supports dry-run mode for validation.

## Updates (January 10, 2026)
- Updated to Python 3.14.2.
- Library updates: requests>=2.32.5, urllib3>=2.6.3, certifi>=2026.1.4, pyyaml>=6.0.3.
- Enhanced error handling: Specific exceptions, API retries with backoff, TCL syntax validation for expert rules.
- Rule corrections: Auto-fix common TCL issues (e.g., add Reaction BLOCK, unique -xtype).
- Improved markdown parsing: Better rule type mapping from "Rule Class".

## Requirements
- Python 3.11+
- Docker or Podman
- Trellix ePO server access
- Dependencies listed in `requirements.txt`
- Optional: CA certificate (`ca.pem`) for ePO servers with self-signed/custom CA certificates

## Setup
1. **Clone the Repository**:
   ```bash
   git clone <repository_url>
   cd <this directory>
   ```

2. **Configure**:
   - Edit `config.json` with ePO server details, rules directories, and optional CA certificate.
   - Example:
     ```json
     {
         "epo_server": "epo.example.com",
         "epo_username": "admin",
         "epo_password": "secure_password",
         "rules_dir": "/app/rules",
         "markdown_rules_dir": "/app/rules_markdown",
         "batch_size": 10,
         "dry_run": true,
         "group_id": null,
         "ca_cert": "/app/certs/ca.pem"
     }
     ```
   - **CA Certificate**: Set `ca_cert` to the path of `ca.pem` if the ePO server uses a self-signed/custom CA. Use `null` if the server’s certificate is signed by a trusted CA (e.g., DigiCert).

3. **Build and Run**:
   ```bash
   docker build -t trellix-ens-rule-upload .
   docker run -v $(pwd)/rules:/app/rules -v $(pwd)/rules_markdown:/app/rules_markdown -v $(pwd)/certs:/app/certs -v $(pwd)/logs:/app/logs trellix-ens-rule-upload
   ```

## Usage
- **JSON Rules**: Place JSON rule files in `/app/rules`. See `rules/example_rule.json` for format.
- **Markdown Rules**: Place markdown files with TCL, JSON, or YAML rules in `/app/rules_markdown`. Rules are extracted from ````tcl`, ````text`, ````json`, or ````yaml` code blocks.
- **Dry Run**: Set `"dry_run": true` in `config.json` to test without uploading.
- **CA Certificate**: Mount the CA certificate (e.g., `-v $(pwd)/certs:/app/certs`) if `ca_cert` is specified.
- **Logs**: Check `/app/logs/rules_upload.log` for processing details.

## Rule Formats
- **JSON Rules** (e.g., `example_rules.json`):
  - Access Protection: `name`, `executables`, `target`, `subrule`, `operations`, `action`, `severity`, `enabled`.
  - Expert: `name`, `content`, `action`, `severity`, `enabled`.
  - Firewall: `name`, `application`, `direction`, `protocol`, `port`, `action`, `enabled`.
- **Markdown Rules**:
  - TCL Expert Rules in ````tcl` or ````text` blocks, mapped to `type: expert`.
  - JSON/YAML rules in ````json` or ````yaml` blocks, supporting Access Protection, Expert, or Firewall.
  - Metadata: `Description`, `Rule Class` (e.g., Process, Registry, File, Value, Section), `Notes`, `Tested Platforms`.
  - `Rule Class` may influence rule type (e.g., `File` → Access Protection).
  - Expert Rules: TCL content validated for balanced braces, required keywords (Process, Target).

## Deployment
Use the provided Ansible playbook (`deploy_rules_upload.yml`) for automated deployment:
```bash
ansible-playbook deploy_rules_upload.yml
```

## Monitoring
- Logs: `/app/logs/rules_upload.log`
- Metrics: Processed rules, corrected rules, errors logged at completion.

## Notes
- Ensure ePO server is reachable and credentials are valid.
- If using a self-signed/custom CA, provide `ca.pem` and update `ca_cert` in `config.json`.
- Markdown files must contain valid TCL, JSON, or YAML syntax.
- Fine-tune Expert Rules to avoid false positives, as noted in markdown files.