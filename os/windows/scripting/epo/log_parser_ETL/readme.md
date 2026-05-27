# Trellix Log Parser Pipeline

This application processes Trellix Endpoint Security (ENS), Agent, and Application Control logs, transforms them into JSON formats (enhanced Splunk CIM, Elastic ECS, or standard JSON), and ships them to one or more specified SIEMs (including Splunk on-prem/cloud, Elastic on-prem/cloud, OpenSearch on-prem/AWS). It runs in a container (Docker or Podman) and can be deployed via Ansible.

The ETL pipeline has been holistically enhanced:
- **Extract**: Improved parsing to handle multiple Trellix log formats (modern pipe-separated, legacy I/E/W severity, and simple tab-separated date formats).
- **Transform**: Enhanced mapping to Splunk CIM (Malware model compliance) and Elastic ECS (threat fields, event categorization). Additional message parsing extracts key fields like user, detection, action, file_path.
- **Load**: Batched shipping with retries, supports multiple SIEMs independently.

## Prerequisites
- Docker or Podman installed.
- Access to Trellix log directories: (you will have to validate where your logs are stored and then mount the volume to docker)
  - Windows: `%ProgramData%\McAfee`, `%ProgramData%\Trellix`, `%TEMP%\McAfeeLogs`, `%TEMP%\TrellixLogs`, `C:\Windows\Temp\McAfeeLogs`, `C:\Windows\Temp\TrellixLogs`.
  - Linux/macOS: `/var/McAfee`, `/var/log/mcafee`, `/var/Trellix`, `/var/log/trellix`.
- SIEM endpoint details (URL, token/API key).
- For AWS OpenSearch: Set AWS credentials as environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN) and mount them to the container if needed.
- Ansible (for playbook deployment).

## Setup
1. **Create the project directory** with:
   - `universal_log_parser.py`
   - `config.json`
   - `Dockerfile`
   - `requirements.txt`
   - `deploy_log_parser.yml` (for Ansible)
   - Test logs: `sample_text.log`, `sample_csv.log`, `sample_xml.log` (for testing parsing)

2. **Configure `config.json`**:
   - **SIEM Configuration** (supports multiple SIEMs):
     - **Splunk (on-prem or cloud)**: Set `type: splunk`, `endpoint` to HEC URL (e.g., `https://<host>:8088/services/collector/event` for on-prem, `https://input-<instance>.cloud.splunk.com:8088/services/collector/event` for cloud), `token` to HEC token, `index` (e.g., `trellix_logs`), and `sourcetype` (e.g., `trellix_log`). Use `ca_cert` for self-signed certificates.
     - **Elasticsearch (on-prem or cloud)**: Set `type: elastic`, `endpoint` to `https://<host>:9200` (or cloud endpoint), `token` for API key (base64 encoded 'id:api_key'), `username`/`password` for basic auth (optional), `index` (required), and `ca_cert` for self-signed certificates.
     - **OpenSearch (on-prem or AWS)**: Set `type: opensearch`, `endpoint` to `https://<host>:9200` (or AWS domain), `token` for API key, `aws_region` for AWS SigV4 auth (uses env credentials), `username`/`password` for basic auth (optional), `index` (required).
     - **Standard JSON**: Set `type: standard`, `endpoint` to SIEM API URL, and `token` if required.
     - **CA Certificate**: Set `ca_cert` to `/app/certs/ca.pem` for self-signed/custom CAs; use `null` for trusted CAs (e.g., DigiCert). Mount certificate in Docker (`-v ./certs:/app/certs`).
     - **Batch Size**: Set `batch_size` per SIEM to control shipping frequency.

3. **Build the container**:
   - Docker:
     ```bash
     docker build -t trellix-log-parser .
     ```
    - Podman:
     ```bash
     podman build -t trellix-log-parser .
     ```

4. **Run manually**:
    - Docker (add env for AWS if needed):
     ```bash
     docker run -v /var/log/trellix:/var/log/trellix \
           -v /var/McAfee:/var/Trellix \
           -v /var/McAfee:/var/McAfee \
           -v /var/log/mcafee:/var/log/mcafee \
           -e AWS_ACCESS_KEY_ID=your_key \
           -e AWS_SECRET_ACCESS_KEY=your_secret \
           -e AWS_SESSION_TOKEN=your_token \
           -d trellix-log-parser
      ```
    - Podman (similar, add :Z for SELinux):
    ```bash
    podman run -v /var/log/trellix:/var/log/trellix:Z \
           -v /var/McAfee:/var/Trellix:Z \
           -v /var/McAfee:/var/McAfee:Z \
           -v /var/log/mcafee:/var/log/mcafee:Z \
           -e AWS_ACCESS_KEY_ID=your_key \
           -e AWS_SECRET_ACCESS_KEY=your_secret \
           -e AWS_SESSION_TOKEN=your_token \
           -d trellix-log-parser
    ```
    - For Windows, use paths like -v C:/ProgramData/McAfee:/var/log/trellix.

5. **Deploy with Ansible**:
    - Run the playbook:
    ```bash
    ansible-playbook deploy_log_parser.yml -e "container_runtime=docker"
    ```
    - or
    ```bash
    ansible-playbook deploy_log_parser.yml -e "container_runtime=podman"
    ```
    - Ensure `config.json` is in `/etc/trellix-log-parser/` on the target host. Update the playbook to pass AWS env vars if needed.

## Rule Upload Usage

**JSON Rules**: Place JSON rule files in `/app/rules`. See `rules/example_rule.json`.

**Markdown Rules**: Place markdown files with `TCL`, `JSON`, or `YAML` rules in `/app/rules_markdown`.

**Dry Run**: Set `epo.dry_run`: true to test without uploading.

**Logs**: Check `/app/logs/rules_upload.log` for processing details.

## Notes

**Permissions**: On Windows, run with administrative privileges. On Linux, ensure read access to log directories.

**Log Rollover**: Processes `.log` and archived logs (e.g., .log.1).

**Debug Logging**: Enable via Trellix ePO for detailed logs.

**Monitoring**: Check `/app/logs/pipeline.log` in the container for metrics.

**Validation**: Log lines are validated against multiple Trellix formats.

**Multiple SIEMs**: Logs are transformed and shipped independently to each configured SIEM with type-specific formats (enhanced CIM for Splunk, ECS for Elastic/OpenSearch).

**AWS OpenSearch**: Ensure AWS credentials are set in environment variables for SigV4 signing.

**Test Logs**: Use the provided sample log files to test parsing. Mount them to the container if needed, e.g., -v ./sample_text.log:/var/log/trellix/test.log

## Troubleshooting

**File access errors**: Verify mounted directories exist and are accessible.

**SIEM failures**: Check endpoint, token/API key, AWS credentials, and network.

**Invalid logs**: Ensure `log_format` matches log type. Invalid lines are logged to `/app/logs/pipeline.log`. If logs don't match expected formats, they may be skipped.

**Auth issues**: For AWS, verify env vars; for API keys, ensure correct format (base64 'id:api_key').

**Transformation issues**: If message parsing fails to extract fields, original parsed data is still included under "trellix" or "event".