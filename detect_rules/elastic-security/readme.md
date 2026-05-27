# ESQL Pipeline Automation

This Dockerized pipeline converts markdown files with ESQL queries (in ```sql``` blocks) into ECS-compliant JSON rules, merges them into a single NDJSON file, and imports it into Kibana or Elasticsearch with mandatory TLS certificate verification. It supports all MITRE ATT&CK matrices (Enterprise, Mobile, ICS) and dynamically transforms non-ECS-compliant query fields to the Elastic Common Schema (ECS) version 9.1.0.

## Prerequisites
- Docker or Podman
- Kibana/Elasticsearch instance with valid TLS certificates
- **CA Certificate for Self-Signed Certificates**:
  - For on-prem Elasticsearch/Kibana with self-signed certificates, retrieve the CA certificate (`http_ca.crt`) using `get_ca_cert.sh`:
    ```bash
    ./get_ca_cert.sh --container <elasticsearch-container-name> --output ca.crt
    ```
    Or for VM/host:
    ```bash
    ./get_ca_cert.sh --host <elasticsearch-host> --user <ssh-user> --output ca.crt
    ```
  - Mount `ca.crt` into the Docker container and specify via `--ca-cert-path` or `CA_CERT_PATH`.
- GitHub repository with Actions enabled
- Environment variables: `KIBANA_URL`, `KIBANA_API_KEY` or `ES_HOST`, `ES_INDEX`
- Internet access for fetching MITRE ATT&CK data

## Setup
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd <repository>
   ```
2. Retrieve the CA certificate:
   ```bash
   ./get_ca_cert.sh --container elasticsearch --output ca.crt
   ```
3. Create markdown files with ESQL queries and metadata:
   ```markdown
   ---
   name: My Rule
   description: Detects suspicious activity
   severity: high
   tags: [Security, ESQL]
   matrix: enterprise
   tactics:
     - id: TA0001
       techniques:
         - id: T1190
         - id: T1078.001
   ---
   ```sql
   from winlogbeat-* | where hostname = 'test' and event_id = '5136'
   ```
   ```
   - Non-ECS fields (e.g., `hostname`, `event_id`) are transformed to ECS (e.g., `host.name`, `winlog.event_id`).
   - Unmapped fields are stored under `labels.` (e.g., `custom_field` → `labels.custom_field`).
   - Mobile example:
     ```markdown
     ---
     name: Mobile Rule
     matrix: mobile
     tactics:
       - id: TA0027
         techniques:
           - id: T1635
     ---
     ```sql
     from logs-* | where client_ip = '192.168.1.1'
     ```
     ```
   - ICS example:
     ```markdown
     ---
     name: ICS Rule
     matrix: ics
     tactics:
       - id: TA0104
         techniques:
           - id: T0865
     ---
     ```sql
     from logs-* | where server = 'ics'
     ```
     ```
   - Header-based MITRE ATT&CK:
     ```markdown
     ## MITRE ATT&CK
     - Matrix: enterprise
     - Tactic: TA0001, Techniques: T1190, T1078.001
     ```sql
     from logs-* | where src_ip = '10.0.0.1'
     ```
     ```
4. (Optional) Create `config.yaml`:
   ```yaml
   kibana_url: https://your-kibana:5601
   api_key: your-api-key
   es_host: https://your-elasticsearch:9200
   es_index: kibana-saved-objects
   batch_size: 1000
   ca_cert_path: /app/ca.crt
   ```

## ECS Field Mappings
- Queries are transformed to ECS 9.1.0 fields [Elastic ECS Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html).
- Common mappings:
  - `hostname`, `server` → `host.name`
  - `src_ip`, `client_ip` → `source.ip`
  - `dst_ip`, `dest_ip` → `destination.ip`
  - `username` → `user.name`
  - `event_id` → `winlog.event_id`
- Unmapped fields are stored under `labels.` (e.g., `custom_field` → `labels.custom_field`).
- Original query is preserved in `meta.original_query` for auditing.

## Build and Run
1. Build the Docker image:
   ```bash
   docker build -t esql-pipeline .
   ```
2. Run for Kibana import:
   ```bash
   docker run --rm \
     -e KIBANA_URL=https://your-kibana:5601 \
     -e KIBANA_API_KEY=your-api-key \
     -e CA_CERT_PATH=/app/ca.crt \
     -v $(pwd):/app \
     -v $(pwd)/ca.crt:/app/ca.crt \
     esql-pipeline
   ```
3. Run for Elasticsearch import:
   ```bash
   docker run --rm \
     -e ES_HOST=https://your-elasticsearch:9200 \
     -e ES_INDEX=kibana-saved-objects \
     -e STREAM_TO=elasticsearch \
     -e CA_CERT_PATH=/app/ca.crt \
     -v $(pwd):/app \
     -v $(pwd)/ca.crt:/app/ca.crt \
     esql-pipeline
   ```

## Run Tests
```bash
docker run --rm esql-pipeline python -m unittest test_esql_pipeline.py -v
```

## GitHub Actions
- Configure secrets: `KIBANA_URL`, `KIBANA_API_KEY`, `ES_HOST`, `CA_CERT_PATH`, `SLACK_BOT_TOKEN`.
- Outputs NDJSON, logs, and CA certificate artifacts.

## Troubleshooting
- Check `import/final/pipeline.log` for errors.
- Verify `ca.crt` is mounted and valid for TLS.
- Test Kibana connectivity:
  ```bash
  curl --cacert ca.crt -H "Authorization: ApiKey your-api-key" https://your-kibana:5601/api/status
  ```
- For ECS issues, ensure queries use supported fields or rely on automatic transformation.
- For MITRE issues, verify internet access or check logs for invalid IDs.

## Directory Structure
```
├── config.yaml
├── esql_pipeline.py
├── test_esql_pipeline.py
├── get_ca_cert.sh
├── requirements.txt
├── Dockerfile
├── ca.crt
├── import/
│   ├── rules-editing/
│   ├── final/
├── *.md/**/*.md
```