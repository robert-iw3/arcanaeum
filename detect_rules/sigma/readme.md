# Sigma Rule Import Pipeline for OpenSearch and AWS OpenSearch

This pipeline automates importing Sigma rules from YAML files into OpenSearch or AWS OpenSearch Security Analytics. It features robust validation, parallel processing, bulk imports, error handling, metrics, and a GitHub Actions workflow for CI/CD. It automatically generates or replaces `id` fields if missing or duplicated, with optional dry-run and read-only modes.

## Prerequisites
- OpenSearch (2.x+) or AWS OpenSearch (2.5+) cluster
- Python 3.9+ (for local development)
- Docker (for containerized deployment)
- GitHub repository with Actions enabled (for CI/CD)
- AWS IAM credentials with `es:ESHttpPost` and `aoss:WriteDocument` permissions (for AWS OpenSearch)
- Write permissions for YAML directories (unless using `--read-only`)

## Setup

1. **Clone Repository**
   ```bash
   git clone <your-repo-url>
   cd <repo-directory>
   ```

2. **Configure Environment Variables**
   Create a `.env` file or set environment variables:
   ```bash
   OPENSEARCH_HOST=<your-opensearch-host>
   OPENSEARCH_PORT=<your-opensearch-port>
   OPENSEARCH_SCHEME=<http|https>
   OPENSEARCH_USERNAME=<your-username>  # For generic OpenSearch
   OPENSEARCH_PASSWORD=<your-password>  # For generic OpenSearch
   PROVIDER=<opensearch|aws>
   AWS_REGION=<your-aws-region>  # Required for AWS OpenSearch
   AWS_ACCESS_KEY_ID=<your-access-key>  # For AWS OpenSearch
   AWS_SECRET_ACCESS_KEY=<your-secret-key>  # For AWS OpenSearch
   AWS_SESSION_TOKEN=<your-session-token>  # Optional for AWS OpenSearch
   CONFIG_PATH=config.yaml
   METRICS_PORT=8000
   ```

3. **Configure Validation Rules**
   Edit `config.yaml` to customize validation (e.g., AWS logsource products, tag prefixes):
   ```yaml
   aws_logsource_products:
     - windows
     - cloudtrail
     - dns
     - vpcflow
     - s3
   valid_tag_prefixes:
     - attack.
     - threat_
   ```

4. **Install Dependencies**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

5. **Run Tests**
   ```bash
   python test_sigma_pipeline.py
   ```

6. **Import Rules Locally**
   ```bash
   python sigma_pipeline.py \
     --host $OPENSEARCH_HOST \
     --port $OPENSEARCH_PORT \
     --scheme $OPENSEARCH_SCHEME \
     --username $OPENSEARCH_USERNAME \
     --password $OPENSEARCH_PASSWORD \
     --provider $PROVIDER \
     --aws-region $AWS_REGION \
     --config $CONFIG_PATH \
     --metrics-port $METRICS_PORT \
     --directory <path-to-yaml-files> \
     --strict-tags \
     --max-files 1000 \
     --batch-size 100 \
     --dry-run \
     --read-only
   ```
   - `--provider`: Set to `opensearch` for generic OpenSearch or `aws` for AWS OpenSearch.
   - `--strict-tags`: Enforce tag naming from `config.yaml`. Use `--no-strict-tags` for non-standard tags.
   - `--max-files`: Limit the number of YAML files processed (default: 1000).
   - `--batch-size`: Number of rules per bulk import (default: 100).
   - `--dry-run`: Simulate imports without modifying OpenSearch or YAML files.
   - `--read-only`: Prevent YAML file updates (e.g., for ID generation).
   - `--config`: Path to configuration file (default: `config.yaml`).
   - `--metrics-port`: Port for Prometheus metrics (default: 8000).
   - The pipeline auto-generates a UUID for missing `id` fields and replaces duplicate `id`s in YAML files (unless `--read-only`).

7. **Docker Deployment**
   Build and run:
   ```bash
   docker build -t sigma-importer .
   docker run --rm --env-file .env -p 8000:8000 sigma-importer
   ```

8. **GitHub Actions**
   - Add secrets to your GitHub repository: `OPENSEARCH_HOST`, `OPENSEARCH_PORT`, `OPENSEARCH_SCHEME`, `OPENSEARCH_USERNAME`, `OPENSEARCH_PASSWORD`, `PROVIDER`, `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` (optional), and `SLACK_BOT_TOKEN` (optional for notifications).
   - The workflow (`.github/workflows/import-sigma-rules.yml`) runs on push, pull requests, or daily at midnight UTC.

9. **Monitoring**
   - Access Prometheus metrics at `http://<host>:8000` for import success/failure counts and durations.

## Directory Structure
- Place Sigma rule YAML files (`.yaml` or `.yml`) in subdirectories (e.g., `rules/windows/`).
- Example rule: See `rules/example.yaml` in the repository.
- Logs are written to `sigma_import.log` (rotated at 10MB, 5 backups) in JSON format.
- YAML files are updated in-place if `id` is missing or duplicated (unless `--read-only`).
- Configuration is defined in `config.yaml`.

## Troubleshooting
- Check `sigma_import.log` for error messages, including `id` generation or replacement (e.g., "Generated new ID for rule.yaml: ...").
- Ensure OpenSearch or AWS OpenSearch is accessible and credentials are valid.
- Verify YAML files follow Sigma specification (see SigmaHQ repository).
- For AWS OpenSearch, ensure IAM permissions include `es:ESHttpPost` or `aoss:WriteDocument` for Serverless.
- Use `--no-strict-tags` if custom tags cause validation failures.
- Use `--read-only` if YAML updates fail due to permissions.
- Use `--dry-run` to test imports without modifying files or OpenSearch.
- Adjust `--max-files` or `--batch-size` for large directories to optimize performance.
- Check Prometheus metrics at `http://<host>:8000` for import performance.