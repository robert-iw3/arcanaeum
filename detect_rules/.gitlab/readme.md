# Detection Rules Pipeline (GitLab CI/CD)

This repository contains GitLab CI/CD pipelines for automating threat detection rule imports across multiple security platforms. Each pipeline processes rules or queries from specific directories and deploys them to the respective platforms. This README provides instructions for setting up secrets and variables, adding rules/queries, and executing the pipelines.

## Repository Structure
The pipelines are organized by platform, with each having its own directory and `.gitlab-ci.yml` file under the `.gitlab` folder:
- **Crowdstrike**: `.gitlab/crowdstrike/.gitlab-ci.yml` (processes `crowdstrike/queries/*`)
- **Datadog**: `.gitlab/datadog/.gitlab-ci.yml` (processes `datadog/rules/*`)
- **Elastic Security (ESQL)**: `.gitlab/elastic-security/.gitlab-ci.yml` (processes `elastic-security/queries/*`)
- **Azure Sentinel (KQL)**: `.gitlab/kql/.gitlab-ci.yml` (processes `kql/queries/*`)
- **Splunk**: `.gitlab/splunk/.gitlab-ci.yml` (processes `splunk/searches/*`)
- **Suricata**: `.gitlab/suricata/.gitlab-ci.yml` (processes `suricata/custom/*`)
- **YARA-L (Google SecOps)**: `.gitlab/google-secops/.gitlab-ci.yml` (processes `google-secops/rules/*`)

Each pipeline triggers on file changes in the specified directories on the `release` branch.

## Prerequisites
- A GitLab project with the `release` branch.
- Access to GitLab project settings to configure CI/CD variables and environments.
- Access to the target platforms (e.g., Datadog, Crowdstrike) with API credentials.
- Python 3.12 and Docker installed locally for testing (optional).
- A `.dockerignore` file in `elastic-security` and `splunk` directories to exclude unnecessary files (e.g., `.git`, `*.md`) from Docker builds.

## Setup Instructions

### 1. Configure GitLab CI/CD Variables
Secrets and configuration variables are managed in **Settings > CI/CD > Variables** in your GitLab project. Add the following variables, ensuring sensitive ones are marked as `protected` and `masked`.

#### Secrets (Set as `protected` and `masked`)
- **Datadog**:
  - `DD_API_KEY`: Datadog API key (Environment: `production`)
  - `DD_APP_KEY`: Datadog application key (Environment: `production`)
  - `SLACK_BOT_TOKEN`: Slack token for notifications (Environment: `production`)
- **Crowdstrike**:
  - `FALCON_CLIENT_ID`: Crowdstrike API client ID (Environment: `production`)
  - `FALCON_CLIENT_SECRET`: Crowdstrike API client secret (Environment: `production`)
- **Elastic Security (ESQL)**:
  - `KIBANA_URL`: Kibana instance URL (Environment: `production`)
  - `KIBANA_API_KEY`: Kibana API key (Environment: `production`)
  - `ES_HOST`: Elasticsearch host URL (Environment: `production`)
  - `CA_CERT_PATH`: Path to CA certificate or certificate content (Environment: `production`)
  - `SLACK_BOT_TOKEN`: Slack token for notifications (Environment: `production`)
- **Azure Sentinel**:
  - `AZURE_CLIENT_ID`: Azure service principal client ID (Environment: `azure`)
  - `AZURE_TENANT_ID`: Azure tenant ID (Environment: `azure`)
  - `AZURE_SUBSCRIPTION_ID`: Azure subscription ID (Environment: `azure`)
  - `CODECOV_TOKEN`: Codecov token for coverage reports (Environment: `azure`)
- **YARA-L (Google SecOps)**:
  - `CHRONICLE_API_URL`: Google Chronicle API URL (Environment: `production`)
  - `GOOGLE_CLOUD_CREDENTIALS`: Google Cloud service account JSON (Environment: `production`)
- **Splunk**:
  - `SPLUNK_USER`: Splunk username (Environment: `production`)
  - `SPLUNK_PASSWORD`: Splunk password (Environment: `production`)

#### Variables (Non-sensitive, not masked)
- **Crowdstrike**:
  - `RULEGROUP_ID`: Crowdstrike rule group ID (Environment: `production`)
- **Elastic Security (ESQL)**:
  - `ES_INDEX`: Elasticsearch index (default: `kibana-saved-objects`, Environment: `production`)
  - `STREAM_TO`: Import target (default: `kibana`, Environment: `production`)
  - `OVERWRITE`: Overwrite existing objects (default: `true`, Environment: `production`)
- **Azure Sentinel**:
  - `RESOURCE_GROUP_NAME`: Azure resource group name (Environment: `azure`)
  - `WORKSPACE_NAME`: Sentinel workspace name (Environment: `azure`)
  - `AZURE_LOCATION`: Azure region (Environment: `azure`)
  - `QUERY_PACK_NAME`: Sentinel query pack name (Environment: `azure`)
- **Splunk**:
  - `SPLUNK_HOST`: Splunk host URL (Environment: `production`)
  - `SPLUNK_PORT`: Splunk port (Environment: `production`)
  - `APP_CONTEXT`: Splunk app context (Environment: `production`)
  - `SPLUNK_SSL_VERIFY`: SSL verification setting (`true` or `false`, Environment: `production`)
  - `CLEANUP_JSON`: JSON cleanup setting (Environment: `production`)
  - `POOL_SIZE`: Connection pool size (Environment: `production`)
  - `RATE_LIMIT_CALLS`: API rate limit calls (Environment: `production`)
  - `RATE_LIMIT_PERIOD`: API rate limit period (Environment: `production`)
  - `API_TIMEOUT`: API timeout duration (Environment: `production`)
  - `MAX_FILES`: Maximum files to process (Environment: `production`)
  - `VALIDATE_API`: API validation setting (Environment: `production`)
  - `CONFIG_PATH`: Path to Splunk config file (Environment: `production`)

#### Environment Setup
1. Go to **Settings > CI/CD > Variables**.
2. Add each variable, selecting the appropriate `Environment scope` (`production` or `azure`).
3. For secrets, enable `Protected` (to restrict to protected branches like `release`) and `Masked` (to hide in logs).
4. Save changes.

### 2. Set Up Environments
Create environments in **Deployments > Environments**:
- **production**: For Datadog, Crowdstrike, ESQL, Splunk, and YARA-L pipelines.
- **azure**: For Azure Sentinel pipeline.
- Optionally, enable protected environment settings (e.g., require approval) for added security.

### 3. Add Rules and Queries
Place rule or query files in the appropriate directories:
- **Crowdstrike**: Add FQL queries to `crowdstrike/queries/`.
- **Datadog**: Add rules to `datadog/rules/`.
- **Elastic Security**: Add ESQL queries to `elastic-security/queries/`.
- **Azure Sentinel**: Add KQL queries to `kql/queries/`.
- **Splunk**: Add search queries to `splunk/searches/`.
- **Suricata**: Add custom rules to `suricata/custom/`.
- **YARA-L**: Add rules to `google-secops/rules/`.

Ensure a `requirements.txt` file exists in each directory (`datadog`, `kql`, `google-secops`) with dependencies using `>=` for latest compatible versions. For example:
```text
pyyaml>=6.0.2
datadog-api-client>=2.25.0
urllib3>=2.2.3
jsonschema>=4.23.0
coverage>=7.6.1
```

### 4. Run Pipelines
1. Push changes to the `release` branch, ensuring files are added or modified in the directories listed above.
2. Monitor pipeline execution in **CI/CD > Pipelines** in your GitLab project.
3. Check artifacts (e.g., logs, JSON files) in the job outputs under **CI/CD > Jobs**.
4. Review Slack notifications (if configured) in the `security-alerts` or `pipeline-notifications` channels.

### 5. Troubleshooting
- **Pipeline Failures**: Check logs in the job output or downloaded artifacts (e.g., `pipeline.log`, `test_metrics.json`).
- **Secrets Errors**: Verify variables are set with correct `Environment scope` in **Settings > CI/CD > Variables**.
- **Dependency Issues**: Ensure `requirements.txt` files exist and specify compatible versions with `>=`.
- **Docker Issues**: For ESQL and Splunk, verify the `Dockerfile` builds with Python 3.12 and includes all dependencies. Add a `.dockerignore` to exclude unnecessary files:
  ```text
  .git
  *.md
  __pycache__
  *.pyc
  ```
- **Suricata Validation**: If Suricata is not installed, validation is skipped; ensure the Suricata binary is available in the environment if required.
- **Azure Login**: Ensure `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, and `AZURE_SUBSCRIPTION_ID` are correctly set and have sufficient permissions.

### 6. Customization
- **Tuning Rules**: Adjust queries/rules to match your environment (e.g., data sources, indices).
- **Extending Pipelines**: Add new jobs or pipelines by following the existing structure and updating variables.
- **Caching**: Pipelines cache Python dependencies in `.cache/pip`. Clear the cache in **CI/CD > Pipelines** if dependency issues occur.
- **Artifacts**: Artifacts expire after 7 days. Adjust `expire_in` in the `.gitlab-ci.yml` files if longer retention is needed.

For detailed logs and outputs, refer to the artifacts section of each job run. For contributions, open a merge request or issue in the GitLab project.