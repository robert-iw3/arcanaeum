# Detection Rules Pipeline

This repository contains GitHub Actions workflows for automating threat detection rule imports across multiple security platforms. Each pipeline processes rules or queries from specific directories and deploys them to the respective platforms. Below is a guide to set up and operate these pipelines.

## Repository Structure
The pipelines are organized by platform, with each having its own directory and workflow file:
- **Crowdstrike**: `./crowdstrike` (`crowdstrike-pipeline.yml`)
- **Datadog**: `./datadog` (`datadog-pipeline.yml`)
- **Elastic Security (ESQL)**: `./elastic-security` (`esql-pipeline.yml`)
- **Azure Sentinel (KQL)**: `./kql` (`sentinel-pipeline.yml`)
- **Splunk**: `./splunk` (`splunk-pipeline.yml`)
- **Suricata**: `./suricata` (`suricata-pipeline.yml`)
- **YARA-L (Google SecOps)**: `./google-secops` (`yaral-pipeline.yml`)

Each pipeline triggers on file changes in the following directories on the `release` branch:
- Crowdstrike: `crowdstrike/queries/*`
- Datadog: `datadog/rules/*`
- Elastic Security: `elastic-security/queries/*`
- Azure Sentinel: `kql/queries/*`
- Splunk: `splunk/searches/*`
- Suricata: `suricata/custom/*`
- YARA-L: `google-secops/rules/*`

## Prerequisites
- A GitHub repository with the `release` branch.
- Access to GitHub repository settings to configure secrets and variables.
- Access to the target platforms (e.g., Datadog, Crowdstrike) with API credentials.
- Python 3.12 and Docker installed locally for testing (optional).

## Setup Instructions

### 1. Configure GitHub Secrets
Sensitive data is stored as GitHub Secrets. Navigate to your repository's **Settings > Secrets and variables > Actions > Secrets** and add the following secrets:

- **Datadog**:
  - `DD_API_KEY`: Datadog API key.
  - `DD_APP_KEY`: Datadog application key.
  - `SLACK_BOT_TOKEN`: Slack token for notifications.
- **Crowdstrike**:
  - `FALCON_CLIENT_ID`: Crowdstrike API client ID.
  - `FALCON_CLIENT_SECRET`: Crowdstrike API client secret.
- **Elastic Security (ESQL)**:
  - `KIBANA_URL`: Kibana instance URL.
  - `KIBANA_API_KEY`: Kibana API key.
  - `ES_HOST`: Elasticsearch host URL.
  - `CA_CERT_PATH`: Path to CA certificate (or store certificate content).
  - `SLACK_BOT_TOKEN`: Slack token for notifications.
- **Azure Sentinel**:
  - `AZURE_CLIENT_ID`: Azure service principal client ID.
  - `AZURE_TENANT_ID`: Azure tenant ID.
  - `AZURE_SUBSCRIPTION_ID`: Azure subscription ID.
  - `CODECOV_TOKEN`: Codecov token for coverage reports.
- **YARA-L (Google SecOps)**:
  - `CHRONICLE_API_URL`: Google Chronicle API URL.
  - `GOOGLE_CLOUD_CREDENTIALS`: Google Cloud service account JSON.
- **Splunk**:
  - `SPLUNK_USER`: Splunk username.
  - `SPLUNK_PASSWORD`: Splunk password.
  - `SLACK_BOT_TOKEN`: Slack token for notifications (if used).

For pipelines using the `production` environment (Datadog, Crowdstrike, ESQL, Splunk, YARA-L), create an environment named `production` in **Settings > Environments** and add the secrets there. Optionally, set protection rules (e.g., required reviewers) for added security.

### 2. Configure GitHub Variables
Non-sensitive configuration is stored as GitHub Variables in **Settings > Secrets and variables > Actions > Variables**:

- **Crowdstrike**:
  - `RULEGROUP_ID`: Crowdstrike rule group ID.
- **Elastic Security (ESQL)**:
  - `ES_INDEX`: Elasticsearch index (default: `kibana-saved-objects`).
  - `STREAM_TO`: Import target (default: `kibana`).
  - `OVERWRITE`: Overwrite existing objects (default: `true`).
- **Azure Sentinel**:
  - `RESOURCE_GROUP_NAME`: Azure resource group name.
  - `WORKSPACE_NAME`: Sentinel workspace name.
  - `AZURE_LOCATION`: Azure region.
  - `QUERY_PACK_NAME`: Sentinel query pack name.
- **Splunk**:
  - `SPLUNK_HOST`: Splunk host URL.
  - `SPLUNK_PORT`: Splunk port.
  - `APP_CONTEXT`: Splunk app context.
  - `SPLUNK_SSL_VERIFY`: SSL verification setting (`true` or `false`).
  - `CLEANUP_JSON`: JSON cleanup setting.
  - `POOL_SIZE`: Connection pool size.
  - `RATE_LIMIT_CALLS`: API rate limit calls.
  - `RATE_LIMIT_PERIOD`: API rate limit period.
  - `API_TIMEOUT`: API timeout duration.
  - `MAX_FILES`: Maximum files to process.
  - `VALIDATE_API`: API validation setting.
  - `CONFIG_PATH`: Path to Splunk config file.

### 3. Add Rules and Queries
Place rule or query files in the appropriate directories:
- **Crowdstrike**: Add FQL queries to `crowdstrike/queries/`.
- **Datadog**: Add rules to `datadog/rules/`.
- **Elastic Security**: Add ESQL queries to `elastic-security/queries/`.
- **Azure Sentinel**: Add KQL queries to `kql/queries/`.
- **Splunk**: Add search queries to `splunk/searches/`.
- **Suricata**: Add custom rules to `suricata/custom/`.
- **YARA-L**: Add rules to `google-secops/rules/`.

### 4. Run Pipelines
- Push changes to the `release` branch, ensuring files are added or modified in the directories above.
- Monitor pipeline execution in the **Actions** tab of your GitHub repository.
- Check artifacts (e.g., logs, JSON files) in the workflow run outputs.
- Review Slack notifications (if configured) in the `security-alerts` or `pipeline-notifications` channels.

### 5. Troubleshooting
- **Pipeline Failures**: Check logs in the Actions tab or downloaded artifacts (e.g., `pipeline.log`, `test_metrics.json`).
- **Secrets Errors**: Ensure secrets are correctly set in the `production` or `azure` environments.
- **Dependency Issues**: Verify `requirements.txt` files exist in each directory and contain compatible versions.
- **Docker Issues**: For ESQL and Splunk, ensure Docker is properly configured and images build successfully.

### 6. Customization
- **Tuning Rules**: Modify queries/rules to match your environment (e.g., data sources, indices).
- **Extending Pipelines**: Add new steps or pipelines by following the existing structure and updating secrets/variables.