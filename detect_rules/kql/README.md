# Azure Sentinel KQL Import Pipeline

Automates importing KQL queries into Azure Sentinel with validation, CI/CD, and monitoring.

## Prerequisites
- **Azure Credentials**:
  - Environment variables: `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`, `SUBSCRIPTION_ID`, `RESOURCE_GROUP_NAME`, `WORKSPACE_NAME`, `AZURE_LOCATION` (default: `eastus2`), `QUERY_PACK_NAME` (default: `DefaultQueryPack`).
  - Permissions: `Log Analytics Contributor` on the target workspace.
- **Tools**:
  - Python 3.11+
  - Dependencies: See `requirements.txt` for pinned versions.
  - GitHub Actions or Azure DevOps for CI/CD (optional).
  - Docker (optional).
- **KQL Files**:
  - Place `.kql` files in `./queries/` or a subdirectory.
  - Queries must follow [Microsoft Sentinel KQL best practices](https://docs.microsoft.com/en-us/azure/sentinel/kql-best-practices).
  - Metadata format:
    ```kql
    // Name: Query Name
    // Description: Line 1
    // of a multi-line description
    // Tags: tag1, tag2
    ```

## Setup
1. **Set Environment Variables**:
   ```bash
   export AZURE_CLIENT_ID=<your_client_id>
   export AZURE_CLIENT_SECRET=<your_client_secret>
   export AZURE_TENANT_ID=<your_tenant_id>
   export SUBSCRIPTION_ID=<your_subscription_id>
   export RESOURCE_GROUP_NAME=<your_resource_group>
   export WORKSPACE_NAME=<your_workspace>
   export AZURE_LOCATION=eastus2
   export QUERY_PACK_NAME=DefaultQueryPack
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Local Execution
1. Clone the repository and navigate to its directory.
2. Place KQL files in `./queries/`.
3. Run the pipeline:
   ```bash
   python sentinel_pipeline.py
   ```
   - Outputs JSON to `./import/` and imports queries to Sentinel.
   - Logs saved to `sentinel_pipeline.log`.
   - Metrics at `http://localhost:8000` (Prometheus).

## Docker Execution
1. Build and run:
   ```bash
   docker build -t sentinel-pipeline .
   docker run -e AZURE_CLIENT_ID=<id> -e AZURE_CLIENT_SECRET=<secret> -e AZURE_TENANT_ID=<tenant> \
     -e SUBSCRIPTION_ID=<sub> -e RESOURCE_GROUP_NAME=<rg> -e WORKSPACE_NAME=<ws> \
     -e AZURE_LOCATION=eastus2 -e QUERY_PACK_NAME=DefaultQueryPack -p 8000:8000 sentinel-pipeline
   ```

## CI/CD Execution
- **GitHub Actions**:
  - Configure secrets: `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`, `SUBSCRIPTION_ID`, `RESOURCE_GROUP_NAME`, `WORKSPACE_NAME`, `AZURE_LOCATION`, `QUERY_PACK_NAME`, `CODECOV_TOKEN` (optional).
  - Workflow (`sentinel_pipeline.yml`) runs on push/PR to `main` or manually.
  - Includes static analysis (`flake8`) and KQL linting.
  - Secure secrets using GitHub's encrypted secrets.
- **Azure DevOps**:
  - Configure variables: `AZURE_SUBSCRIPTION_ID`, `RESOURCE_GROUP_NAME`, `WORKSPACE_NAME`, `AZURE_LOCATION`, `QUERY_PACK_NAME`.
  - Set up `AZURE_SERVICE_CONNECTION` (use service principal with minimal permissions).
  - Pipeline (`azure-pipelines.yml`) runs on push/PR to `main` with linting.

## Monitoring
- **Logs**: Structured JSON logs in `sentinel_pipeline.log`.
- **Metrics**: Prometheus metrics (e.g., `pipeline_queries_imported_total`, `kql_validation_success_total`, `metadata_parsing_errors_total`) at `http://localhost:8000` or CI/CD artifacts.
- **Coverage**: Reports in `coverage.xml` (CI/CD artifacts).

## Troubleshooting
- Verify environment variables and permissions.
- Check `sentinel_pipeline.log` for errors (e.g., KQL validation, metadata parsing, API issues).
- Ensure KQL queries include `TimeGenerated` filters and avoid deprecated operators.
- Monitor `metadata_parsing_errors_total` for metadata issues.

## Security
- Use pinned dependencies (`requirements.txt`) to avoid supply chain attacks.
- Store credentials in secure CI/CD secrets or environment variables.
- Ensure `Log Analytics Contributor` is the only role assigned to the service principal.

### kql
---

Kusto Query Language (KQL) is a powerful, read-only query language developed by Microsoft for exploring and analyzing large datasets. It is primarily used within Azure services like Azure Data Explorer, Azure Monitor Log Analytics, and Azure Sentinel for tasks such as:

Log Analytics:

Querying and analyzing log data from various sources to identify patterns, anomalies, and potential issues.

Big Data Analytics:

Exploring and gaining insights from massive datasets stored in Azure Data Explorer.

Security Information and Event Management (SIEM):

Analyzing security-related logs to detect threats and manage incidents in Azure Sentinel.

https://learn.microsoft.com/en-us/kusto