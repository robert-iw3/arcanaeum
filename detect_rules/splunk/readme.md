# Splunk Query Pipeline

This pipeline automates the conversion of Markdown-based threat intelligence queries (stored in `.md` files within subdirectories) into JSON files in `./import/searches`, which are then uploaded to Splunk via API. It supports Splunk SPL syntax (e.g., macros with arguments, `index=`, `| tstats`), dynamically maps queries to CIM-compliant fields, validates queries using Splunk's API (`/services/search/validate`, `/services/search/parser`, `/services/saved/searches/validate`), normalizes query syntax, and corrects common errors. Custom configurations are defined in `config.json`.

## Prerequisites
- Docker installed
- Splunk instance (version 8.0+) accessible with API credentials
- `.env` file in the project root with:
  ```
  SPLUNK_HOST=your_splunk_host
  SPLUNK_PORT=8089
  SPLUNK_USER=admin
  SPLUNK_PASSWORD=your_password
  APP_CONTEXT=search
  SPLUNK_SSL_VERIFY=true
  CLEANUP_JSON=false
  POOL_SIZE=4
  RATE_LIMIT_CALLS=10
  RATE_LIMIT_PERIOD=60
  API_TIMEOUT=10
  MAX_FILES=1000
  VALIDATE_API=true
  CONFIG_PATH=/import/config.json
  ```
- `config.json` in the project root to define comment patterns, validation rules, normalization rules, and custom CIM mappings.

## Configuration File
Create a `config.json` file to customize parsing, validation, and normalization:
```json
{
  "comment_patterns": [
    {"pattern": "^\\s*--\\s*(.*)$", "extractor": "group(1)"},
    {"pattern": "^\\s*/\\*\\s*(.*?)\\s*\\*/\\s*$", "extractor": "group(1)"}
  ],
  "validation_rules": {
    "required_metadata": ["title"],
    "allowed_spl_commands": ["search", "table", "stats"],
    "allow_macros": true,
    "validate_macro_arguments": true,
    "allow_subsearches": true
  },
  "normalization_rules": {
    "standardize_case": true,
    "normalize_whitespace": true
  },
  "custom_cim_mappings": {
    "client_ip": "src_ip"
  }
}
```
- **comment_patterns**: Regex patterns for comment styles (e.g., `--`, `/* */`).
- **validation_rules**: Required metadata, allowed SPL commands, macro/subsearch permissions, and macro argument validation.
- **normalization_rules**: Standardize command case and normalize whitespace.
- **custom_cim_mappings**: Additional CIM field mappings.

## Markdown Structure for Threat Intelligence
Place `.md` files in subdirectories (e.g., `./APTs/somefile.md`, `./Intel/China/storm-2603.md`). Example:

```markdown
### Login Detection
```sql
// title: Admin Login Check
// field_map: user_id=user
search user_id=admin | table user_id
```

```sql
/* title: Macro Query */
/* description: Uses a macro with arguments */
`example_syntax_macro("admin", "192.168.1.1")` | stats count by user
```

```sql
-- title: Index Query
index=thisindex sourcetype=access_combined | stats count by clientip
```
```
- **Section Header**: `###` followed by a title (fallback query name).
- **Description**: Optional text before the SQL block, trimmed of leading `---`.
- **SQL Block**: Enclosed in ```sql ... ```, containing:
  - Comments (`--`, `#`, `//`, `/* */`, `# ... #`, `comment( -- ... )`) for metadata.
  - `field_map: old_field=new_field` for custom CIM mappings.
  - Splunk query (e.g., `search ...`, `index=...`, `` `macro(arg1, arg2)` ``).
- Queries are validated via Splunk APIs, normalized (e.g., lowercase commands), and corrected for syntax errors.
- Macros are validated against Splunk's macro definitions if `validate_macro_arguments` is true.

## Populating Threat Intelligence
1. **Create Markdown Files**:
   - Place `.md` files in subdirectories.
   - Include Splunk queries with macros, `index=`, or other SPL syntax.
2. **Configure `config.json`**:
   - Define comment patterns, validation rules, and normalization preferences.
3. **Validate Structure**:
   - Ensure required metadata (e.g., `title`) per `config.json`.
   - Queries are validated, normalized, and corrected dynamically.

## Launching the Pipeline
1. **Set Up Environment**:
   - Create `.env` and `config.json` files.
   - Place `.md` files in subdirectories.
2. **Build Docker Image**:
   ```bash
   docker build -f pipeline.Dockerfile -t splunk-pipeline .
   ```
3. **Run Pipeline**:
   ```bash
   docker run --env-file .env -v $(pwd)/import:/import -v $(pwd):/import/src splunk-pipeline
   ```
   - Processes `.md` files, applies CIM mappings, validates/corrects/normalizes queries, generates JSON, and uploads to Splunk.
   - Use `--dry-run` to test without API calls:
     ```bash
     docker run --env-file .env -v $(pwd)/import:/import -v $(pwd):/import/src splunk-pipeline --dry-run
     ```
4. **Verify Output**:
   - JSON files in `./import/searches` (e.g., `APTs_somefile_query.json`), removed if `CLEANUP_JSON=true`.
   - Logs detail CIM mappings, syntax corrections, normalization, and validation results.
5. **CI/CD (Optional)**:
   - Use `pipeline.yml` with GitHub Actions for automated runs.
   - Ensure `.env`, `config.json`, and secrets are configured.

## Pipeline Sequence
1. **Markdown Parsing**: Recursively finds `.md` files, parses comments per `config.json`, maps to CIM fields, corrects/normalizes queries, and converts to JSON.
2. **Query Validation**: Uses Splunk APIs (`/services/search/validate`, `/services/search/parser`, `/services/saved/searches/validate`) or basic checks, validating macro arguments.
3. **JSON Validation**: Validates JSON against a schema.
4. **Splunk Import**: Authenticates, creates/updates saved searches, and sets ACLs.
5. **Cleanup (Optional)**: Removes JSON files if `CLEANUP_JSON=true`.