# YARA-L Pipeline for Google Security Operations

This pipeline automates the upload of YARA-L rules to Google Security Operations, with validation and parallel processing.

## Prerequisites
- Google Cloud service account key (`service-account.json`).
- Access to a Google Security Operations instance.
- Docker installed locally (optional for local runs).

## Setup
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```
2. Create a `rules` directory and add your `.yaral` files.
3. Update `config.yaml` with your Chronicle API URL and credentials path.
4. Place `service-account.json` in the project root.
5. Install dependencies (if running locally without Docker):
   ```bash
   pip install -r requirements.txt
   ```

## Running the Pipeline
- **Local (without Docker)**:
  ```bash
  python yaral_pipeline.py
  ```
- **Using Docker**:
  ```bash
  docker build -t yara-l-pipeline .
  docker run --rm \
    -e CHRONICLE_API_URL=https://<your_chronicle_instance>.backstory.chronicle.security/v2 \
    -e CREDENTIALS_FILE=/app/service-account.json \
    -e AUTH_SCOPE=https://www.googleapis.com/auth/chronicle-backstory \
    yara-l-pipeline
  ```

## GitHub Actions
- The pipeline runs automatically on push/PR to `main`.
- Set GitHub secrets: `CHRONICLE_API_URL` and `GOOGLE_CLOUD_CREDENTIALS`.
- Logs are uploaded as artifacts for debugging.

## Testing
Run unit tests to validate the pipeline:
```bash
python -m unittest test_yaral_pipeline.py
```

## Logs
Check `yara_pipeline.log` for detailed execution logs.