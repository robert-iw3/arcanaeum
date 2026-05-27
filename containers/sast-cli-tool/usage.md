# Static Code Analyzer

## Prerequisites
- **System**: Linux or macOS
- **Tools**:
  - Python 3.8+
  - Node.js 16+ and npm
  - Ansible 2.9+
  - Docker (optional, for containerized deployment)
- **Dependencies**: Install Python packages (`pyyaml`, `jsonschema`) and Node.js dependencies (React, Tailwind CSS)

## Setup Instructions

1. **Clone the Repository**
   ```bash
   git clone <repository-url>
   cd sast-cli-tool
   ```

2. **Backend Setup**
   - Place `languages.py`, `scanner.py`, and `config.yaml` in `~/static-code-analyzer/api`.
   - Install Python dependencies:
     ```bash
     pip install pyyaml jsonschema
     ```

3. **Frontend Setup**
   - Navigate to `~/static-code-analyzer/web-frontend`.
   - Install Node.js dependencies:
     ```bash
     npm install
     ```

4. **Deploy with Ansible**
   - Place `playbook.yml` in `~/static-code-analyzer`.
   - Set environment variables:
     ```bash
     export JWT_SECRET="your_jwt_secret"
     export DB_PASSWORD="your_db_password"
     ```
   - Run Ansible playbook:
     ```bash
     ansible-playbook playbook.yml
     ```

5. **Run the Scanner**
   - Scan a project:
     ```bash
     python -m static_code_analyzer.scanner -f ~/static-code-analyzer/test_project -o ~/static-code-analyzer/results/results.json --config ~/static-code-analyzer/config.yaml
     ```
   - Check logs at `/app/logs/analyzer.log`.

6. **Run the Frontend**
   - Start the development server:
     ```bash
     cd ~/static-code-analyzer/web-frontend
     npm run dev
     ```
   - Access at `http://localhost:3000`.
   - For production, build and deploy:
     ```bash
     npm run build
     ```
   - Access at `https://localhost:443` after Ansible deployment.

## Verification
- **Backend**: Verify `results.json` contains vulnerabilities and CVEs. Check `/app/logs/analyzer.log` for scan details.
- **Frontend**: View results at `http://localhost:3000` (dev) or `https://localhost:443` (prod). Toggle light/dark mode to confirm UI functionality.