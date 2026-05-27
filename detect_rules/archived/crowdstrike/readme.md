# CrowdStrike Falcon IOA Import Pipeline [In-Progress/Testing]

## Quick Setup
1. **Customize config.yaml**: Edit for your paths, defaults, API settings.
2. **Install Dependencies**: `pip install crowdstrike-falconpy pyyaml`
3. **Run Generate**: `python pipeline.py --generate` (scans .md in input_dir, outputs JSONs to output_dir)
4. **Run Upload**: Set env vars `FALCON_CLIENT_ID` and `FALCON_CLIENT_SECRET`, then `python pipeline.py --upload [--rulegroup_id <id>]`
   - API creds from Falcon console.
   - Override rulegroup_id if needed.

## Docker Usage
- Build: `docker build -t falcon-pipeline .`
- Generate: `docker run -v $(pwd):/app falcon-pipeline`
- Upload: `docker run -v $(pwd):/app -e FALCON_CLIENT_ID=your_id -e FALCON_CLIENT_SECRET=your_secret falcon-pipeline python pipeline.py --upload`

## CI/CD
- **GitHub**: Generates on push to main. Manual upload (set secrets/vars).
- **GitLab**: Generates on main. Manual upload (set variables).

## Notes
- .md files in input_dir or subs.
- Queries parsed to field_values; complex may fail, check logs.
- Secure: Secrets via env vars.
- Future: Improve parser for complex queries, add validation.