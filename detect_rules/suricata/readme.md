# Suricata Rule Transformation Pipeline

This pipeline processes, validates, and transforms Suricata rules from the `./custom` directory into a standardized format in the `./transformed_rules` directory, compatible with Suricata 7.0+.

## Prerequisites
- Python 3.9+
- Suricata 7.0+ (for validation)
- `pyyaml` package
- Dataset files referenced in rules (e.g., `./datasets/*.list`)

## Steps to Use the Pipeline

1. **Place Rules**: Add Suricata `.rules` files to the `./custom` directory.
2. **Ensure Dataset Files**: Place dataset files (e.g., `malicious_ips_cve_2025_53770.list`) in `./datasets`.
3. **Run Script**: Execute the transformation script:
   ```bash
   python parse_suricata_rules.py
   ```
4. **Verify Output**: Check `./transformed_rules` for transformed rules and `suricata_datasets.yaml` for dataset configurations.
5. **Validate Rules**: Test rules with Suricata:
   ```bash
   suricata -T -c transformed_rules/suricata_datasets.yaml -S transformed_rules/*.rules
   ```
6. **Deploy Rules**: Configure Suricata to use `transformed_rules/*.rules` and `suricata_datasets.yaml`.
7. **Automate (Optional)**: Use the GitHub Actions workflow (`pipeline.yml`) to process rules on push to `custom/*.rules`. Set up `GITHUB_TOKEN` in repository secrets for pushing changes.

## Troubleshooting
- **Invalid Rule Syntax**: Ensure rules include `msg`, `sid`, `rev`, `classtype`, and end with a semicolon.
- **Missing Datasets**: Verify dataset files exist in `./datasets` and match rule references.
- **SID Conflicts**: The script generates unique SIDs starting from 1,000,000.
- **Performance Issues**: Optimize PCRE usage with `fast_pattern` and limit broad matches.
- **Logs**: Check logs in the console or pipeline output for errors.

## Notes
- Compatible with Suricata 7.0+ due to dataset support.
- Rules are validated against Suricata best practices (https://suricata.readthedocs.io/).
- Dataset types (`string` or `ip`) are inferred from rule context.
- Contact support or check logs for persistent issues.