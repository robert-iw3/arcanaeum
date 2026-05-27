### GCP Persistence & Gaining Foothold TTPs
---

Create Account: Cloud Account: Monitor for the creation or modification of the $HOME/.customize_environment file within Google Cloud Shell environments. This file is not created by default, so its presence or changes to it could indicate malicious activity.

Command and Scripting Interpreter: Unix Shell: Look for suspicious commands or scripts within $HOME/.customize_environment that attempt to establish outbound connections (e.g., nc, curl, wget to external IPs or unusual domains), download and execute binaries, or exfiltrate data (e.g., gcloud credentials, tokens).

Hijack Execution Flow: Dynamic Linker Hijacking: While not explicitly stated for .customize_environment, be aware that attackers might attempt to leverage other startup files like .bashrc for similar persistence, potentially loading malicious libraries or modifying environment variables.

Account Manipulation: Regularly audit Google Cloud Shell settings to ensure that Cloud Shell access is restricted to only necessary users or disabled entirely if not required for the organization, as this is the most effective way to prevent this persistence method.

Indicator Removal: File Deletion: Be aware that attackers may attempt to delete or modify logs related to Cloud Shell activity, as native logging for Cloud Shell is limited. Focus on collecting and analyzing logs from other GCP services that interact with Cloud Shell, such as Cloud Audit Logs for administrative activities.
