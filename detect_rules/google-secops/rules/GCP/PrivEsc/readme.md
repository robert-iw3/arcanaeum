### Privilege Escalatin in GCP TTP's
---

LXD Privilege Escalation (T1068 - Exploitation for Privilege Escalation): Monitor for unusual activity by users who are members of the lxd group, especially the execution of lxd init, lxc launch, or any attempts to interact with LXD sockets to mount host filesystems.

Docker Privilege Escalation (T1068 - Exploitation for Privilege Escalation): Detect attempts by non-root users to execute Docker commands that involve mounting the host's root filesystem (docker run -v /:/mnt/host) or modifying sensitive system files like /etc/group or /etc/sudoers from within a container.

DHCP Hijacking (T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning): Look for suspicious DHCP ACK packets originating from unexpected sources or containing unusual configurations (e.g., rapid lease renewals, changes to hostname/IP that point to internal or non-standard addresses). This can indicate an attempt to redirect metadata server communication.

Modification of /etc/hosts (T1573.002 - Encrypted Channel: Asymmetric Cryptography): Monitor for unauthorized or unusual modifications to the /etc/hosts file, particularly entries related to metadata.google.internal that point to non-Google IP addresses.

Unauthorized sudo usage (T1548.001 - Abuse Elevation Control Mechanism: Sudo and SUID): Alert on successful sudo commands executed by users who are not expected to have administrative privileges, especially after any of the aforementioned suspicious activities.

GCP Service Account Impersonation: Monitor for GenerateAccessToken events in GCP Admin Activity audit logs, especially when the principal caller is a service account or an unusual user. Look for multiple failed impersonation attempts from the same IP address or user-agent in a short timeframe.

SSH Key Modification in Instance/Project Metadata: Detect changes to ssh-keys in Compute Engine instance or project metadata. Specifically, look for protoPayload.methodName:"compute.instances.setMetadata" or protoPayload.methodName:"compute.projects.setCommonInstanceMetadata" combined with protoPayload.metadata.instanceMetadataDelta.addedMetadataKeys:"ssh-keys" or protoPayload.metadata.projectMetadataDelta.addedMetadataKeys:"ssh-keys".

Abuse of Default Service Account with Editor Role: Identify instances using the default service account (PROJECT_NUMBER-compute@developer.gserviceaccount.com) with the Editor role, as this is an insecure default configuration that attackers can exploit for broad access.

Domain-Wide Delegation Configuration Changes: Monitor Google Workspace audit logs for changes to domain-wide delegation settings, particularly the granting of API client access to service accounts. Investigate the actor email that created the delegation configuration and the associated OAuth scopes.

OS Login Privilege Escalation: While OS Login is generally more secure, be aware of potential privilege escalation vulnerabilities if overly permissive default group memberships are present. Monitor for gcloud compute os-login ssh-keys add commands and investigate any new SSH keys added to OS Login profiles, especially for administrative users.

Suspicious gcloud Command Usage: Look for gcloud commands executed from unexpected locations or by unusual users, particularly those involving gcloud auth activate-service-account --key-file or --impersonate-service-account.

Metadata Service Abuse: Monitor for unusual or excessive requests to the instance metadata endpoint (169.254.169.254 or metadata.google.internal), especially if combined with other suspicious activities like SSRF.

Monitor for the use of deploymentmanager.deployments.create permission, as it allows the creation of new deployments with the default project editor service account, enabling privilege escalation.

Detect attempts to update IAM roles using iam.roles.update by users on custom roles assigned to themselves, which can be used to add arbitrary permissions.

Look for suspicious iam.serviceAccounts.getAccessToken or iam.serviceAccountKeys.create API calls, indicating an attempt to obtain access tokens or create keys for service accounts with higher privileges.

Identify the creation or update of Cloud Functions (cloudfunctions.functions.create, cloudfunctions.functions.update) or Compute Engine instances (compute.instances.create) with associated service accounts by users who also possess iam.serviceAccounts.actAs permission, as these can be used to exfiltrate service account credentials.

Monitor for cloudbuild.builds.create activity, especially when originating from unusual users or locations, as this permission can be abused to gain the extensive privileges of the Cloud Build Service Account.

Track modifications to organization, folder, project, or service account IAM policies (*.setIamPolicy permissions) that grant elevated roles to existing users or service accounts.

Detect the creation of new HMAC keys for Cloud Storage (storage.hmacKeys.create) or API keys (serviceusage.apiKeys.create), particularly when performed by accounts with limited initial permissions, as these can be used for privilege escalation.

Implement detection for the creation or modification of cloud functions with overly permissive service accounts, especially those granting cloudbuild.builds.builder or similar build-related permissions, which could be abused for command execution during the build process.