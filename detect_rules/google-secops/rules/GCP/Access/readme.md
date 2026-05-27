### Credential Access TTPs
---

GCP Service Account Key Creation by Service Account: Monitor for google.iam.admin.v1.CreateServiceAccountKey events where the authenticationInfo.principalEmail (the entity performing the action) is the same as the service account email in the request.name field (the service account for which the key is being created). This indicates a service account creating a key for itself, which is highly unusual and suspicious behavior.

GCP Service Account Key Usage After Deletion: While direct detection of a deleted key being used is difficult due to token non-revocability, monitor for any activity from service accounts whose keys have recently been deleted. This could indicate the use of a lingering, unrevoked access token.

GCP Service Account with Excessive Permissions: Identify service accounts with roles that include the iam.serviceAccountKeys.create permission (e.g., roles/editor, roles/owner, roles/iam.serviceAccountKeyAdmin, roles/assuredoss.admin, roles/securitycenter.admin). These accounts are at higher risk for this persistence technique if compromised.

GCP gcloud auth activate-service-account Usage: Monitor for the use of gcloud auth activate-service-account commands, especially in unexpected environments or by unusual users. This command activates a service account using a key file and generates an access token.

GCP Access Token File Access: Monitor for access to ~/.config/gcloud/access_tokens.db and ~/.config/gcloud/credentials.db on systems where GCP gcloud CLI is used. Unauthorized access to these files could indicate an adversary attempting to steal or reuse access tokens or service account credentials.
