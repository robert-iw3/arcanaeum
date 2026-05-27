### GCP Exfiltration TTPs
---

Cross-Project Image Creation: Monitor for v1.compute.images.insert events where the sourceImage project and the resourceName project are different. This indicates a compute image being copied from one project to another, which can be a precursor to exfiltration.

Cloud Build API Enablement: Detect google.api.serviceusage.v1.ServiceUsage.EnableService events for cloudbuild.googleapis.com. Unexpected enablement of the Cloud Build API, especially by non-standard accounts, could signal an attacker preparing to export data.

Cloud Build Initiated Image Export: Look for compute.images.get events where the principalEmail is a Cloud Build service account (e.g., @cloudbuild.gserviceaccount.com). This indicates Cloud Build is accessing compute images, likely for export.

Cloud Build Initiated Storage Object Creation: Identify storage.objects.create events where the principalEmail is a Cloud Build service account and filter out common noisy events like those containing "log" or "daisy" in the resourceName. This can pinpoint Cloud Build exporting images to storage buckets.

Anomalous Storage Object Access: Monitor for an anomalous number or pattern of storage.objects.get, storage.buckets.get, and storage.objects.list events, particularly when originating from unusual IAM entities, IP addresses, or exhibiting high volume within short periods. While GCP logs storage.objects.get for various access types, including metadata reads and actual downloads, anomalies can still indicate suspicious activity.

Establish alerts for outbound network connections from cloud function environments to suspicious external endpoints, particularly those associated with tunneling services like Ngrok (e.g., *.ngrok-free.app or other Ngrok domains).