### GCP Lateral Movement TTPs
---

GCPW Golden Image Lateral Movement: Detect instances where the gaia account password (stored as an LSA secret named Chrome-GCPW-<User_SID>) is extracted using tools like Mimikatz. This is particularly critical in environments utilizing cloned VMs with pre-installed GCPW, as a shared gaia password can enable lateral movement across multiple machines.

Abuse of gcloud compute ssh for Privilege Escalation and Lateral Movement: Monitor for the execution of gcloud compute ssh commands, especially when originating from compromised instances or service accounts. This command can create SSH keys, inject them into target instances, and add the user to the sudoers group, facilitating privilege escalation and lateral movement within GCP.

GCP Instance Metadata Manipulation: Look for modifications to instance metadata, specifically attempts to add or modify SSH keys (gcloud compute instances add-metadata --metadata-from-file ssh-keys=meta.txt) or enable serial console access (gcloud compute instances add-metadata instance-name --metadata serial-port-enable=TRUE). These actions can indicate an attacker establishing persistence or gaining unauthorized access to VMs.

GCP Snapshot Creation and Disk Attachment Abuse: Detect the creation of VM disk snapshots (gcloud compute snapshots create) and subsequent disk creation from snapshots (gcloud compute disks create --source-snapshot) followed by attaching these disks to new instances (gcloud compute instances attach-disk). This technique allows attackers to access the contents of disks they were not originally authorized to view.