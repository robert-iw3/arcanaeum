### K8sploitation: Hacking Kubernetes the Fun Way
---

https://media.defcon.org/DEF%20CON%2033/DEF%20CON%2033%20workshops/DEF%20CON%2033%20-%20Workshops%20-%20Marcelo%20Ribeiro%20-%20K8sploitation_%20Hacking%20Kubernetes%20the%20Fun%20Way%20-%20Slides.pptx

This report summarizes common attack vectors and misconfigurations in Kubernetes environments, highlighting how attackers exploit weaknesses in API servers, etcd, RBAC, and container runtimes to achieve privilege escalation and lateral movement. The core takeaway is that misconfigurations, particularly overly permissive settings and insecure defaults, are primary enablers for compromise in Kubernetes clusters.

Recent intelligence indicates a continued rise in Kubernetes-focused supply chain attacks and cryptojacking campaigns, often leveraging misconfigured API servers and vulnerable container images. Notably, the exploitation of critical vulnerabilities like CVE-2024-7646 (Ingress-nginx Annotation Validation Bypass) and CVE-2024-31989 (Argo CD default Redis instance) in 2024 demonstrates attackers' focus on exploiting application-level flaws within the Kubernetes ecosystem for initial access and privilege escalation.

### Actionable Threat Data
---

Monitor for overly permissive RBAC roles and bindings: Attackers frequently exploit misconfigured Role-Based Access Control (RBAC) to escalate privileges, particularly roles granting create permissions on pods or broad access to cluster-admin to unauthenticated groups.

Detect container escape attempts via hostPath mounts and privileged containers: Attackers leverage hostPath volumes and privileged container settings (privileged: true, hostPID: true, hostNetwork: true) to break out of containers and gain access to the underlying host filesystem or processes.

Identify exploitation of known runtime vulnerabilities: Monitor for attempts to exploit vulnerabilities in container runtimes like runc (e.g., CVE-2019-5736) which allow attackers to escape containers and gain root access on the host.

Monitor for suspicious API server and etcd access: Publicly exposed or misconfigured Kubernetes API servers and etcd databases are prime targets for attackers to gain unauthorized access, dump sensitive data (including secrets), and achieve full cluster compromise.

Implement network segmentation and monitor for network policy bypasses: Default flat pod-to-pod networks and misconfigured network policies can enable lateral movement. Look for unusual traffic flows, ARP poisoning (especially with CAP_NET_RAW enabled pods), and DNS spoofing attempts.

Detect ServiceAccount token misuse and exfiltration: Compromised pods can steal ServiceAccount tokens, especially when automountServiceAccountToken: true is enabled, to authenticate to the API server and schedule pods on other nodes for lateral movement.

Scan for vulnerable container images and supply chain attacks: Attackers inject malicious code into container images or exploit vulnerabilities in the CI/CD pipeline, leading to cryptojacking or other compromises. Regularly scan images for known CVEs and enforce image signing.

### Overly Permissive RBAC
---
Name: Kubernetes - Overly Permissive ClusterRoleBinding

Author: RW

Date: 2025-08-11

Description: Detects the creation or update of a ClusterRoleBinding that grants a highly privileged role, such as 'cluster-admin', to a broad system group like
'system:unauthenticated' or 'system:authenticated'. This configuration is a significant security risk and can be exploited for privilege escalation across the entire cluster.

False Positive Sensitivity: Medium. Binding 'cluster-admin' to 'system:unauthenticated' is a critical finding. Binding to 'system:authenticated' may be
intentional in some non-production environments. Consider tuning by excluding specific users or environments if necessary.
MITRE TTPs: T1078 (Valid Accounts), T1068 (Exploitation for Privilege Escalation)

splunk:
```sql
`kube_audit` -- Replace with your macro or search for Kubernetes audit logs. e.g. `index=k8s sourcetype=kube:audit`
-- Filter for ClusterRoleBinding creation or updates.
| search objectRef.resource="clusterrolebindings" verb IN ("create", "update")
-- Exclude common system service accounts to reduce noise.
| where isnull(user.username) OR NOT like(user.username, "system:serviceaccount:%")
-- Parse the role name and subjects from the requestObject.
| spath input=requestObject
| rename roleRef.name as PrivilegedRoleAssigned, subjects{} as subjects
-- Focus on the cluster-admin role, which is the highest privilege.
| where PrivilegedRoleAssigned="cluster-admin"
-- Expand the subjects array to evaluate each subject individually.
| mvexpand subjects
-- Parse the name and kind for each subject.
| spath input=subjects
| rename name as AssignedToGroup, kind as AssignedToKind
-- Filter for bindings to broad, high-risk system groups.
| where AssignedToKind="Group" AND AssignedToGroup IN ("system:unauthenticated", "system:authenticated")
-- Format the output for readability and alerting.
| table _time, auditID, verb, user.username, sourceIPs{}, objectRef.name, PrivilegedRoleAssigned, AssignedToGroup
| rename
    _time as Time,
    auditID as AuditID,
    verb as Verb,
    user.username as ActorUsername,
    sourceIPs{} as SourceIP,
    objectRef.name as ClusterRoleBindingName
```

crowdstrike fql:
```sql
event_platform="K8s" event_type="Audit"
| object_ref.resource="clusterrolebindings" verb IN ("create", "update")
| user.username IS NULL OR user.username NOT LIKE "system:serviceaccount:%"
| role_ref.name="cluster-admin"
| subjects.kind="Group" subjects.name IN ("system:unauthenticated", "system:authenticated")
| project timestamp, audit_id, verb, user.username, source_ips, object_ref.name, role_ref.name, subjects.name
| rename timestamp as Time, audit_id as AuditID, verb as Verb, user.username as ActorUsername, source_ips as SourceIP, object_ref.name as ClusterRoleBindingName, role_ref.name as PrivilegedRoleAssigned, subjects.name as AssignedToGroup
```

datadog:
```sql
source:kubernetes.audit objectRef.resource:clusterrolebindings verb:(create OR update) -user.username:"system:serviceaccount:*"
roleRef.name:cluster-admin subjects.kind:Group subjects.name:(system:unauthenticated OR system:authenticated)
| select @timestamp as Time, auditID as AuditID, verb as Verb, user.username as ActorUsername, sourceIPs as SourceIP, objectRef.name as ClusterRoleBindingName, roleRef.name as PrivilegedRoleAssigned, subjects.name as AssignedToGroup
```

elastic:
```sql
FROM kubernetes_audit_logs
| WHERE kubernetes.audit.objectRef.resource == "clusterrolebindings"
  AND kubernetes.audit.verb IN ("create", "update")
  AND (kubernetes.audit.user.username IS NULL OR kubernetes.audit.user.username NOT LIKE "system:serviceaccount:%")
  AND kubernetes.audit.requestObject.roleRef.name == "cluster-admin"
  AND kubernetes.audit.requestObject.subjects.kind == "Group"
  AND kubernetes.audit.requestObject.subjects.name IN ("system:unauthenticated", "system:authenticated")
| EVAL Time = @timestamp,
        AuditID = kubernetes.audit.auditID,
        Verb = kubernetes.audit.verb,
        ActorUsername = kubernetes.audit.user.username,
        SourceIP = kubernetes.audit.sourceIPs,
        ClusterRoleBindingName = kubernetes.audit.objectRef.name,
        PrivilegedRoleAssigned = kubernetes.audit.requestObject.roleRef.name,
        AssignedToGroup = kubernetes.audit.requestObject.subjects.name
| KEEP Time, AuditID, Verb, ActorUsername, SourceIP, ClusterRoleBindingName, PrivilegedRoleAssigned, AssignedToGroup
```

sentinel one:
```sql
event.type = "KubernetesAudit" AND kubernetes.resource = "clusterrolebindings"
AND kubernetes.verb IN ("create", "update")
AND (kubernetes.user.username IS NULL OR kubernetes.user.username NOT LIKE "system:serviceaccount:%")
AND kubernetes.requestObject.roleRef.name = "cluster-admin"
AND kubernetes.requestObject.subjects.kind = "Group"
AND kubernetes.requestObject.subjects.name IN ("system:unauthenticated", "system:authenticated")
| SELECT event.timestamp AS Time,
         kubernetes.auditID AS AuditID,
         kubernetes.verb AS Verb,
         kubernetes.user.username AS ActorUsername,
         kubernetes.sourceIPs AS SourceIP,
         kubernetes.objectRef.name AS ClusterRoleBindingName,
         kubernetes.requestObject.roleRef.name AS PrivilegedRoleAssigned,
         kubernetes.requestObject.subjects.name AS AssignedToGroup
```

### Container Escape via hostPath
---
Name: Kubernetes - Container Escape Attempt via Privileged Pod Configuration

Author: RW

Date: 2025-08-11

Description: Detects the creation or update of a Pod with configurations that could facilitate a container escape. This includes running as a privileged container, using the host's PID or network namespaces, or mounting sensitive host directories via hostPath. Such configurations can be exploited by an attacker to gain access to the underlying node.

False Positive Sensitivity: Medium. Legitimate administrative or monitoring pods may use some of these settings. Review the pod's purpose and the user creating it. Consider excluding specific namespaces or service accounts if they are known to run such workloads.

MITRE TTPs: T1611 (Escape to Host), T10555 (Process Injection)

splunk:
```sql
`kube_audit` -- Replace with your Kubernetes audit log source, e.g., index=k8s sourcetype=kube:audit
-- Filter for Pod creation or update events.
| search objectRef.resource="pods" verb IN ("create", "update")
-- Exclude system namespaces which often have privileged pods by design.
| where 'objectRef.namespace' NOT IN ("kube-system", "kube-public", "kube-node-lease")
-- Parse relevant fields from the JSON request object.
| spath input=requestObject
| rename spec.hostPID as hostPID, spec.hostNetwork as hostNetwork, spec.containers{}.securityContext.privileged as privilegedContainers, spec.volumes{}.hostPath.path as hostPaths, spec.containers{}.image as image
-- Evaluate for risky configurations.
| eval isPrivileged = if(mvfind(privilegedContainers, "true") > 0, 1, 0)
| eval isHostPID = if(isnotnull(hostPID) AND hostPID="true", 1, 0)
| eval isHostNetwork = if(isnotnull(hostNetwork) AND hostNetwork="true", 1, 0)
-- Identify mounts of sensitive host directories.
| eval sensitiveHostPaths = mvfilter(match(hostPaths, "(^/$)|(^/etc)|(^/root)|(^/proc)|(^/var/run/docker\.sock)|(^/var/lib/kubelet)|(^/var/run/containerd/containerd\.sock)"))
| eval hasSensitiveMount = if(mvcount(sensitiveHostPaths) > 0, 1, 0)
-- Trigger if any of the risky settings are present.
| where isPrivileged=1 OR isHostPID=1 OR isHostNetwork=1 OR hasSensitiveMount=1
-- Create a summary of reasons for easier triage.
| eval Reasons = ""
| eval Reasons = if(isPrivileged=1, Reasons + "PrivilegedContainer, ", Reasons)
| eval Reasons = if(isHostPID=1, Reasons + "HostPID, ", Reasons)
| eval Reasons = if(isHostNetwork=1, Reasons + "HostNetwork, ", Reasons)
| eval Reasons = if(hasSensitiveMount=1, Reasons + "SensitiveHostPath, ", Reasons)
| eval Reasons = rtrim(Reasons, ", ")
-- Format the final output.
| table _time, auditID, verb, user.username, sourceIPs{}, objectRef.namespace, objectRef.name, image, Reasons, sensitiveHostPaths
| rename
    _time as Time,
    auditID as AuditID,
    verb as Verb,
    user.username as ActorUsername,
    sourceIPs{} as SourceIP,
    'objectRef.namespace' as PodNamespace,
    'objectRef.name' as PodName,
    image as Image,
    sensitiveHostPaths as SensitivePathsMounted
```

crowdstrike fql:
```sql
event_platform="K8s" event_type="Audit"
| object_ref.resource="pods" verb IN ("create", "update")
| object_ref.namespace NOT IN ("kube-system", "kube-public", "kube-node-lease")
| spec.hostPID="true" -> isHostPID=1 ELSE isHostPID=0
| spec.hostNetwork="true" -> isHostNetwork=1 ELSE isHostNetwork=0
| spec.containers.securityContext.privileged CONTAINS "true" -> isPrivileged=1 ELSE isPrivileged=0
| spec.volumes.hostPath.path MATCHES "(^/$)|(^/etc)|(^/root)|(^/proc)|(^/var/run/docker\.sock)|(^/var/lib/kubelet)|(^/var/run/containerd/containerd\.sock)" -> hasSensitiveMount=1 ELSE hasSensitiveMount=0
| isPrivileged=1 OR isHostPID=1 OR isHostNetwork=1 OR hasSensitiveMount=1
| isPrivileged=1 -> Reasons="PrivilegedContainer" ELSE Reasons=""
| isHostPID=1 -> Reasons=Reasons+", HostPID"
| isHostNetwork=1 -> Reasons=Reasons+", HostNetwork"
| hasSensitiveMount=1 -> Reasons=Reasons+", SensitiveHostPath"
| Reasons=TRIM(Reasons, ", ")
| project timestamp, audit_id, verb, user.username, source_ips, object_ref.namespace, object_ref.name, spec.containers.image, Reasons, spec.volumes.hostPath.path
| rename timestamp as Time, audit_id as AuditID, verb as Verb, user.username as ActorUsername, source_ips as SourceIP, object_ref.namespace as PodNamespace, object_ref.name as PodName, spec.containers.image as Image, spec.volumes.hostPath.path as SensitivePathsMounted
```

datadog:
```sql
source:kubernetes.audit objectRef.resource:pods verb:(create OR update) -objectRef.namespace:(kube-system OR kube-public OR kube-node-lease)
(spec.hostPID:true OR spec.hostNetwork:true OR spec.containers.securityContext.privileged:true OR spec.volumes.hostPath.path:/ OR spec.volumes.hostPath.path:/etc* OR spec.volumes.hostPath.path:/root* OR spec.volumes.hostPath.path:/proc* OR spec.volumes.hostPath.path:/var/run/docker.sock OR spec.volumes.hostPath.path:/var/lib/kubelet* OR spec.volumes.hostPath.path:/var/run/containerd/containerd.sock)
| eval Reasons = concat(
  if(spec.containers.securityContext.privileged:true, "PrivilegedContainer, Dolores, ""),
  if(spec.hostPID:true, "HostPID, ", ""),
  if(spec.hostNetwork:true, "HostNetwork, ", ""),
  if(spec.volumes.hostPath.path:/ OR spec.volumes.hostPath.path:/etc* OR spec.volumes.hostPath.path:/root* OR spec.volumes.hostPath.path:/proc* OR spec.volumes.hostPath.path:/var/run/docker.sock OR spec.volumes.hostPath.path:/var/lib/kubelet* OR spec.volumes.hostPath.path:/var/run/containerd/containerd.sock, "SensitiveHostPath, ", "")
)
| select @timestamp as Time, auditID as AuditID, verb as Verb, user.username as ActorUsername, sourceIPs as SourceIP, objectRef.namespace as PodNamespace, objectRef.name as PodName, spec.containers.image as Image, Reasons, spec.volumes.hostPath.path as SensitivePathsMounted
```

elastic:
```sql
FROM kubernetes_audit_logs
| WHERE kubernetes.audit.objectRef.resource == "pods"
  AND kubernetes.audit.verb IN ("create", "update")
  AND kubernetes.audit.objectRef.namespace NOT IN ("kube-system", "kube-public", "kube-node-lease")
| EVAL isPrivileged = CASE(MV_CONTAINS(kubernetes.audit.requestObject.spec.containers.securityContext.privileged, "true"), 1, 0),
      isHostPID = CASE(kubernetes.audit.requestObject.spec.hostPID == "true", 1, 0),
      isHostNetwork = CASE(kubernetes.audit.requestObject.spec.hostNetwork == "true", 1, 0),
      sensitiveHostPaths = MV_FILTER(kubernetes.audit.requestObject.spec.volumes.hostPath.path, path -> path MATCHES "(^/$)|(^/etc)|(^/root)|(^/proc)|(^/var/run/docker\.sock)|(^/var/lib/kubelet)|(^/var/run/containerd/containerd\.sock)"),
      hasSensitiveMount = CASE(MV_COUNT(sensitiveHostPaths) > 0, 1, 0),
      Reasons = CONCAT(
        CASE(isPrivileged == 1, "PrivilegedContainer, ", ""),
        CASE(isHostPID == 1, "HostPID, ", ""),
        CASE(isHostNetwork == 1, "HostNetwork, ", ""),
        CASE(hasSensitiveMount == 1, "SensitiveHostPath, ", "")
      ),
      Reasons = RTRIM(Reasons, ", ")
| WHERE isPrivileged == 1 OR isHostPID == 1 OR isHostNetwork == 1 OR hasSensitiveMount == 1
| KEEP @timestamp AS Time,
      kubernetes.audit.auditID AS AuditID,
      kubernetes.audit.verb AS Verb,
      kubernetes.audit.user.username AS ActorUsername,
      kubernetes.audit.sourceIPs AS SourceIP,
      kubernetes.audit.objectRef.namespace AS PodNamespace,
      kubernetes.audit.objectRef.name AS PodNa
      kubernetes.audit.requestObject.spec.containers.image AS Image,
      Reasons,
      sensitiveHostPaths AS SensitivePathsMounted
```

sentinel one:
```sql
event.type = "KubernetesAudit" AND kubernetes.resource = "pods"
AND kubernetes.verb IN ("create", "update")
AND kubernetes.objectRef.namespace NOT IN ("kube-system", "kube-public", "kube-node-lease")
AND (
  kubernetes.requestObject.spec.hostPID = "true" OR
  kubernetes.requestObject.spec.hostNetwork = "true" OR
  kubernetes.requestObject.spec.containers.securityContext.privileged = "true" OR
  kubernetes.requestObject.spec.volumes.hostPath.path MATCHES "(^/$)|(^/etc)|(^/root)|(^/proc)|(^/var/run/docker\.sock)|(^/var/lib/kubelet)|(^/var/run/containerd/containerd\.sock)"
)
| SELECT event.timestamp AS Time,
         kubernetes.auditID AS AuditID,
         kubernetes.verb AS Verb,
         kubernetes.user.username AS ActorUsername,
         kubernetes.sourceIPs AS SourceIP,
         kubernetes.objectRef.namespace AS PodNamespace,
         kubernetes.objectRef.name AS PodName,
         kubernetes.requestObject.spec.containers.image AS Image,
         CASE
           WHEN kubernetes.requestObject.spec.containers.securityContext.privileged = "true" THEN "PrivilegedContainer"
           ELSE ""
         END +
         CASE
           WHEN kubernetes.requestObject.spec.hostPID = "true" THEN ", HostPID"
           ELSE ""
         END +
         CASE
           WHEN kubernetes.requestObject.spec.hostNetwork = "true" THEN ", HostNetwork"
           ELSE ""
         END +
         CASE
           WHEN kubernetes.requestObject.spec.volumes.hostPath.path MATCHES "(^/$)|(^/etc)|(^/root)|(^/proc)|(^/var/run/docker\.sock)|(^/var/lib/kubelet)|(^/var/run/containerd/containerd\.sock)" THEN ", SensitiveHostPath"
           ELSE ""
         END AS Reasons,
         kubernetes.requestObject.spec.volumes.hostPath.path AS SensitivePathsMounted
| WHERE Reasons != ""
| EVAL Reasons = TRIM(Reasons, ", ")
```

### Runtime Vulnerability Exploitation
---
Name: Kubernetes - Potential Container Runtime File Overwrite

Author: RW

Date: 2025-08-11

Description: Detects attempts to modify or overwrite critical container runtime binaries on a host, such as 'runc'. This is a key indicator of a container escape attempt, notably associated with vulnerabilities like CVE-2019-5736. Legitimate updates to these files should only be performed by system package managers (e.g., yum, apt). Any other process modifying these files is highly suspicious.

False Positive Sensitivity: Medium. Custom update scripts or configuration management tools (e.g., Ansible, Puppet) might perform legitimate modifications. Exclude known legitimate processes or parent processes if they cause noise in your environment.

MITRE TTPs: T1611 (Escape to Host), T1068 (Exploitation for Privilege Escalation)

splunk:
```sql
-- This detection requires host-level file monitoring from an EDR tool (e.g., Sysmon, CrowdStrike, Carbon Black).
-- Replace `edr_file_events` with your data source.
`edr_file_events`
-- Define sensitive container runtime binary paths.
| where file_path IN (
    "/usr/bin/runc",
    "/usr/sbin/runc",
    "/bin/runc",
    "/sbin/runc",
    "/var/lib/docker/runc",
    "/usr/bin/containerd-shim",
    "/usr/bin/containerd-shim-runc-v1",
    "/usr/bin/containerd-shim-runc-v2"
)
-- Exclude modifications performed by known, legitimate package managers.
| where NOT process_name IN (
    "yum",
    "dnf",
    "apt",
    "apt-get",
    "dpkg",
    "unattended-upgr",
    "rpm"
)
-- Format the output for alerting and investigation.
| table _time, host, user, process_name, process_cmd, parent_process_name, file_path
| rename
    _time as Time,
    host as Host,
    user as User,
    process_name as ProcessName,
    process_cmd as ProcessCommandLine,
    parent_process_name as ParentProcessName,
    file_path as ModifiedFile
```

crowdstrike fql:
```sql
event_type="FileModification"
| file_path IN ("/usr/bin/runc", "/usr/sbin/runc", "/bin/runc", "/sbin/runc", "/var/lib/docker/runc", "/usr/bin/containerd-shim", "/usr/bin/containerd-shim-runc-v1", "/usr/bin/containerd-shim-runc-v2")
| process_name NOT IN ("yum", "dnf", "apt", "apt-get", "dpkg", "unattended-upgr", "rpm")
| project timestamp, hostname, user_name, process_name, process_cmd_line, parent_process_name, file_path
| rename timestamp as Time, hostname as Host, user_name as User, process_name as ProcessName, process_cmd_line as ProcessCommandLine, parent_process_name as ParentProcessName, file_path as ModifiedFile
```

datadog:
```sql
source:edr event_type:file_modification
file_path:("/usr/bin/runc" OR "/usr/sbin/runc" OR "/bin/runc" OR "/sbin/runc" OR "/var/lib/docker/runc" OR "/usr/bin/containerd-shim" OR "/usr/bin/containerd-shim-runc-v1" OR "/usr/bin/containerd-shim-runc-v2")
-process_name:(yum OR dnf OR apt OR apt-get OR dpkg OR unattended-upgr OR rpm)
| select @timestamp as Time, host as Host, user as User, process_name as ProcessName, process_cmd as ProcessCommandLine, parent_process_name as ParentProcessName, file_path as ModifiedFile
```

elastic:
```sql
FROM edr_file_events
| WHERE event.action == "file_modification"
  AND file.path IN (
    "/usr/bin/runc",
    "/usr/sbin/runc",
    "/bin/runc",
    "/sbin/runc",
    "/var/lib/docker/runc",
    "/usr/bin/containerd-shim",
    "/usr/bin/containerd-shim-runc-v1",
    "/usr/bin/containerd-shim-runc-v2"
  )
  AND process.name NOT IN (
    "yum",
    "dnf",
    "apt",
    "apt-get",
    "dpkg",
    "unattended-upgr",
    "rpm"
  )
| KEEP @timestamp AS Time,
      host.hostname AS Host,
      user.name AS User,
      process.name AS ProcessName,
      process.command_line AS ProcessCommandLine,
      process.parent.name AS ParentProcessName,
      file.path AS ModifiedFile
```

sentinel one:
```sql
event.type = "FileModification"
AND file.path IN (
  "/usr/bin/runc",
  "/usr/sbin/runc",
  "/bin/runc",
  "/sbin/runc",
  "/var/lib/docker/runc",
  "/usr/bin/containerd-shim",
  "/usr/bin/containerd-shim-runc-v1",
  "/usr/bin/containerd-shim-runc-v2"
)
AND process.name NOT IN (
  "yum",
  "dnf",
  "apt",
  "apt-get",
  "dpkg",
  "unattended-upgr",
  "rpm"
)
| SELECT event.timestamp AS Time,
         agent.hostname AS Host,
         user.name AS User,
         process.name AS ProcessName,
         process.command_line AS ProcessCommandLine,
         process.parent.name AS ParentProcessName,
         file.path AS ModifiedFile
```

### Suspicious API/etcd Access
---
Name: Kubernetes - Suspicious API Access and Secret Enumeration

Author: RW

Date: 2025-08-11

Description: Detects suspicious access patterns to the Kubernetes API server that may indicate reconnaissance or credential dumping. This includes anonymous users listing sensitive resources or any user attempting to list all secrets across all namespaces. Such activities are often precursors to cluster compromise.

False Positive Sensitivity: Medium. Legitimate administrative scripts or monitoring tools might list all secrets. Exclude known service accounts or users if they perform these actions as part of their normal function.

MITRE TTPs: T1566.002 (Spearphishing Link), T1003.003 (/etc/passwd and /etc/shadow), T1003.001 (LSASS Memory)

splunk:
```sql
`kube_audit` -- Replace with your Kubernetes audit log source, e.g., index=k8s sourcetype=kube:audit
-- Combine search for both scenarios for efficiency.
| search (
    -- Scenario A: An anonymous user attempts to list or get sensitive resources.
    (user.username="system:anonymous" verb IN ("list", "get", "watch") objectRef.resource IN ("secrets", "configmaps", "pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs"))
    OR
    -- Scenario B: A non-system user lists all secrets across all namespaces.
    (objectRef.resource="secrets" verb="list" (isnull('objectRef.namespace') OR 'objectRef.namespace'="") NOT user.username LIKE "system:serviceaccount:kube-system%")
)
-- Add a 'Tactic' field to explain why the event is suspicious.
| eval Tactic = case(
    user.username == "system:anonymous", "Initial Access via Anonymous User",
    'objectRef.resource' == "secrets" AND verb == "list", "Credential Access via Secret Enumeration",
    1=1, "Reconnaissance"
)
-- Format the output for alerting and investigation.
| table _time, auditID, verb, user.username, user.groups{}, sourceIPs{}, userAgent, objectRef.resource, objectRef.namespace, objectRef.name, requestURI, responseStatus.code
| rename
    _time as Time,
    auditID as AuditID,
    verb as Verb,
    user.username as ActorUsername,
    user.groups{} as ActorGroups,
    sourceIPs{} as SourceIP,
    userAgent as UserAgent,
    'objectRef.resource' as Resource,
    'objectRef.namespace' as Namespace,
    'objectRef.name' as ResourceName,
    requestURI as RequestURI,
    'responseStatus.code' as ResponseStatusCode
```

crowdstrike fql:
```sql
event_platform="K8s" event_type="Audit"
| (
    (user.username="system:anonymous"
     AND verb IN ("list", "get", "watch")
     AND object_ref.resource IN ("secrets", "configmaps", "pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs"))
    OR
    (object_ref.resource="secrets"
     AND verb="list"
     AND (object_ref.namespace IS NULL OR object_ref.namespace="")
     AND user.username NOT LIKE "system:serviceaccount:kube-system%")
  )
| Tactic=CASE(
    user.username="system:anonymous", "Initial Access via Anonymous User",
    object_ref.resource="secrets" AND verb="list", "Credential Access via Secret Enumeration",
    TRUE, "Reconnaissance"
  )
| project timestamp, audit_id, verb, user.username, user.groups, source_ips, user_agent, object_ref.resource, object_ref.namespace, object_ref.name, request_uri, response_status.code
| rename timestamp as Time, audit_id as AuditID, verb as Verb, user.username as ActorUsername, user.groups as ActorGroups, source_ips as SourceIP, user_agent as UserAgent, object_ref.resource as Resource, object_ref.namespace as Namespace, object_ref.name as ResourceName, request_uri as RequestURI, response_status.code as ResponseStatusCode
```

datadog:
```sql
source:kubernetes.audit (
  (user.username:system:anonymous verb:(list OR get OR watch) objectRef.resource:(secrets OR configmaps OR pods OR deployments OR daemonsets OR statefulsets OR jobs OR cronjobs))
  OR
  (objectRef.resource:secrets verb:list (objectRef.namespace:NULL OR objectRef.namespace:"") -user.username:"system:serviceaccount:kube-system*")
)
| eval Tactic = case(
  user.username == "system:anonymous", "Initial Access via Anonymous User",
  objectRef.resource == "secrets" AND verb == "list", "Credential Access via Secret Enumeration",
  true, "Reconnaissance"
)
| select @timestamp as Time, auditID as AuditID, verb as Verb, user.username as ActorUsername, user.groups as ActorGroups, sourceIPs as SourceIP, userAgent as UserAgent, objectRef.resource as Resource, objectRef.namespace as Namespace, objectRef.name as ResourceName, requestURI as RequestURI, responseStatus.code as ResponseStatusCode
```

elastic:
```sql
FROM kubernetes_audit_logs
| WHERE (
    (kubernetes.audit.user.username == "system:anonymous"
     AND kubernetes.audit.verb IN ("list", "get", "watch")
     AND kubernetes.audit.objectRef.resource IN ("secrets", "configmaps", "pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs"))
    OR
    (kubernetes.audit.objectRef.resource == "secrets"
     AND kubernetes.audit.verb == "list"
     AND (kubernetes.audit.objectRef.namespace IS NULL OR kubernetes.audit.objectRef.namespace == "")
     AND kubernetes.audit.user.username NOT LIKE "system:serviceaccount:kube-system%")
  )
| EVAL Tactic = CASE(
    kubernetes.audit.user.username == "system:anonymous", "Initial Access via Anonymous User",
    kubernetes.audit.objectRef.resource == "secrets" AND kubernetes.audit.verb == "list", "Credential Access via Secret Enumeration",
    TRUE, "Reconnaissance"
  )
| KEEP @timestamp AS Time,
      kubernetes.audit.auditID AS AuditID,
      kubernetes.audit.verb AS Verb,
      kubernetes.audit.user.username AS ActorUsername,
      kubernetes.audit.user.groups AS ActorGroups,
      kubernetes.audit.sourceIPs AS SourceIP,
      kubernetes.audit.userAgent AS UserAgent,
      kubernetes.audit.objectRef.resource AS Resource,
      kubernetes.audit.objectRef.namespace AS Namespace,
      kubernetes.audit.objectRef.name AS ResourceName,
      kubernetes.audit.requestURI AS RequestURI,
      kubernetes.audit.responseStatus.code AS ResponseStatusCode
```

sentinel one:
```sql
event.type = "KubernetesAudit"
AND (
  (kubernetes.user.username = "system:anonymous"
   AND kubernetes.verb IN ("list", "get", "watch")
   AND kubernetes.objectRef.resource IN ("secrets", "configmaps", "pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs"))
  OR
  (kubernetes.objectRef.resource = "secrets"
   AND kubernetes.verb = "list"
   AND (kubernetes.objectRef.namespace IS NULL OR kubernetes.objectRef.namespace = "")
   AND kubernetes.user.username NOT LIKE "system:serviceaccount:kube-system%")
)
| SELECT event.timestamp AS Time,
         kubernetes.auditID AS AuditID,
         kubernetes.verb AS Verb,
         kubernetes.user.username AS ActorUsername,
         kubernetes.user.groups AS ActorGroups,
         kubernetes.sourceIPs AS SourceIP,
         kubernetes.userAgent AS UserAgent,
         kubernetes.objectRef.resource AS Resource,
         kubernetes.objectRef.namespace AS Namespace,
         kubernetes.objectRef.name AS ResourceName,
         kubernetes.requestURI AS RequestURI,
         kubernetes.responseStatus.code AS ResponseStatusCode,
         CASE
           WHEN kubernetes.user.username = "system:anonymous" THEN "Initial Access via Anonymous User"
           WHEN kubernetes.objectRef.resource = "secrets" AND kubernetes.verb = "list" THEN "Credential Access via Secret Enumeration"
           ELSE "Reconnaissance"
         END AS Tactic
```

### Network Policy Bypass
---
Name: Kubernetes - Pod Created with Network Policy Bypass Capability

Author: RW

Date: 2025-08-11

Description: Detects the creation or update of a Pod with configurations that can bypass network policies or facilitate network-based attacks like ARP and DNS spoofing. This includes enabling hostNetwork, which attaches the pod directly to the node's network, or adding the CAP_NET_RAW capability, which allows for crafting raw packets.

False Positive Sensitivity: Medium. Legitimate workloads, such as CNI plugins or network monitoring tools, may require these privileges. Exclude known service accounts or namespaces if they are expected to create such pods.

MITRE TTPs: T1557.001 (Man-in-the-Middle: ARP Poisoning), T1557.002 (Man-in-the-Middle: DNS Spoofing), T1611 (Escape to Host), T1213 (Data from Information Repositories)

splunk:
```sql
`kube_audit` -- Replace with your Kubernetes audit log source, e.g., index=k8s sourcetype=kube:audit
-- Filter for Pod creation or update events.
| search objectRef.resource="pods" verb IN ("create", "update")
-- Exclude system namespaces which often have privileged pods by design.
| where 'objectRef.namespace' NOT IN ("kube-system", "kube-public", "kube-node-lease")
-- Parse relevant fields from the JSON request object.
| spath input=requestObject
| rename spec.hostNetwork as hostNetwork, spec.containers{}.securityContext.capabilities.add{} as capabilities, spec.containers{}.image as image
-- Check for hostNetwork or CAP_NET_RAW capability.
| eval isHostNetwork = if(isnotnull(hostNetwork) AND hostNetwork="true", 1, 0)
| eval hasCapNetRaw = if(mvfind(capabilities, "NET_RAW") > 0, 1, 0)
| where isHostNetwork=1 OR hasCapNetRaw=1
-- Create a summary of reasons for easier triage.
| eval Reasons = ""
| eval Reasons = if(isHostNetwork=1, Reasons + "HostNetworkEnabled, ", Reasons)
| eval Reasons = if(hasCapNetRaw=1, Reasons + "CapNetRawAdded, ", Reasons)
| eval Reasons = rtrim(Reasons, ", ")
-- Format the final output.
| table _time, auditID, verb, user.username, sourceIPs{}, objectRef.namespace, objectRef.name, image, Reasons
| rename
    _time as Time,
    auditID as AuditID,
    verb as Verb,
    user.username as ActorUsername,
    sourceIPs{} as SourceIP,
    'objectRef.namespace' as PodNamespace,
    'objectRef.name' as PodName,
    image as Image
```

crowdstrike fql:
```sql
event_platform="K8s" event_type="Audit"
| object_ref.resource="pods" verb IN ("create", "update")
| object_ref.namespace NOT IN ("kube-system", "kube-public", "kube-node-lease")
| spec.hostNetwork="true" -> isHostNetwork=1 ELSE isHostNetwork=0
| spec.containers.securityContext.capabilities.add CONTAINS "NET_RAW" -> hasCapNetRaw=1 ELSE hasCapNetRaw=0
| isHostNetwork=1 OR hasCapNetRaw=1
| Reasons=""
| isHostNetwork=1 -> Reasons=Reasons+"HostNetworkEnabled, "
| hasCapNetRaw=1 -> Reasons=Reasons+"CapNetRawAdded, "
| Reasons=TRIM(Reasons, ", ")
| project timestamp, audit_id, verb, user.username, source_ips, object_ref.namespace, object_ref.name, spec.containers.image, Reasons
| rename timestamp as Time, audit_id as AuditID, verb as Verb, user.username as ActorUsername, source_ips as SourceIP, object_ref.namespace as PodNamespace, object_ref.name as PodName, spec.containers.image as Image
```

datadog:
```sql
source:kubernetes.audit objectRef.resource:pods verb:(create OR update) -objectRef.namespace:(kube-system OR kube-public OR kube-node-lease)
(spec.hostNetwork:true OR spec.containers.securityContext.capabilities.add:NET_RAW)
| eval Reasons = concat(
  if(spec.hostNetwork:true, "HostNetworkEnabled, ", ""),
  if(spec.containers.securityContext.capabilities.add:NET_RAW, "CapNetRawAdded, ", "")
)
| eval Reasons = rtrim(Reasons, ", ")
| select @timestamp as Time, auditID as AuditID, verb as Verb, user.username as ActorUsername, sourceIPs as SourceIP, objectRef.namespace as PodNamespace, objectRef.name as PodName, spec.containers.image as Image, Reasons
```

elastic:
```sql
FROM kubernetes_audit_logs
| WHERE kubernetes.audit.objectRef.resource == "pods"
  AND kubernetes.audit.verb IN ("create", "update")
  AND kubernetes.audit.objectRef.namespace NOT IN ("kube-system", "kube-public", "kube-node-lease")
| EVAL isHostNetwork = CASE(kubernetes.audit.requestObject.spec.hostNetwork == "true", 1, 0),
      hasCapNetRaw = CASE(MV_CONTAINS(kubernetes.audit.requestObject.spec.containers.securityContext.capabilities.add, "NET_RAW"), 1, 0),
      Reasons = CONCAT(
        CASE(isHostNetwork == 1, "HostNetworkEnabled, ", ""),
        CASE(hasCapNetRaw == 1, "CapNetRawAdded, ", "")
      ),
      Reasons = RTRIM(Reasons, ", ")
| WHERE isHostNetwork == 1 OR hasCapNetRaw == 1
| KEEP @timestamp AS Time,
      kubernetes.audit.auditID AS AuditID,
      kubernetes.audit.verb AS Verb,
      kubernetes.audit.user.username AS ActorUsername,
      kubernetes.audit.sourceIPs AS SourceIP,
      kubernetes.audit.objectRef.namespace AS PodNamespace,
      kubernetes.audit.objectRef.name AS PodName,
      kubernetes.audit.requestObject.spec.containers.image AS Image,
      Reasons
```

sentinel one:
```sql
event.type = "KubernetesAudit"
AND kubernetes.resource = "pods"
AND kubernetes.verb IN ("create", "update")
AND kubernetes.objectRef.namespace NOT IN ("kube-system", "kube-public", "kube-node-lease")
AND (
  kubernetes.requestObject.spec.hostNetwork = "true"
  OR kubernetes.requestObject.spec.containers.securityContext.capabilities.add IN ("NET_RAW")
)
| SELECT event.timestamp AS Time,
         kubernetes.auditID AS AuditID,
         kubernetes.verb AS Verb,
         kubernetes.user.username AS ActorUsername,
         kubernetes.sourceIPs AS SourceIP,
         kubernetes.objectRef.namespace AS PodNamespace,
         kubernetes.objectRef.name AS PodName,
         kubernetes.requestObject.spec.containers.image AS Image,
         CASE
           WHEN kubernetes.requestObject.spec.hostNetwork = "true" THEN "HostNetworkEnabled"
           ELSE ""
         END +
         CASE
           WHEN kubernetes.requestObject.spec.containers.securityContext.capabilities.add IN ("NET_RAW") THEN ", CapNetRawAdded"
           ELSE ""
         END AS Reasons
| EVAL Reasons = TRIM(Reasons, ", ")
```

### ServiceAccount Token Misuse
---
Name: Kubernetes - ServiceAccount Token Misuse for Lateral Movement

Author: RW

Date: 2025-08-11

Description: Detects a ServiceAccount being used with a command-line tool like 'kubectl' to create a pod on a specific node. This is a strong indicator of lateral movement, where an attacker has stolen a ServiceAccount token from a compromised pod and is using it to spread to other nodes in the cluster. Legitimate controllers typically handle node scheduling automatically.

False Positive Sensitivity: Medium. While this behavior is highly suspicious, some administrative or CI/CD scripts might legitimately use a ServiceAccount token with kubectl to schedule pods on specific nodes. Consider excluding known service accounts or source IPs if this is expected behavior.

MITRE TTPs: T1550.001 (Use Alternate Authentication Material: Application Access Token), T1059.001 (Command and Scripting Interpreter)

splunk:
```sql
`kube_audit` -- Replace with your Kubernetes audit log source, e.g., index=k8s sourcetype=kube:audit
-- Look for pod creation events.
| search objectRef.resource="pods" verb="create"
-- The actor must be a ServiceAccount, indicating token usage.
| where like(user.username, "system:serviceaccount:%")
-- The action is performed via kubectl, not a standard controller.
| where like(userAgent, "kubectl%")
-- Exclude common system namespaces where this might be less anomalous.
| where 'objectRef.namespace' NOT IN ("kube-system", "kube-public")
-- Parse the request object to inspect the pod specification.
| spath input=requestObject
-- Check if the pod spec explicitly targets a specific node using nodeName.
| rename spec.nodeName as targetNode
| where isnotnull(targetNode)
-- Format the output for alerting and investigation.
| table _time, auditID, verb, user.username, sourceIPs{}, userAgent, 'objectRef.name', 'objectRef.namespace', "spec.containers{}.image", targetNode
| rename
    _time as Time,
    auditID as AuditID,
    verb as Verb,
    user.username as ActorUsername,
    sourceIPs{} as SourceIP,
    userAgent as UserAgent,
    'objectRef.name' as PodName,
    'objectRef.namespace' as PodNamespace,
    "spec.containers{}.image" as Image,
    targetNode as TargetNode
```

crowdstrike fql:
```sql
event_platform="K8s" event_type="Audit"
| object_ref.resource="pods" verb="create"
| user.username LIKE "system:serviceaccount:%"
| user_agent LIKE "kubectl%"
| object_ref.namespace NOT IN ("kube-system", "kube-public")
| spec.nodeName IS NOT NULL
| project timestamp, audit_id, verb, user.username, source_ips, user_agent, object_ref.name, object_ref.namespace, spec.containers.image, spec.nodeName
| rename timestamp as Time, audit_id as AuditID, verb as Verb, user.username as ActorUsername, source_ips as SourceIP, user_agent as UserAgent, object_ref.name as PodName, object_ref.namespace as PodNamespace, spec.containers.image as Image, spec.nodeName as TargetNode
```

datadog:
```sql
source:kubernetes.audit objectRef.resource:pods verb:create user.username:"system:serviceaccount:*" userAgent:"kubectl*" -objectRef.namespace:(kube-system OR kube-public) spec.nodeName:*
| select @timestamp as Time, auditID as AuditID, verb as Verb, user.username as ActorUsername, sourceIPs as SourceIP, userAgent as UserAgent, objectRef.name as PodName, objectRef.namespace as PodNamespace, spec.containers.image as Image, spec.nodeName as TargetNode
```

elastic:
```sql
FROM kubernetes_audit_logs
| WHERE kubernetes.audit.objectRef.resource == "pods"
  AND kubernetes.audit.verb == "create"
  AND kubernetes.audit.user.username LIKE "system:serviceaccount:%"
  AND kubernetes.audit.userAgent LIKE "kubectl%"
  AND kubernetes.audit.objectRef.namespace NOT IN ("kube-system", "kube-public")
  AND kubernetes.audit.requestObject.spec.nodeName IS NOT NULL
| KEEP @timestamp AS Time,
      kubernetes.audit.auditID AS AuditID,
      kubernetes.audit.verb AS Verb,
      kubernetes.audit.user.username AS ActorUsername,
      kubernetes.audit.sourceIPs AS SourceIP,
      kubernetes.audit.userAgent AS UserAgent,
      kubernetes.audit.objectRef.name AS PodName,
      kubernetes.audit.objectRef.namespace AS PodNamespace,
      kubernetes.audit.requestObject.spec.containers.image AS Image,
      kubernetes.audit.requestObject.spec.nodeName AS TargetNode
```

sentinel one:
```sql
event.type = "KubernetesAudit"
AND kubernetes.resource = "pods"
AND kubernetes.verb = "create"
AND kubernetes.user.username LIKE "system:serviceaccount:%"
AND kubernetes.userAgent LIKE "kubectl%"
AND kubernetes.objectRef.namespace NOT IN ("kube-system", "kube-public")
AND kubernetes.requestObject.spec.nodeName IS NOT NULL
| SELECT event.timestamp AS Time,
         kubernetes.auditID AS AuditID,
         kubernetes.verb AS Verb,
         kubernetes.user.username AS ActorUsername,
         kubernetes.sourceIPs AS SourceIP,
         kubernetes.userAgent AS UserAgent,
         kubernetes.objectRef.name AS PodName,
         kubernetes.objectRef.namespace AS PodNamespace,
         kubernetes.requestObject.spec.containers.image AS Image,
         kubernetes.requestObject.spec.nodeName AS TargetNode
```