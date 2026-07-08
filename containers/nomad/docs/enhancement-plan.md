# Nomad deployment: gap analysis and enhancement plan

Scope: everything under `nomad/` as of this pass (ansible avenue, terraform/AWS avenue,
baremetal/Vagrant avenue, `deploy.py` orchestrator, `tests/`). This is a snapshot for
planning the next round of work, not a task list to execute blindly — sizes and
priorities should be revisited against actual usage once the cluster is running
real workloads.

## What's solid today

- TLS: single shared CA signs every node (ansible), no independent per-host CAs.
- Secrets: no defaults shipped for gossip key/Vault token; AWS avenue generates them
  once into Secrets Manager (KMS-encrypted) and fetches at boot via IAM, never bakes
  them into a template.
- Multi-server clustering via cloud auto-join (`retry_join`) rather than a static
  peer list, so ASGs can actually scale.
- `deploy.py` validates Raft quorum parity and config shape before touching
  `ansible-playbook`/`terraform`.
- `tests/` catches real breakage (`tofu validate`, `tflint`, `fmt`) in CI, not just
  after a failed apply.

## Gaps, by category

### 1. Security

| Gap | Why it matters | Rough effort |
|---|---|---|
| Security groups allow `0.0.0.0/0` on 4646 (HTTP API), 22 (SSH), 80/443 in all three cluster modules | ACLs/TLS mitigate but don't replace network segmentation; SSH open to the internet is the biggest single item here | S — restrict to a bastion/VPN CIDR variable, default-deny otherwise |
| No secret rotation for the gossip encryption key or ACL bootstrap token | Generated once, forever; a leaked gossip key requires a manual `nomad operator gossip keyring` rotation no automation covers | M |
| Public Grafana ALB has only a password, no WAF/IP allowlist | Grafana exposes cluster topology and metrics; a single password is thin | S — attach `aws_wafv2_web_acl` or restrict listener to a CIDR |
| No CIS/host-hardening baseline beyond Nomad's own ports | `prepare_host.yml` opens exactly what Nomad/Podman need but doesn't touch SSH hardening, auditd, or a CIS profile | M — could reuse patterns from `kube-bench/` or `stig-manager/` elsewhere in this repo |
| Sentinel policy is a single stub template | No real admission control on job submissions (image sources, driver restrictions, resource ceilings) | M |

### 2. Reliability / HA

| Gap | Why it matters | Rough effort |
|---|---|---|
| No Raft snapshot backup/DR story | `nomad operator snapshot save` is never automated or shipped off-box; a lost quorum with no recent snapshot is a full rebuild | M — a scheduled Nomad system job or cron + S3 upload |
| No documented rolling-upgrade procedure | Bumping `nomad_version` mid-cluster-lifetime isn't covered — order of operations (clients before servers? leader step-down first?) isn't written down anywhere | S (docs) → M if scripted |
| Secondary AWS region depends on the primary region's Secrets Manager at boot | Every secondary-region instance makes a cross-region API call during cloud-init; if the primary region is unreachable, secondary-region instances fail to bootstrap even though they're meant to be the failover | M — replicate the secret cross-region (`aws_secretsmanager_secret_replica`) |
| No remote Terraform state backend configured | State is local by default; concurrent `terraform apply` from two operators (or two CI runs) will race or corrupt state | S — add an S3+DynamoDB (or Terraform Cloud) backend block, gated behind a variable so local dev still works |

### 3. Scalability / scheduling features

| Gap | Why it matters | Rough effort |
|---|---|---|
| `nomad_autoscaler_enabled` exists as a variable but nothing deploys the actual [Nomad Autoscaler](https://developer.hashicorp.com/nomad/tools/autoscaling) | Only EC2-level ASG scaling exists (AWS avenue only); there's no job-level horizontal scaling anywhere, and the ansible avenue has zero autoscaling story | M — ship the autoscaler as a Nomad job + a target plugin |
| No CSI plugin wired up | Any stateful workload (databases, queues) has nowhere to get a real persistent volume; `host_volume` in the ansible role is the only option and it's node-local | M–L depending on backend (EBS CSI is the natural AWS choice) |
| No Consul Connect actually enabled in either avenue's Consul config | `examples/jobs/countdash-connect.nomad.hcl` assumes Connect works, but neither `user-data-consul.sh` nor the ansible Consul integration turns on `connect { enabled = true }` | S |

### 4. Observability / operations

| Gap | Why it matters | Rough effort |
|---|---|---|
| No alerting wired from Prometheus/CloudWatch to anywhere a human sees it | Metrics are collected but nothing pages; `aws_cloudwatch_metric_alarm` resources exist for autoscaling only, not for "servers down" / "quorum lost" | S–M — add `aws_sns_topic` subscriptions or Alertmanager |
| Logs stop at fluent-bit → stdout | No shipped-off-box aggregation (CloudWatch Logs, Loki) — logs die with the instance on termination | M |
| Ansible avenue has no metrics/monitoring counterpart at all | `terraform/modules/monitoring` has no equivalent role in `ansible/`; an ansible-deployed cluster is currently unobservable out of the box | M |

### 5. Multi-cloud / portability

| Gap | Why it matters | Rough effort |
|---|---|---|
| `terraform/` is AWS-only despite `deploy.py`'s "avenue" abstraction implying more could be added | Anyone on GCP/Azure has to write a new avenue from scratch with no scaffolding | L — out of scope unless there's an actual second-cloud requirement |
| `baremetal/Vagrantfile` has never been run against a real libvirt or vSphere target, only Ruby-syntax-checked | The multi-VM rewrite is plausible but unverified; the `vsphere` provider block in particular depends on plugin/template conventions that are only documented, not tested | S — needs one real run against each provider to shake out surprises (dummy box URL, vSphere folder/permissions, etc.) |

### 6. Testing

| Gap | Why it matters | Rough effort |
|---|---|---|
| No test actually exercises a live `nomad agent` (bootstrap, join, `nomad server members`) | Everything today is static (`tofu validate`, `tflint`, ansible-lint if run) — a config can be "valid" and still fail to form quorum at runtime | M — a container-based smoke test (podman-in-podman or a 3-container Nomad dev cluster) would close this |
| Packer template (`terraform/packer/nomad-podman-ami.pkr.hcl`) has no CI check at all | Unlike the Terraform modules, nothing runs `packer validate` against it | S — add a `packer validate`/`packer fmt -check` step to the same tofu Dockerfile or a sibling one |
| `ansible/roles/nomad` has no molecule tests | The role is only validated by `ansible-lint`/syntax-check in `.gitlab-ci.yml`, never actually run against a container/VM in CI | M |

## Suggested phasing

This is a rough ordering by (impact × how cheap it is to close), not a commitment:

1. **Quick wins (S effort, do first):** restrict security group ingress to a
   bastion/VPN CIDR variable; enable Consul Connect in both avenues; add a remote
   Terraform state backend (optional via variable); add `packer validate` to CI.
2. **Fill the biggest reliability hole:** automated Raft snapshot backup + a written
   rolling-upgrade runbook; cross-region secret replication for the AWS avenue.
3. **Close the observability gap on the ansible avenue:** port (or link to) an
   equivalent monitoring role so ansible-deployed clusters aren't flying blind, plus
   basic alerting (SNS/Alertmanager) on top of what's already collected.
4. **Scheduling maturity:** real CSI volume support and the actual Nomad Autoscaler,
   in that order — persistent storage unblocks more workload types than autoscaling
   does for a cluster this size.
5. **Everything else** (Sentinel policy library, host-hardening baseline, live
   smoke-test harness, molecule tests) — valuable but lower urgency than the above.

Items intentionally not proposed: a second cloud avenue (no stated requirement)
and Kubernetes-style admission webhooks (Sentinel already fills that role for
Nomad; building a parallel system would be redundant).
