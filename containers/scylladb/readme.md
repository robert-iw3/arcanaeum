# ScyllaDB

## Overview
Deploys ScyllaDB 5.4 Enterprise on Kubernetes, Docker, or Podman. Supports 1 to 100+ tenant keyspaces, with authentication, TLS, RBAC, and audit logging. TLS certificates are dynamically generated for Docker/Podman. Configure via `user_config.yaml`.

## File Structure
```
scylladb-deployment/
├── ansible/
│   ├── inventory.ini
│   └── playbooks/
│       ├── deploy-sharded.yml
│       └── templates/
│           ├── docker-compose.yml.j2
│           ├── ca.cnf.j2
│           ├── scylla.cnf.j2
│           └── scylla-cluster.cnf.j2
├── certs/
│   ├── ca.pem
│   ├── scylla.pem
│   └── scylla-cluster.pem
├── config/
│   └── user_config.yaml
├── deploy_scylladb.py
├── k8s-scylladb.yaml
└── README.md
```

## Prerequisites
- Kubernetes (kubectl), Docker, or Podman with `docker-compose`/`podman-compose`.
- Ansible and OpenSSL for certificate generation.
- ScyllaDB Operator (Kubernetes) or image (`scylladb/scylla-enterprise:5.4`).

## Configuration
1. **Configure user_config.yaml**:
   - Set `platform` (docker, podman, kubernetes, ansible).
   - Set `num_tenants` (1 for single DB, 100 for enterprise).
   - Define `tenant_config.keyspaces` for custom keyspaces (optional). E.g.:
     ```yaml
     num_tenants: 1  # or 100
     tenant_config:
       keyspaces:
         - name: orders
           replication:
             class: SimpleStrategy
             replication_factor: 3
           tables:
             - name: data
               columns:
                 - name: order_id
                   type: uuid
                 - name: customer_id
                   type: text
               partition_key: customer_id
     ```
   - Customize TLS: `cert_path`, `ca_cn`, `node_cn`, `san`, `cert_days`. E.g.:
     ```yaml
     tls_enabled: true
     cert_path: ./certs
     ca_cn: My CA
     san: dns:scylla.example.com,ip:192.168.1.100
     ```
   - Set `tls_enabled: false` for testing (no TLS).

2. **Install Dependencies**:
   - Kubernetes:
     ```bash
     helm repo add scylla https://scylladb.github.io/scylla-operator/
     helm repo update
     helm install scylla-operator scylla/scylla-operator --namespace scylla --create-namespace
     ```
   - Docker/Podman:
     ```bash
     apt-get install -y docker.io docker-compose openssl  # or podman podman-compose
     ansible-galaxy collection install community.docker
     ```

3. **Deploy**:
   - Run: `python3 deploy_scylladb.py config/user_config.yaml`
   - Kubernetes: `kubectl apply -f k8s-scylladb.yaml` (manually provide certs in Secrets).
   - Docker/Podman: `docker compose -f docker-compose.yml up -d` or `podman-compose up -d`
   - Ansible: `ansible-playbook -i ansible/inventory.ini ansible/playbooks/deploy-enterprise-sharded.yml --ask-vault-pass`
   - Certificates are generated in `cert_path` (e.g., `./certs`).

4. **Verify**:
   - Connect: `cqlsh --ssl -u admin -p <pass> localhost 9142` (Docker/Podman) or `scylla-cluster.scylla.svc.cluster.local 9142` (Kubernetes).
   - Check: `DESCRIBE KEYSPACES` (e.g., `orders`, `tenant_1`). Verify: `SELECT * FROM orders.data;`.

## Extensibility
- **Single DB**: Set `num_tenants: 1`, define one keyspace in `tenant_config.keyspaces`.
- **100 DBs**: Set `num_tenants: 100`, define keyspaces or use defaults (e.g., `tenant_N`).
- Customize TLS via `ca.cnf.j2`, `scylla.cnf.j2`, `scylla-cluster.cnf.j2` in `ansible/playbooks/templates`.

## Fault Tolerance
- 3 nodes/rack, replication factor 3.
- Kubernetes: HPA scales 3-12 replicas. Operator handles failures.
- Docker/Podman: Auto-restart, seed nodes ensure cluster formation.

## Performance
- Shard-per-core (16 shards, 8-core node) for 1000s QPS.
- Cache: 12GB (75% of 16GB RAM).
- Tenant init: ~0.5s for 100 keyspaces.

## Security
- Auth: PasswordAuthenticator, RBAC per tenant.
- TLS: Auto-generated certs for client (9142) and internode (7001). Set `tls_enabled: false` for testing.
- Non-root: UID 999. Perms: 750/400.
- Audit: Enabled (AUTH, DDL, 5% overhead).
- Use Vault for passwords in production.

## Notes
- Monitor: ScyllaDB Manager (port 10001) or Prometheus.
- Backup: Configure ScyllaDB Manager for backups.
- Test: Start with `num_tenants=1`, `tls_enabled: false`.
- Production: Customize `san` in `user_config.yaml` for node hostnames/IPs.