# PCAP Analyzer

Rust-based PCAP analyzer with TypeScript/Vite React web app for network forensics. Supports Docker, Podman, Kubernetes. Features ML anomaly detection, IPv6 private filtering, HTTPS, rate limiting.

## Parsed PCAP Data
- Hosts: SNI (TLS), DNS (A/AAAA/CNAME), HTTP Host headers
- Ports: TCP/UDP source/destination
- Data Size: Bytes per IP
- User Agents: HTTP User-Agent strings
- Certificates: TLS subject, issuer, validity
- Timestamps: Packet timestamps (UTC)
- Protocol Stats: TCP/UDP packet counts and ratios
- Packet Count: Total packets per IP
- IPv6 Support: Parses IPv6 with private filtering
- Anomalies: ML-based detection (packet count, size, ports, timestamp patterns, protocol ratios)
- Output: JSON

## Prerequisites
- Docker or Podman
- Node.js v24+
- Rust v1.89+
- Python 3.12+
- Ansible
- Trivy
- kubectl (Kubernetes)
- OpenSSL (for SSL certs)

## Setup
1. Clone: `git clone <repo-url> && cd pcapan-project`
2. **Rust Analyzer**:
   - Build: `cd rust-app && cargo build --release`
   - Run: `./target/release/pcapan --dir /path/to/pcaps --whitelist ../whitelist.yaml --output results.json`
   - Docker: `docker build -t pcapan:latest . && docker run --rm -v /path/to/pcaps:/pcaps -v /path/to/whitelist.yaml:/whitelist.yaml pcapan:latest --dir /pcaps --whitelist /whitelist.yaml --output /results.json`
   - Podman: Replace `docker` with `podman`
3. **Web App**:
   - Generate SSL certs: `cd web-app/certs && openssl req -x509 -newkey rsa:4096 -nodes -out server.crt -keyout server.key -days 365`
   - Build: `cd web-app && npm install && npm run build`
   - Start: `npm run start`
   - Access: `https://localhost:3000` (Login: user/pass)
   - Docker: `docker build -t pcapan-web:latest . && docker run -d -p 3000:3000 -v /path/to/pcaps:/pcaps -e JWT_SECRET=secret pcapan-web:latest`
4. **Deployment**:
   - Edit: `deployment/config.yaml` (set `deploy_type: docker`, `podman`, or `kubernetes`)
   - Run: `cd deployment && python initiator.py`
5. **Security**: Scan images: `trivy image pcapan:latest && trivy image pcapan-web:latest`
6. **Monitoring**: Prometheus at `https://localhost:3000/metrics` (requests, analysis duration)
7. **Tests**:
   - Rust: `cd rust-app && cargo test`
   - Web: `cd web-app && npm test`
   - Python: `cd deployment && python -m unittest initiator_test.py`
   - Integration: `cd deployment && python integration_test.py`

## Features
- Web app: Light/dark mode, JWT-auth uploads (login at `/api/login`)
- ML: RandomForest anomaly detection (packet count, size, ports, timestamp patterns, protocol ratios)
- Security: HTTPS, rate limiting (10 req/min per IP)
- Kubernetes: Web app Deployment/Service with PVC, analyzer Job
- CI/CD: GitHub Actions (`ci.yml`)

## Notes
- Profile Rust: `cd rust-app && cargo flamegraph`
- Extend ML: Add more anomaly features (e.g., certificate anomalies)