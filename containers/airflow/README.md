# Airflow

A collection of Apache Airflow DAGs to illustrate advanced use cases and strategies. This project provides a secure and optimized development environment for developing and testing Airflow DAGs locally.

## Requirements

- [Docker](https://docs.docker.com/engine/install/) or [Podman](https://podman.io/getting-started/installation)
- [Docker Compose](https://docs.docker.com/compose/install/) or [Podman Compose](https://github.com/containers/podman-compose)
- [Kubernetes](https://kubernetes.io/docs/setup/) (optional for K8s deployment)
- Python 3.9+ for deployment script

## Security Improvements

- Added secure Fernet key generation
- Implemented secret management for credentials
- Configured non-root user execution
- Added resource limits and health checks
- Implemented SSL/TLS for PostgreSQL connections

## Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd airflow
```

2. Create a `.env` file with secure credentials:
```bash
AIRFLOW__CORE__FERNET_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
_AIRFLOW_WWW_USER_USERNAME=your_username
_AIRFLOW_WWW_USER_PASSWORD=your_secure_password
POSTGRES_PASSWORD=your_secure_postgres_password
```

3. Install development dependencies (optional):
```bash
pip install -r requirements-dev.txt
pre-commit install
```

## Customizing Your Image

Extend the official Airflow image using the provided `Dockerfile`. Add additional dependencies to `requirements.txt`.

## Deployment

### Docker/Podman
```bash
python deploy_airflow.py --type docker
# or
python deploy_airflow.py --type podman
```

### Kubernetes
```bash
python deploy_airflow.py --type kubernetes
```

### Cleanup
```bash
python deploy_airflow.py --type docker --action cleanup
# or
python deploy_airflow.py --type kubernetes --action cleanup
```

## Access Airflow UI

- URL: [http://localhost:8080](http://localhost:8080)
- Default credentials: Configured in `.env` file
- For Kubernetes: Use `kubectl port-forward` to access the webserver

## Configuration

Create a `deploy_config.yaml`:
```yaml
airflow_version: 3.0.3
namespace: airflow
replicas: 1
resources:
  requests:
    cpu: "500m"
    memory: "512Mi"
  limits:
    cpu: "1000m"
    memory: "2Gi"
```

## Contributing

1. Install development dependencies:
```bash
pip install -r requirements-dev.txt
pre-commit install
```

2. Run pre-commit checks:
```bash
pre-commit run --all-files
```

3. Submit a Pull Request with your changes.

## Security Best Practices

- Use strong, unique passwords for all services
- Regularly rotate Fernet keys
- Monitor logs for suspicious activity
- Keep dependencies updated
- Use network policies in Kubernetes