# APIDetector Deployment Guide

APIDetector is a powerful API endpoint discovery tool. Follow these steps to deploy:

## Prerequisites

- Docker, Podman, or Kubernetes with kubectl
- Python 3.x

## Deployment Options

### Docker

```bash
python deploy.py --docker
```
Access at: http://localhost:8080

### Podman

```bash
python deploy.py --podman
```
Access at: http://localhost:8080

### Kubernetes

```bash
python deploy.py --k8s
```

Check status: `kubectl get pods -n apidetector`

Access via LoadBalancer IP (get with `kubectl get svc -n apidetector`)