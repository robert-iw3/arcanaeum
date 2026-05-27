#!/bin/bash

# Orchestrator Bash Script for Kubernetes Deployment
# Usage: ./deploy_k8s_stack.sh
# Assumptions: kubectl configured, YAML files in current dir (named 01-*.yaml, etc.)
# Secrets: Uses env vars or prompts; set SIEM_TOKEN, MINIO_USER, MINIO_PASSWORD before running.
# Author: Robert Weber

set -e  # Exit on error

# Check prerequisites
if ! command -v kubectl &> /dev/null; then
    echo "kubectl not found. Please install and configure it."
    exit 1
fi

# Prompt for secrets if not set
SIEM_TOKEN=${SIEM_TOKEN:-$(read -sp "Enter SIEM Token: " token; echo $token)}
MINIO_USER=${MINIO_USER:-"minioadmin"}
MINIO_PASSWORD=${MINIO_PASSWORD:-"minioadmin"}

# Create namespace
kubectl apply -f namespace.yaml

# Create secrets (base64 encode)
kubectl create secret generic siem-token --from-literal=token=$(echo -n "$SIEM_TOKEN" | base64) -n security || true
kubectl create secret generic minio-creds --from-literal=user=$(echo -n "$MINIO_USER" | base64) --from-literal=password=$(echo -n "$MINIO_PASSWORD" | base64) -n security || true

# Apply in order
echo "Applying ConfigMaps..."
kubectl apply -f configmaps.yaml -n security
kubectl apply -f grafana-configs.yaml -n security
kubectl apply -f grafana-dashboards.yaml -n security

echo "Applying PVCs..."
kubectl apply -f pvcs.yaml -n security

echo "Applying Deployments/StatefulSets..."
kubectl apply -f deployments.yaml -n security

echo "Applying Services..."
kubectl apply -f services.yaml -n security

echo "Applying HPA..."
kubectl apply -f hpa.yaml -n security

echo "Applying CronJob..."
kubectl apply -f cronjob.yaml -n security

echo "Applying Network Policies..."
kubectl apply -f networkpolicies.yaml -n security

echo "Applying Prometheus..."
kubectl apply -f prometheus.yaml -n security

echo "Applying Grafana..."
kubectl apply -f grafana.yaml -n security

echo "Deployment complete! Check status with: kubectl get all -n security"