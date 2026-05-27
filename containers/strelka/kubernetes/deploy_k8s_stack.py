"""
Orchestrator Python Script for Kubernetes Deployment
Usage: python deploy_k8s_stack.py
Assumptions: kubectl installed and configured, YAML files in current dir.
Secrets: Uses env vars or prompts.
Author: Robert Weber
"""
import subprocess
import base64
import os
import getpass

def run_cmd(cmd):
    """Run shell command and handle errors."""
    try:
        subprocess.check_call(cmd, shell=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running '{cmd}': {e}")
        exit(1)

# Get secrets
siem_token = os.getenv('SIEM_TOKEN') or getpass.getpass("Enter SIEM Token: ")
minio_user = os.getenv('MINIO_USER', 'minioadmin')
minio_password = os.getenv('MINIO_PASSWORD', 'minioadmin')

# Create namespace
run_cmd("kubectl apply -f namespace.yaml")

# Create secrets
run_cmd(f"kubectl create secret generic siem-token --from-literal=token={base64.b64encode(siem_token.encode()).decode()} -n security || true")
run_cmd(f"kubectl create secret generic minio-creds --from-literal=user={base64.b64encode(minio_user.encode()).decode()} --from-literal=password={base64.b64encode(minio_password.encode()).decode()} -n security || true")

# Apply in order
print("Applying ConfigMaps...")
run_cmd("kubectl apply -f configmaps.yaml -n security")
run_cmd("kubectl apply -f grafana-configs.yaml -n security")
run_cmd("kubectl apply -f grafana-dashboards.yaml -n security")

print("Applying PVCs...")
run_cmd("kubectl apply -f pvcs.yaml -n security")

print("Applying Deployments/StatefulSets...")
run_cmd("kubectl apply -f deployments.yaml -n security")

print("Applying Services...")
run_cmd("kubectl apply -f services.yaml -n security")

print("Applying HPA...")
run_cmd("kubectl apply -f hpa.yaml -n security")

print("Applying CronJob...")
run_cmd("kubectl apply -f cronjob.yaml -n security")

print("Applying Network Policies...")
run_cmd("kubectl apply -f networkpolicies.yaml -n security")

print("Applying Prometheus...")
run_cmd("kubectl apply -f prometheus.yaml -n security")

print("Applying Grafana...")
run_cmd("kubectl apply -f grafana.yaml -n security")

print("Deployment complete! Check status with: kubectl get all -n security")