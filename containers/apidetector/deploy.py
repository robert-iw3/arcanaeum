import argparse
import subprocess
import os
import yaml
from pathlib import Path

def deploy_docker():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    dockerfile_path = os.path.join(current_dir, 'Dockerfile')

    subprocess.run(['docker', 'build', '-t', 'apidetector:latest', '.'], check=True)
    subprocess.run([
        'docker', 'run', '-d', '--name', 'apidetector',
        '-p', '8080:8080', 'apidetector:latest'
    ], check=True)
    print("Docker deployment completed. Access at http://localhost:8080")

def deploy_podman():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    dockerfile_path = os.path.join(current_dir, 'Dockerfile')

    subprocess.run(['podman', 'build', '-t', 'apidetector:latest', '.'], check=True)
    subprocess.run([
        'podman', 'run', '-d', '--name', 'apidetector',
        '-p', '8080:8080', 'apidetector:latest'
    ], check=True)
    print("Podman deployment completed. Access at http://localhost:8080")

def deploy_kubernetes():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    k8s_yaml = os.path.join(current_dir, 'k8s-deployment.yaml')
    subprocess.run(['kubectl', 'apply', '-f', k8s_yaml], check=True)
    print("Kubernetes deployment completed. Check pods with 'kubectl get pods'")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deploy APIDetector")
    parser.add_argument('--docker', action='store_true', help='Deploy using Docker')
    parser.add_argument('--podman', action='store_true', help='Deploy using Podman')
    parser.add_argument('--k8s', action='store_true', help='Deploy using Kubernetes')
    args = parser.parse_args()

    if sum([args.docker, args.podman, args.k8s]) > 1:
        print("Please choose only one deployment method")
    elif args.docker:
        deploy_docker()
    elif args.podman:
        deploy_podman()
    elif args.k8s:
        deploy_kubernetes()
    else:
        print("Please specify deployment method with --docker, --podman, or --k8s")