import pytest
import yaml
from jinja2 import Environment, FileSystemLoader
from pathlib import Path

def test_render_docker_compose():
    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template('docker-compose.j2')
    context = {
        'rudder_version': '1.25.0',
        'image_registry': 'docker.io',
        'workspace_token': 'test-token',
        'enable_logging': False
    }
    rendered = template.render(**context)
    parsed = yaml.safe_load(rendered)
    assert parsed['services']['rudder-server']['image'] == 'docker.io/rudderlabs/rudder-server:1.25.0'
    assert parsed['services']['rudder-transformer']['depends_on']['rudder-server']['condition'] == 'service_healthy'

def test_render_helm_values():
    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template('k8s-helm-values.j2')
    context = {
        'rudder_version': '1.25.0',
        'image_registry': 'docker.io',
        'namespace': 'rudderstack',
        'replicas': 2,
        'workspace_token': 'test-token',
        'enable_logging': False
    }
    rendered = template.render(**context)
    parsed = yaml.safe_load(rendered)
    assert parsed['rudderWorkspaceToken'] == 'test-token'
    assert parsed['replicaCount'] == 2