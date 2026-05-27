import yaml
import jinja2
import subprocess

def load_config(config_path='config.yaml'):
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def render_template(template_path, output_path, vars_dict):
    with open(template_path, 'r') as f:
        template = jinja2.Template(f.read())
    with open(output_path, 'w') as f:
        f.write(template.render(vars_dict))

def run_ansible(playbook):
    subprocess.run(['ansible-playbook', playbook], check=True)

if __name__ == '__main__':
    config = load_config()
    deploy_type = config.get('deploy_type', 'docker')
    render_template(f'templates/deploy_{deploy_type}.j2', f'deploy_{deploy_type}.yaml', config)
    run_ansible(f'deploy_{deploy_type}.yaml')