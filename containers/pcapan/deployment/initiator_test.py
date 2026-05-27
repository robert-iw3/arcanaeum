import unittest
import os
from initiator import load_config, render_template

class TestInitiator(unittest.TestCase):
    def test_load_config(self):
        with open('test_config.yaml', 'w') as f:
            f.write('deploy_type: podman\n')
        config = load_config('test_config.yaml')
        self.assertEqual(config['deploy_type'], 'podman')
        os.remove('test_config.yaml')

    def test_render_template(self):
        with open('test.j2', 'w') as f:
            f.write('deploy_type: {{ deploy_type }}\n')
        render_template('test.j2', 'test.yaml', {'deploy_type': 'podman'})
        with open('test.yaml', 'r') as f:
            content = f.read()
        self.assertIn('deploy_type: podman', content)
        os.remove('test.j2')
        os.remove('test.yaml')

if __name__ == '__main__':
    unittest.main()