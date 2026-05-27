import unittest
import requests
import subprocess
import os
import time
import tempfile
import shutil

class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.base_url = 'https://localhost:3000'
        self.temp_dir = tempfile.mkdtemp()
        self.pcap_dir = os.path.join(self.temp_dir, 'pcaps')
        os.makedirs(self.pcap_dir)
        shutil.copy('mock.pcap', self.pcap_dir)
        subprocess.run(['docker', 'run', '-d', '-p', '3000:3000', '-v', f'{self.pcap_dir}:/pcaps', '-v', f'{os.getcwd()}/whitelist.yaml:/whitelist.yaml', '-e', 'JWT_SECRET=secret', 'pcapan-web:latest'])
        time.sleep(5)

    def tearDown(self):
        subprocess.run(['docker', 'stop', '$(docker ps -q)'])
        shutil.rmtree(self.temp_dir)

    def test_end_to_end(self):
        resp = requests.post(f'{self.base_url}/api/login', json={'username': 'user', 'password': 'pass'}, verify=False)
        self.assertEqual(resp.status_code, 200)
        token = resp.json()['token']
        files = {'pcapDir': open(os.path.join(self.pcap_dir, 'mock.pcap'), 'rb')}
        headers = {'Authorization': f'Bearer {token}'}
        resp = requests.post(f'{self.base_url}/api/analyze', files=files, headers=headers, verify=False)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(isinstance(resp.json(), dict))

    def test_rate_limit(self):
        resp = requests.post(f'{self.base_url}/api/login', json={'username': 'user', 'password': 'pass'}, verify=False)
        self.assertEqual(resp.status_code, 200)
        token = resp.json()['token']
        files = {'pcapDir': open(os.path.join(self.pcap_dir, 'mock.pcap'), 'rb')}
        headers = {'Authorization': f'Bearer {token}'}
        for _ in range(10):
            resp = requests.post(f'{self.base_url}/api/analyze', files=files, headers=headers, verify=False)
            self.assertEqual(resp.status_code, 200)
        resp = requests.post(f'{self.base_url}/api/analyze', files=files, headers=headers, verify=False)
        self.assertEqual(resp.status_code, 429)

if __name__ == '__main__':
    unittest.main()