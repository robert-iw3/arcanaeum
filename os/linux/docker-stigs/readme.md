### Docker STIG'ing
---

yup, we doing STIG's, uhgain.

```bash
# Direct Run:

sudo VERBOSE=Y JSON_OUTPUT=Y ./docker_stig.sh --ip 192.168.1.100 #bash
sudo python3 docker_stig.py --verbose --json --ip 192.168.1.100 #python

# Check logs:
tail -f /var/log/docker_stig.log
tail -f /var/log/docker_stig.log.json | jq

# Restart Docker:
systemctl restart docker

# Docker:

# Build:
docker build -t docker-stig .

# Run:
docker run --rm --cap-add SYS_ADMIN --cap-add AUDIT_CONTROL \
    -v /etc/docker:/etc/docker -v /lib/systemd/system:/lib/systemd/system \
    -v /run/containerd:/run/containerd -v /var/log:/var/log -v /var/backups:/var/backups docker-stig

# Kubernetes:

kubectl apply -f docker_stig.yaml

# View logs:

kubectl logs -l app=docker-stig
```