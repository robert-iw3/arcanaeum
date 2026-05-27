### firewalld configurations
---

```bash
# Run:

sudo python3 configure_firewalld.py --interface eth0 --subnet 192.168.1.0/24 --zone custom --verbose --json

# Check logs:

tail -f /var/log/firewalld_config.log
tail -f /var/log/firewalld_config.json | jq

# Monitor dropped packets:

tail -f /var/log/firewalld-dropped.log
```