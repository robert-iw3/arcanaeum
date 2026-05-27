#!/bin/bash

cat << EOF | sudo tee /etc/logrotate.d/list_packet_sniffers
/var/log/list_packet_sniffers.log /var/log/packet_sniffers_summary.json {
    size 10M
    rotate 5
    compress
    create 600 root root
    postrotate
        systemctl restart list_packet_sniffers.service >/dev/null 2>&1 || true
    endscript
}
EOF