#!/bin/bash

cp list_packet_sniffers_v2.py /usr/bin/list_packet_sniffers_v2.py
chmod +x /usr/bin/list_packet_sniffers_v2.py

# Create the systemd service file
cat << EOF | sudo tee /etc/systemd/system/list_packet_sniffers.service
[Unit]
Description=List Packet Sniffers Monitor
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/bin/list_packet_sniffers_v2.py
User=root
# Ensure log and JSON files exist with proper permissions
ExecStartPre=/bin/sh -c 'touch /var/log/list_packet_sniffers.log /var/log/packet_sniffers_summary.json && chmod 600 /var/log/list_packet_sniffers.log /var/log/packet_sniffers_summary.json'

[Install]
WantedBy=multi-user.target
EOF

# Create the systemd timer file
cat << EOF | sudo tee /etc/systemd/system/list_packet_sniffers.timer
[Unit]
Description=Periodic List Packet Sniffers Monitor

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h
Unit=list_packet_sniffers.service

[Install]
WantedBy=timers.target
EOF

# Reload systemd and enable the timer
sudo systemctl daemon-reload
sudo systemctl enable --now list_packet_sniffers.timer