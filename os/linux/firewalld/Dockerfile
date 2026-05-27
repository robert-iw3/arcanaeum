# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f"

FROM ${repo}/${base_image}@sha256:${image_hash}

RUN apk add --no-cache python3 py3-pip firewalld rsyslog fail2ban auditd && \
    pip install --no-cache-dir typing-extensions && \
    mkdir -p /var/backups/firewalld /var/log /etc/audit/rules.d && \
    chown root:root /var/backups/firewalld /var/log /etc/audit/rules.d && \
    chmod 750 /var/backups/firewalld /var/log /etc/audit/rules.d

COPY configure_firewalld.py /configure_firewalld.py
COPY firewalld.rules /etc/audit/rules.d/firewalld.rules

RUN chmod 755 /configure_firewalld.py && chmod 640 /etc/audit/rules.d/firewalld.rules

CMD ["python3", "/configure_firewalld.py", "--json"]