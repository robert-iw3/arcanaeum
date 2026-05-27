# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f"

FROM ${repo}/${base_image}@sha256:${image_hash}

RUN apk add --no-cache python3 py3-pip jq auditd rsyslog docker-cli && \
    pip install --no-cache-dir typing-extensions && \
    mkdir -p /var/backups/docker /var/log /etc/audit/rules.d && \
    chown root:root /var/backups/docker /var/log /etc/audit/rules.d && \
    chmod 750 /var/backups/docker /var/log /etc/audit/rules.d

COPY docker_stigs_v2.py /docker_stig.py
COPY docker.rules /etc/audit/rules.d/docker.rules

RUN chmod 755 /docker_stig.py && chmod 640 /etc/audit/rules.d/docker.rules

CMD ["python3", "/docker_stig.py", "--json"]