# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f"

FROM ${repo}/${base_image}@sha256:${image_hash}

RUN apk add --no-cache python3 py3-pip aide rsyslog libcap-utils && \
    pip install --no-cache-dir typing-extensions && \
    mkdir -p /var/backups/aide /etc/aide/aide.conf.d /var/log/aide /var/lib/aide && \
    chown root:root /var/backups/aide /etc/aide /var/log/aide /var/lib/aide && \
    chmod 750 /var/backups/aide /var/log/aide /var/lib/aide

COPY configure_aide.py /configure_aide.py

RUN chmod 755 /configure_aide.py

CMD ["python3", "/configure_aide.py", "--json"]