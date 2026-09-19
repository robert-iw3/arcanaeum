# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f"

FROM ${repo}/${base_image}@sha256:${image_hash}

RUN apk add --no-cache python3 py3-pip coreutils findutils && \
    pip install --no-cache-dir typing-extensions && \
    mkdir -p /var/log && \
    chown root:root /var/log && \
    chmod 750 /var/log

COPY ssh_key_audit_v2.py /ssh_key_audit.py

RUN chmod 755 /ssh_key_audit.py

CMD ["python3", "/ssh_key_audit.py", "--json"]