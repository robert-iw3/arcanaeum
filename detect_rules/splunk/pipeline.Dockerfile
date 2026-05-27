# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.23" \
    image_hash="1882fa4569e0c591ea092d3766c4893e19b8901a8e649de7067188aba3cc0679"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/import/splunk-import/bin:/usr/local/bin:/usr/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

ENV SPLUNK_HOST="your_splunk_host" \
    SPLUNK_PORT="8089" \
    SPLUNK_USER="admin" \
    APP_CONTEXT="search" \
    SPLUNK_SSL_VERIFY="true" \
    ACL_READ="power,admin" \
    ACL_WRITE="admin" \
    RATE_LIMIT_CALLS=10 \
    RATE_LIMIT_PERIOD=60 \
    API_TIMEOUT=10 \
    POOL_SIZE=4 \
    MAX_FILES=1000 \
    VALIDATE_API="true" \
    CONFIG_PATH="/import/config.json"

RUN apk add --no-cache \
        bash \
        curl \
        tzdata \
        ca-certificates \
        python3 \
        py3-pip ; \
    python3 -m venv /import/splunk-import ; \
    . /import/splunk-import/bin/activate ; \
    pip install --no-cache-dir --upgrade \
        pip \
        requests \
        urllib3 \
        jsonschema \
        ratelimit ; \
    apk del --purge ; \
    rm -rf /var/cache/apk/* /root/.cache/*

RUN adduser -D splunkuser
USER splunkuser

WORKDIR /import
COPY . .

# Support Docker secrets for SPLUNK_PASSWORD
CMD ["sh", "-c", "SPLUNK_PASSWORD=$(cat /run/secrets/splunk_password 2>/dev/null || echo $SPLUNK_PASSWORD) python pipeline.py"]