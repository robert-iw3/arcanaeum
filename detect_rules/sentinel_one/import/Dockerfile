# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.23" \
    image_hash="1882fa4569e0c591ea092d3766c4893e19b8901a8e649de7067188aba3cc0679"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/import/sentinelone-import/bin:/usr/local/bin:/usr/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

# Replace with your SentinelOne API token
ENV API_TOKEN="YOUR_API_TOKEN"
# Replace with your SentinelOne instance URL
ENV SENTINELONE_API_URL="https://your-sentinelone-instance.s1.systems/api/v2.0"

RUN \
    apk add --no-cache \
        bash \
        curl \
        tzdata \
        ca-certificates \
        musl-dev \
        linux-headers \
        python3 \
        py3-pip

WORKDIR /import

COPY . .

RUN \
    python3 -m venv sentinelone-import; \
    . sentinelone-import/bin/activate; \
    pip install --upgrade pip requests urllib3; \
    rm -rf /var/cache/apk/* /root/.cache/*; \
    apk cache clean

CMD ["python3", "/import/import_searches.py"]