# syntax=docker/dockerfile:1
# https://github.com/NeffIsBack/wsuks
ARG repo="docker.io" \
    base_image="alpine:3.23" \
    image_hash="1882fa4569e0c591ea092d3766c4893e19b8901a8e649de7067188aba3cc0679"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/root/.local/bin:/usr/local/bin:/usr/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

RUN \
    apk add --no-cache \
        bash \
        tzdata \
        ca-certificates \
        libgcc \
        libstdc++ \
        musl-dev \
        linux-headers \
        build-base \
        python3-dev \
        py3-pip \
        pipx \
        py3-nftables \
        py3-netifaces

RUN \
    pipx ensurepath; \
    pipx install wsuks --system-site-packages; \
    apk del --purge --no-network \
        libgcc \
        libstdc++ \
        musl-dev \
        linux-headers \
        build-base \
        py3-pip; \
    rm -rf /var/cache/apk/* /root/.cache/*

CMD [ "bash" ]
# wsuks -h