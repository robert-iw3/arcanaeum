# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.23" \
    image_hash="1882fa4569e0c591ea092d3766c4893e19b8901a8e649de7067188aba3cc0679"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/root/.local/bin:/usr/local/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/sbin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

RUN \
    apk add --no-cache -U \
        bash \
        tzdata \
        ca-certificates \
        build-base \
        krb5-dev \
        openldap-dev \
        libsasl \
        git \
        python3-dev \
        pipx

RUN \
    pipx ensurepath ; \
    pipx install git+https://github.com/synacktiv/gpoParser; \
    rm -rf /var/cache/apk/* /root/.cache/*

CMD [ "bash" ]
# gpoParser -h