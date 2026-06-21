# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.24" \
    image_hash="79ff19e9084a00eece421b2523fb93e22d730e2c0e525905de047e848e56d95f"

FROM ${repo}/${base_image}@sha256:${image_hash}

ARG VERSION=3.5.5
ENV PATH=/teamfiltration:/usr/local/bin:/usr/bin:$PATH

RUN \
    apk add --no-cache \
        bash \
        wget \
        tzdata \
        coreutils \
        ca-certificates \
        libgcc \
        libstdc++ \
        musl-dev \
        linux-headers; \
    \
    mkdir /teamfiltration && cd /teamfiltration; \
    wget --progress=bar:force https://github.com/Flangvik/TeamFiltration/releases/download/v${VERSION}/TeamFiltration-v${VERSION}-linux-x86_64.zip \
        -O teamfiltration.zip; \
    unzip teamfiltration.zip; \
    rm -f teamfiltration.zip; \
    chmod +x TeamFiltration; \
    \
    rm -rf /var/cache/apk/*

CMD [ "bash" ]