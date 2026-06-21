# syntax=docker/dockerfile:1
# sccmsecrets: SCCM policies exploitation tool.
# https://github.com/synacktiv/SCCMSecrets
ARG repo="docker.io" \
    base_image="alpine:3.24" \
    image_hash="79ff19e9084a00eece421b2523fb93e22d730e2c0e525905de047e848e56d95f"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/sccmsecrets/bin:/usr/local/bin:/usr/bin:$PATH \
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
        git \
        libgcc \
        libstdc++ \
        openssl \
        musl-dev \
        linux-headers \
        python3 \
        py3-pip

WORKDIR /sccmsecrets

RUN git clone https://github.com/synacktiv/SCCMSecrets.git .

RUN \
    python3 -m venv sccmsecrets; \
    . sccmsecrets/bin/activate; \
    pip install --upgrade pip; \
    pip install -r requirements.txt; \
    mv sccmsecrets/* . ; \
    apk del --purge --no-network \
        git \
        libgcc \
        libstdc++ \
        musl-dev \
        linux-headers \
        py3-pip; \
    rm -rf /var/cache/apk/* /root/.cache/*

CMD [ "bash" ]
# python3 SCCMSecrets.py -h