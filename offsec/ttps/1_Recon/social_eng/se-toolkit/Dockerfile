# syntax=docker/dockerfile:1
# The Social-Engineer Toolkit is an open-source penetration testing framework designed for social engineering.
ARG repo="docker.io" \
    base_image="alpine:3.24" \
    image_hash="79ff19e9084a00eece421b2523fb93e22d730e2c0e525905de047e848e56d95f"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/setoolkit/set/bin:/usr/local/bin:/usr/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

RUN \
    apk add --no-cache \
        bash \
        curl \
        tzdata \
        git \
        grep \
        ca-certificates \
        libgcc \
        libstdc++ \
        libxml2 \
        musl-dev \
        linux-headers \
        python3 \
        py3-pip

WORKDIR /setoolkit
RUN git clone git clone https://github.com/trustedsec/social-engineer-toolkit . ; \

RUN \
    python3 -m venv set; \
    . set/bin/activate; \
    pip install --upgrade pip; \
    pip install -r requirements.txt; \
    python3 setup.py; \
    rm -rf /var/cache/apk/* /root/.cache/*

CMD [ "python3" ]
# https://raw.githubusercontent.com/trustedsec/social-engineer-toolkit/master/readme/User_Manual.pdf
