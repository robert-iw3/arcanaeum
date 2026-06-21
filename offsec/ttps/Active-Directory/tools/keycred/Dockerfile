# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.24" \
    image_hash="79ff19e9084a00eece421b2523fb93e22d730e2c0e525905de047e848e56d95f"

FROM ${repo}/${base_image}@sha256:${image_hash} AS go-builder

RUN \
    apk add --no-cache -U \
        bash \
        tzdata \
        ca-certificates \
        build-base \
        krb5-dev \
        openldap-dev \
        go

COPY . .

RUN \
    go build ./cmd/keycred; \
    go build ./cmd/pfxtool; \
    mv keycred pfxtool /usr/local/bin/; \
    rm -rf /var/cache/apk/*

CMD [ "bash" ]
# keycred -h
# pfxtool -h