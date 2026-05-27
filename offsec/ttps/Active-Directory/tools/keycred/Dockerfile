# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.23" \
    image_hash="1882fa4569e0c591ea092d3766c4893e19b8901a8e649de7067188aba3cc0679"

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