# syntax=docker/dockerfile:1
# https://github.com/cerberauth/vulnapi
ARG repo="docker.io" \
    base_image="alpine:3.23" \
    image_hash="4d889c14e7d5a73929ab00be2ef8ff22437e7cbc545931e52554a7b00e123d8b"

FROM ${repo}/${base_image}@sha256:${image_hash} AS go-builder

ENV GOPATH=/usr/local/bin/go

RUN \
    apk add --no-cache -t .vulnapi-deps \
        build-base \
        ca-certificates \
        go \
        git; \
    \
    mkdir -p ${GOPATH}/src/github.com/vulnapi; \
    cd ${GOPATH}/src/github.com/vulnapi; \
    git clone https://github.com/cerberauth/vulnapi.git .; \
    export GO111MODULE=on; \
    go install; \
    apk del --no-network --purge .vulnapi-deps; \
    rm -rf /var/cache/apk/*; \
    rm -rf ${GOPATH}/src/

FROM ${repo}/${base_image}@sha256:${image_hash}

RUN \
    addgroup -g 65535 vulnapi; \
    adduser --shell /sbin/nologin --disabled-password -h /home/vulnapi --uid 65535 --ingroup vulnapi vulnapi; \
    apk add --no-cache \
        bash \
        bind-tools \
        ca-certificates \
        curl \
        chromium

COPY --chown=vulnapi:vulnapi --from=go-builder /usr/local/bin/go/bin/vulnapi /usr/local/bin/

WORKDIR /home/vulnapi
USER vulnapi
CMD [ "bash" ]
LABEL \
    org.opencontainers.image.name='vulnapi' \
    org.opencontainers.image.description='Scan your APIs for common security vulnerabilities and weaknesses.' \
    org.opencontainers.image.licenses='MIT' \
    org.opencontainers.image.schema-version='0.8.9'