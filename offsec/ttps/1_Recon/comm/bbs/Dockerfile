# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.23" \
    image_hash="1882fa4569e0c591ea092d3766c4893e19b8901a8e649de7067188aba3cc0679"

FROM ${repo}/${base_image}@sha256:${image_hash} AS go-builder

ENV GOPATH=/usr/local/bin/go

RUN \
    apk add --no-cache -t \
        build-base \
        ca-certificates \
        go; \
    mkdir -p ${GOPATH}/src/; \
    cd ${GOPATH}/src/

COPY . .

RUN \
    export GO111MODULE=on; \
    go install .; \
    # pac support
    # go install -tags pac . ; \
    rm -rf /var/cache/apk/*; \
    rm -rf ${GOPATH}/src/

FROM ${repo}/${base_image}@sha256:${image_hash}

RUN \
    apk add --no-cache \
        bash \
        bind-tools \
        ca-certificates \
        python3 \
        py3-parsing

COPY --from=go-builder /usr/local/bin/go/bin/ /usr/local/bin/
COPY bbs.json .

CMD [ "bash" ]
# bbs -c bbs.json -v -log-file bbs.log