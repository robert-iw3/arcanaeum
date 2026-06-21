# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.24" \
    image_hash="79ff19e9084a00eece421b2523fb93e22d730e2c0e525905de047e848e56d95f"

FROM ${repo}/${base_image}@sha256:${image_hash} AS go-builder

RUN \
    apk add --no-cache -U \
        build-base \
        ca-certificates \
        go \
        mingw-w64-gcc \
        mingw-w64-binutils

COPY . .

RUN \
    go build -o dllshimmer; \
    rm -rf /var/cache/apk/*

FROM ${repo}/${base_image}@sha256:${image_hash}

RUN apk add --no-cache -U \
    bash \
    mingw-w64-gcc \
    mingw-w64-binutils

COPY --from=go-builder /dllshimmer /usr/local/bin/

CMD [ "bash" ]
# dllshimmer -h