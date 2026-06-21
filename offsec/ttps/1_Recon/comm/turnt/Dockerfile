# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.24" \
    image_hash="79ff19e9084a00eece421b2523fb93e22d730e2c0e525905de047e848e56d95f"

FROM ${repo}/${base_image}@sha256:${image_hash} AS go-builder

RUN \
    apk add --no-cache \
        build-base \
        ca-certificates \
        go

COPY . .

RUN \
    # Build the TURN credentials utility
    go build -o turnt-credentials ./cmd/credentials; \
    # Build the controller (SOCKS proxy client/controller)
    go build -o turnt-controller ./cmd/controller; \
    # Build the relay (TURN-facing relay side)
    go build -o turnt-relay ./cmd/relay; \
    # Build the admin console utility
    go build -o turnt-admin ./cmd/admin; \
    rm -rf /var/cache/apk/*

FROM ${repo}/${base_image}@sha256:${image_hash}

RUN apk add --no-cache bash

WORKDIR /bins

COPY --from=go-builder /turnt-credentials .
COPY --from=go-builder /turnt-controller .
COPY --from=go-builder /turnt-relay .
COPY --from=go-builder /turnt-admin .

CMD [ "bash" ]