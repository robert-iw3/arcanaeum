# syntax=docker/dockerfile:1
ARG repo="docker.io"
ARG base_image="node:18-alpine3.22"
ARG image_hash="3f14a1b07f3a6f8b6b6f5a7a0f6b3b0e2c2b8f8e9e5f6a0b8c2e2d6f3c4e5a6"

FROM ${repo}/${base_image}@sha256:${image_hash} AS builder

WORKDIR /app

RUN \
    apk add --no-cache python3 git; \
    npm install -g npm@10.2.5 yarn; \
    echo "backstage" | npx --yes @backstage/create-app@latest; \
    yarn --cwd /app/backstage add pg

FROM ${repo}/${base_image}

RUN \
    addgroup -S backstage; \
    adduser -S -G backstage backstage; \
    mkdir /app; \
    chown backstage:backstage /app

USER backstage
WORKDIR /app
COPY --from=builder --chown=backstage:backstage /app/backstage /app

EXPOSE 3000 7007
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/ || exit 1
ENTRYPOINT ["/bin/sh", "-c", "yarn dev"]