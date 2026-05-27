# syntax=docker/dockerfile:1

ARG repo="docker.io" \
    base_image="alpine:3.23" \
    image_hash="4d889c14e7d5a73929ab00be2ef8ff22437e7cbc545931e52554a7b00e123d8b"

FROM ${repo}/${base_image}@sha256:${image_hash} AS build

RUN apk add --no-cache ca-certificates git openssl

ENV PATH /usr/local/go/bin:$PATH
ENV GOLANG_VERSION 1.23.2

# Install Go from source for supported architectures
RUN set -eux; \
    apk add --no-cache --virtual .fetch-deps gnupg; \
    arch="$(apk --print-arch)"; \
    case "$arch" in \
        'x86_64') export GOARCH='amd64' GOOS='linux'; ;; \
        'armhf') export GOARCH='arm' GOARM='6' GOOS='linux'; ;; \
        'armv7') export GOARCH='arm' GOARM='7' GOOS='linux'; ;; \
        'aarch64') export GOARCH='arm64' GOOS='linux'; ;; \
        'x86') export GO386='softfloat' GOARCH='386' GOOS='linux'; ;; \
        'ppc64le') export GOARCH='ppc64le' GOOS='linux'; ;; \
        'riscv64') export GOARCH='riscv64' GOOS='linux'; ;; \
        's390x') export GOARCH='s390x' GOOS='linux'; ;; \
        *) echo >&2 "error: unsupported architecture '$arch'"; exit 1 ;; \
    esac; \
    url='https://dl.google.com/go/go1.23.2.src.tar.gz'; \
    sha256='b1e1e4e3601f6ce6f8a4a0f374f79a50ccee1d9581f73f6a9b82707e05a2cb39'; \
    wget -O go.tgz.asc "$url.asc"; \
    wget -O go.tgz "$url"; \
    echo "$sha256 *go.tgz" | sha256sum -c -; \
    GNUPGHOME="$(mktemp -d)"; export GNUPGHOME; \
    gpg --batch --keyserver keyserver.ubuntu.com --recv-keys 'EB4C 1BFD 4F04 2F6D DDCC EC91 7721 F63B D38B 4796'; \
    gpg --batch --verify go.tgz.asc go.tgz; \
    gpgconf --kill all; \
    rm -rf "$GNUPGHOME" go.tgz.asc; \
    tar -C /usr/local -xzf go.tgz; \
    rm go.tgz; \
    apk add --no-cache --virtual .build-deps bash gcc musl-dev; \
    export GOCACHE='/tmp/gocache'; \
    ( cd /usr/local/go/src; \
      export GOROOT_BOOTSTRAP="$(go env GOROOT)" GOHOSTOS="$GOOS" GOHOSTARCH="$GOARCH"; \
      if [ "${GOARCH:-}" = '386' ]; then export CGO_CFLAGS='-fno-stack-protector'; fi; \
      ./make.bash; \
    ); \
    apk del --no-network .build-deps .fetch-deps; \
    rm -rf /usr/local/go/pkg/*/cmd /usr/local/go/pkg/bootstrap /usr/local/go/pkg/obj \
           /usr/local/go/pkg/tool/*/api /usr/local/go/pkg/tool/*/go_bootstrap \
           /usr/local/go/src/cmd/dist/dist "$GOCACHE"; \
    go version

ENV GOPATH /go
ENV PATH $GOPATH/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 1777 "$GOPATH"

WORKDIR /app
RUN git clone https://github.com/middleware-labs/mw-agent; \
    cd mw-agent; \
    CGO_ENABLED=0; \
    go get -d -v ./...; \
    go mod tidy

ENV AGENT_VERSION="1.3.0"
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.agentVersion=${AGENT_VERSION}" -o /tmp/mw-agent cmd/host-agent/main.go

FROM busybox:glibc
RUN adduser -D -u 1001 mw-agent && mkdir -p /var/log && chown mw-agent /var/log
WORKDIR /opt/mw-host-agent
USER 1001
COPY --from=build --chown=mw-agent /etc/ssl/certs /etc/ssl/certs
COPY --from=build --chown=mw-agent /tmp/mw-agent /opt/mw-host-agent/mw-agent
COPY --from=build --chown=mw-agent /app/otel-config.yaml /etc/mw-agent/otel-config.yaml
CMD ["/opt/mw-host-agent/mw-agent", "start"]