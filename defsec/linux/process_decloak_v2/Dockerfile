# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f"

FROM ${repo}/${base_image}@sha256:${image_hash} AS go-builder

ENV GOOS=linux \
    GOARCH=amd64

COPY . .

RUN \
    apk add --no-cache go; \
    go mod download; \
    go build -o process_decloak -ldflags="-s -w"

FROM ${repo}/${base_image}@sha256:${image_hash}

RUN mkdir -p /var/log && chmod 770 /var/log

COPY --from=go-builder /process_decloak /usr/local/bin/

WORKDIR /host_proc
ENTRYPOINT ["/usr/local/bin/process_decloak"]
CMD ["-json", "-log-stdout"]