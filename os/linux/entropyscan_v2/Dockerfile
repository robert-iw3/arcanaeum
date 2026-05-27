# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f"

FROM ${repo}/${base_image}@sha256:${image_hash} AS go-builder

RUN \
    apk add --no-cache -t .entropyscan-deps \
        build-base \
        ca-certificates \
        go

COPY . .

RUN \
    go mod download; \
    go build -o entropy_scan -ldflags="-s -w"; \
    apk del --no-network --purge .entropyscan-deps; \
    rm -rf /var/cache/apk/*

FROM ${repo}/${base_image}@sha256:${image_hash}

RUN apk add --no-cache bash busybox

COPY --from=go-builder /entropy_scan /entropy_scan

RUN chmod +x /entropy_scan
WORKDIR /scan
#CMD [ "bash" ]
CMD ["tail", "-f", "/dev/null"]