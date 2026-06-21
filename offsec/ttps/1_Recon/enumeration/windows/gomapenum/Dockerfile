# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.24" \
    image_hash="79ff19e9084a00eece421b2523fb93e22d730e2c0e525905de047e848e56d95f"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV GOPATH=/usr/local/bin/go \
    PATH=/usr/local/bin/go:/usr/local/bin:/usr/bin:$PATH

RUN \
    apk add --no-cache \
        bash \
        ca-certificates \
        go

COPY . .
WORKDIR /src
RUN go run main.go
CMD [ "bash" ]
# go run main.go -h