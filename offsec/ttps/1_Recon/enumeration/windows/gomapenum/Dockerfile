# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.23" \
    image_hash="1882fa4569e0c591ea092d3766c4893e19b8901a8e649de7067188aba3cc0679"

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