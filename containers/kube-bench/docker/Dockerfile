# syntax=docker/dockerfile:1
# kube-bench: Checks whether Kubernetes is deployed according to security best practices as defined in the CIS Kubernetes Benchmark.
ARG repo="docker.io" \
    base_image="alpine:3.23" \
    image_hash="4d889c14e7d5a73929ab00be2ef8ff22437e7cbc545931e52554a7b00e123d8b"

FROM ${repo}/${base_image}@sha256:${image_hash} AS base

RUN \
    apk --no-cache upgrade apk-tools; \
    apk --no-cache add \
        procps \
        openssl \
        jq \
        wget; \
    \
    addgroup -g 65535 kbench; \
    adduser -h /home/kbench --shell /sbin/nologin --disabled-password --uid 65535 --ingroup kbench --gecos '' kbench; \
    sed -i -r "/^(kbench|root)/!d" /etc/group /etc/passwd; \
    sed -i -r 's#^(.*):[^:]*$#\1:/sbin/nologin#' /etc/passwd; \
    \
    mkdir -p /host/cfg/; \
    \
    wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub; \
    apk add --no-cache gcompat

FROM base AS build-env

ENV GOPATH=/usr/local/bin/go \
    KBENCH_VER=0.14.0

RUN \
    apk add --no-cache -t .kbench-deps \
        ca-certificates \
        go \
        git; \
    mkdir -p ${GOPATH}/src/github.com/kube-bench; \
    cd ${GOPATH}/src/github.com/kube-bench; \
    git clone --depth 1 --branch v${KBENCH_VER} https://github.com/aquasecurity/kube-bench; \
    cd kube-bench/; \
    go install; \
    mkdir -p /host/cfg; \
    mv cfg/ /host/cfg; \
    rm -rf ${GOPATH}/src/github.com

FROM base

ENV PATH=$PATH:/usr/local/mount-from-host/bin \
    RUNNING_IN_A_CONTAINER=true

COPY --chmod=755 --from=build-env /usr/local/bin/go/bin/ /usr/local/bin
COPY --from=build-env /host/cfg/ /host/cfg/

WORKDIR /home/kbench/

RUN \
    cp -rf /usr/local/bin/kube-bench /host/; \
    chown -R kbench:kbench /host

VOLUME /usr/local/mount-from-host/bin
USER 65535
CMD [ "sh" ]