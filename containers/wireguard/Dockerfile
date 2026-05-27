# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.23" \
    image_hash="4d889c14e7d5a73929ab00be2ef8ff22437e7cbc545931e52554a7b00e123d8b"

FROM ${repo}/${base_image}@sha256:${image_hash}

RUN \
    apk upgrade --no-cache; \
    apk add --no-cache \
        bash \
        dpkg \
        iptables \
        ip6tables \
        nftables \
        kmod \
        iptables-legacy \
        wireguard-tools; \
    apk add --no-cache rinetd --repository=https://dl-cdn.alpinelinux.org/alpine/edge/testing; \
    cp /etc/rinetd.conf /etc/rinetd.conf.ori; \
    update-alternatives --install /usr/sbin/iptables iptables /usr/sbin/iptables-legacy 10 --slave /usr/sbin/iptables-restore iptables-restore /usr/sbin/iptables-legacy-restore --slave /usr/sbin/iptables-save iptables-save /usr/sbin/iptables-legacy-save; \
    update-alternatives --install /usr/sbin/ip6tables ip6tables /usr/sbin/ip6tables-legacy 10 --slave /usr/sbin/ip6tables-restore ip6tables-restore /usr/sbin/ip6tables-legacy-restore --slave /usr/sbin/ip6tables-save ip6tables-save /usr/sbin/ip6tables-legacy-save


COPY wg-start.sh /usr/sbin

CMD ["/usr/sbin/wg-start.sh"]

EXPOSE 51820/udp