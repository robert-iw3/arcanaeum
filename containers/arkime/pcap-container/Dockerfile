FROM docker.io/alpine:3.23

RUN \
    apk add --no-cache \
        coreutils \
        tshark=4.4.6-r0; \
    mkdir /data

COPY --chmod=755 capture.sh .

ENV FILTER="icmp"
ENV IFACE="any"
ENV DURATION="600"
ENV MAXFILESIZE="1000"
ENV MAXFILENUM="10"
ENV FILENAME="dump"
ENV FORMAT="pcapng"
ENV SNAPLENGTH=""

CMD [ "/bin/sh", "-c", "/capture.sh" ]
