FROM docker.io/openjdk:17-jdk-slim

RUN apt-get update; \
    apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        gosu; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -g 1000 burp ; \
    useradd -u 1000 -g burp -m -d /home/burp -s /bin/bash burp

WORKDIR /home/burp

COPY download.sh /usr/local/bin/download.sh
RUN chmod +x /usr/local/bin/download.sh

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ARG PORTSWIGGER_EMAIL_ADDRESS
ARG PORTSWIGGER_PASSWORD
ARG BURP_SUITE_PRO_VERSION
ARG BURP_SUITE_PRO_CHECKSUM
RUN /usr/local/bin/download.sh

RUN chown -R burp:burp /home/burp

EXPOSE 8080

USER burp

# Entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/home/burp/burpsuite_pro.jar"]