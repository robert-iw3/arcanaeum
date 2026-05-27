FROM docker.io/ubuntu:jammy

ENV TINI_VERSION v0.19.0
ENV TINI_URL https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini

RUN \
    apt-get update ; \
    apt-get upgrade -y ; \
    apt-get install -y \
        curl \
        git \
        python3 \
        python3-dev \
        python3-pip \
        python-is-python3 \
        libpcap-dev \
        build-essential \
        procps \
        schedtool \
        cron; \
    pip3 install pcapy-ng; \
    git clone --depth=1 https://github.com/stamparm/maltrail.git /opt/maltrail; \
    python /opt/maltrail/core/update.py; \
    \
    export BINARCH=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/') ; \
    curl -sSLf -o /usr/bin/tini "${TINI_URL}-${BINARCH}" ; \
    chmod +x /usr/bin/tini ; \
    \
    touch /var/log/cron.log; \
    (echo '*/1 * * * * if [ -n "$(ps -ef | grep -v grep | grep -v bash | grep server.py)" ]; then : ; else python /opt/maltrail/server.py -c /opt/maltrail/maltrail.conf; fi >> /var/log/cron.log') | crontab ; \
    (crontab -l ; echo '*/1 * * * * if [ -n "$(ps -ef | grep -v grep | grep -v bash | grep sensor.py)" ]; then : ; else python /opt/maltrail/sensor.py -c /opt/maltrail/maltrail.conf; fi >> /var/log/cron.log') | crontab ; \
    (crontab -l ; echo '0 1 * * * cd /opt/maltrail ; git pull') | crontab ; \
    (crontab -l ; echo '2 1 * * * /usr/bin/pkill -f maltrail') | crontab

EXPOSE 8337/udp
EXPOSE 8338/tcp

ENTRYPOINT [ "/usr/bin/tini", \
                "--", \
                "python /opt/maltrail/server.py", \
                "python /opt/maltrail/sensor.py", \
                "cron", "tail -f /var/log/cron.log" ]