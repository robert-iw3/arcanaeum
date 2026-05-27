FROM ubuntu:questing-20250806

RUN apt update && apt install -y \
    apparmor apparmor-utils auditd python3-pip \
    && pip3 install pyyaml \
    && mkdir -p /etc/apparmor_guardian /var/lib/apparmor_guardian

COPY configure_apparmor.py /configure_apparmor.py
COPY apparmor-config.yaml /etc/apparmor_guardian/apparmor-config.yaml

RUN chmod 755 /configure_apparmor.py

CMD ["python3", "/configure_apparmor.py", "--mode=setup"]