# syntax=docker/dockerfile:1
FROM rockylinux:9

RUN dnf install -y python3-pip policycoreutils setools-console audit2allow \
    policycoreutils-python-utils selinux-policy-devel auditd && \
    pip3 install pyyaml

COPY configure_selinux.py /configure_selinux.py
COPY selinux-config.yaml /etc/selinux_guardian/selinux-config.yaml

RUN chmod 755 /configure_selinux.py

CMD ["python3", "/configure_selinux.py", "--mode=setup"]