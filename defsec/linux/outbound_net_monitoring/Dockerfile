FROM docker.io/python:3.11-slim AS builder

RUN pip install --no-cache-dir --user \
        filelock \
        psutil \
        python-json-logger

FROM docker.io/python:3.11-slim

RUN \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        tcpdump \
        tshark \
        iproute2; \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /root/.local /root/.local
COPY outbound_monitor_v2.py /app/outbound_monitor_v2.py
COPY siem_logger.py /app/siem_logger.py

WORKDIR /app
ENV PATH="/root/.local/bin:$PATH"
ENV OUTBOUND_BASE_DIR=/var/log/outbound_collector
ENV PYTHONUNBUFFERED=1

RUN mkdir -p /var/log/outbound_collector /var/log/siem ; \
    chmod 750 /var/log/outbound_collector /var/log/siem ; \
    chown nobody:nogroup /var/log/outbound_collector /var/log/siem

USER nobody
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD pgrep tcpdump || exit 1

ENTRYPOINT ["/app/outbound_monitor_v2.py"]