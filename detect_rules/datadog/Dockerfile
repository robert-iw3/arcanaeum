# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.23" \
    image_hash="1882fa4569e0c591ea092d3766c4893e19b8901a8e649de7067188aba3cc0679"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/app/bin:/usr/local/bin:/usr/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC \
    DD_API_KEY= \
    DD_APP_KEY= \
    DD_DISABLE_SSL=false \
    DD_SITE=us \
    DD_MAX_RETRIES=3 \
    DD_SCRIPT=convert \
    DD_DRY_RUN=false

RUN apk add --no-cache \
        python3==3.12.3-r0 \
        py3-pip==24.0-r2; \
    pip install --no-cache-dir --upgrade pip==24.2

RUN apk add --no-cache \
        bash==5.2.26-r0 \
        curl==8.10.1-r0 \
        tzdata==2024b-r0 \
        ca-certificates==20240705-r0 \
        musl-dev==1.2.5-r0 \
        linux-headers==6.6-r0

RUN pip install --no-cache-dir \
        requests==2.32.3 \
        urllib3==2.2.3 \
        datadog-api-client==2.25.0 \
        jsonschema==4.23.0; \
    pip cache purge; \
    apk cache clean; \
    rm -rf /var/cache/apk/* /root/.cache/*

RUN addgroup -S appgroup && adduser -S -D -H -h /app -g "" -G appgroup appuser

WORKDIR /app
RUN mkdir -p /app/rules /app/signal_correlation_rules && \
    chown -R appuser:appgroup /app

COPY datadog_rule_converter.py import_rules.py entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

USER appuser

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python3", "/app/datadog_rule_converter.py"]