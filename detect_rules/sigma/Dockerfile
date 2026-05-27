# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.23" \
    image_hash="1882fa4569e0c591ea092d3766c4893e19b8901a8e649de7067188aba3cc0679"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/import/opensearch/bin:/usr/local/bin:/usr/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

# OpenSearch connection details
ENV HOST=localhost
ENV PORT=9200
ENV SCHEME=http
ENV USERNAME=admin
ENV PASSWORD=admin
ENV PROVIDER=opensearch
ENV AWS_REGION=us-east-1
ENV CONFIG_PATH=config.yaml
ENV METRICS_PORT=8000

RUN apk add --no-cache \
        bash \
        curl \
        tzdata \
        ca-certificates \
        python3 \
        py3-pip; \
    python3 -m venv /import/opensearch; \
    /import/opensearch/bin/pip install --no-cache-dir -r requirements.txt; \
    rm -rf /root/.cache/*; \
    apk cache clean

WORKDIR /import

COPY sigma_pipeline.py .
COPY test_sigma_pipeline.py .
COPY requirements.txt .
COPY config.yaml .

# Run tests and then import rules
CMD ["/bin/bash", "-c", \
     "/import/opensearch/bin/python test_sigma_pipeline.py && \
      /import/opensearch/bin/python sigma_pipeline.py \
      --host ${HOST} \
      --port ${PORT} \
      --scheme ${SCHEME} \
      --username ${USERNAME} \
      --password ${PASSWORD} \
      --provider ${PROVIDER} \
      --aws-region ${AWS_REGION} \
      --config ${CONFIG_PATH} \
      --metrics-port ${METRICS_PORT}"]