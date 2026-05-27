# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="python:3.10-slim" \
    image_hash="sha256:5f5f5c4e69e3c1e78e8a86f2d9c8f8b462ec6a69e64b4f8e8e695087c6b8b8b8"

FROM ${repo}/${base_image}@${image_hash}

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY esql_pipeline.py test_esql_pipeline.py get_ca_cert.sh config.yaml ./
RUN chmod +x get_ca_cert.sh

RUN mkdir -p /app/import/rules-editing /app/import/final

CMD ["python", "esql_pipeline.py", "--verbose", "--compress", "--max-workers=4", \
     "--kibana-url=${KIBANA_URL}", "--api-key=${KIBANA_API_KEY}", \
     "--es-host=${ES_HOST}", "--es-index=${ES_INDEX}", \
     "--stream-to=${STREAM_TO:-kibana}", "--overwrite=${OVERWRITE:-true}", \
     "--ca-cert-path=${CA_CERT_PATH}"]