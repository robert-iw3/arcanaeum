# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.23" \
    image_hash="1882fa4569e0c591ea092d3766c4893e19b8901a8e649de7067188aba3cc0679"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/import/kibana-import/bin:/usr/local/bin:/usr/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

# --- Configuration ---
#ENV KIBANA_URL="https://your_kibana_url:5601"
# Superuser credentials for creating the new user and role
#ENV SUPERUSER_USERNAME="elastic"
#ENV SUPERUSER_PASSWORD=""
# Credentials for the new dedicated user
#ENV IMPORT_USERNAME=""
#ENV IMPORT_PASSWORD=""
#ENV KIBANA_API_KEY="${ENCODED_API_KEY}"

RUN \
    apk add --no-cache \
        bash \
        curl \
        jq \
        tzdata \
        ca-certificates \
        musl-dev \
        linux-headers \
        gcc \
        yaml \
        yaml-dev \
        python3 \
        python3-dev \
        py3-pip

WORKDIR /import

COPY . .

RUN chmod +x create_user_api_key.sh && bash -c "create_user_api_key.sh"

RUN \
    python3 -m venv kibana-import; \
    . kibana-import/bin/activate; \
    pip install --upgrade \
        pip \
        requests \
        urllib3 \
        tqdm \
        charset-normalizer \
        pyyaml \
        elasticsearch; \
    rm -rf /var/cache/apk/* /root/.cache/*; \
    apk cache clean

RUN python3 finalize_ndjson_files_for_import.py --input-dir ./rules-editing --output-dir ./final --output-file combined-searches-for-import.ndjson \
    --compress --pattern "*.json" --max-workers 4 --validate --verbose

#CMD [ "python3", "/import/import_searches.py", "--config config.yaml" ]
CMD [ "python3", "/import/import_searches.py", "--input-dir ./final", "--kibana-url ${KIBANA_URL}", \
      "--api-key ${KIBANA_API_KEY}", "--overwrite", "--validate", "--pattern '*.ndjson*'", "--batch-size 1000", "--verbose" ]
# elasticsearch: python3 import_searches.py --input-dir ./final --stream-to elasticsearch --es-host http://localhost:9200 --es-index my-index --validate --batch-size 1000 --verbose
# incremental import: python3 import_searches.py --input-dir ./final --kibana-url http://localhost:5601 --api-key <your-api-key> --pattern "*.ndjson.gz" --validate
# dry-run: python script.py --config config.yaml --dry-run