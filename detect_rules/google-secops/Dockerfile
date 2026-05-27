# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="python:3.11-slim" \
    image_hash="sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

FROM ${repo}/${base_image}@${image_hash}

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "yaral_pipeline.py"]