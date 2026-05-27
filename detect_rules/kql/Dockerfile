FROM docker.io/python:3.11-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

FROM docker.io/python:3.11-slim

WORKDIR /app
COPY --from=builder /root/.local /root/.local
COPY sentinel_pipeline.py .
COPY tests/ tests/
COPY queries/ queries/

ENV PATH=/root/.local/bin:$PATH
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

CMD ["python", "sentinel_pipeline.py"]