FROM docker.io/python:3.13-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM docker.io/python:3.13-slim
WORKDIR /app
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY . /app
RUN pip install .
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD python -c "import static_code_analyzer" || exit 1
ENTRYPOINT ["python", "-m", "static_code_analyzer.scanner"]
CMD ["--help"]
LABEL maintainer="@RW" version="0.7.0" description="Static Code Analyzer"