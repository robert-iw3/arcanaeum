FROM python:3.14.4-slim

WORKDIR /app

RUN pip install --no-cache-dir --upgrade pip
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY upload_ens_rules.py .
COPY config.json .
COPY rules ./rules

RUN mkdir -p /app/logs /app/certs && chmod -R 777 /app/logs /app/certs
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

VOLUME /app/rules
VOLUME /app/certs

CMD ["python", "upload_ens_rules.py"]