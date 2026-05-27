FROM python:3.14-slim

WORKDIR /app

RUN pip install --no-cache-dir --upgrade pip
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY universal_log_parser.py .
COPY config.json .

RUN mkdir -p /app/logs && chmod -R 777 /app/logs
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

VOLUME /var/log/trellix
VOLUME /var/Trellix
VOLUME /var/McAfee
VOLUME /var/log/mcafee

CMD ["python", "universal_log_parser.py"]