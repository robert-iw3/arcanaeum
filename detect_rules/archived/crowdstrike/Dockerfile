FROM docker.io/python:3.12-slim

WORKDIR /app

COPY pipeline.py /app/

RUN pip install --no-cache-dir crowdstrike-falconpy

CMD ["python", "pipeline.py", "--generate"]
# For upload, run with --upload and env vars