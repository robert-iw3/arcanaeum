ARG AIRFLOW_VERSION=3.3.0
FROM docker.io/apache/airflow:${AIRFLOW_VERSION}

USER root
# Install security updates and additional dependencies
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    libpq-dev \
    gcc \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

USER airflow
COPY --chown=airflow:airflow ./requirements.txt /opt/airflow/requirements.txt
RUN pip install --no-cache-dir -r /opt/airflow/requirements.txt