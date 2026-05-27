# syntax=docker/dockerfile:1
FROM docker.io/ubuntu:noble

ENV PATH=/apidetector/bin:/usr/local/bin:/usr/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

RUN \
    apt-get update; \
    apt-get install -y \
        bash \
        curl \
        tzdata \
        coreutils \
        build-essential \
        python3-dev \
        python3-pip \
        python3-venv

COPY . .

RUN \
    python3 -m venv apidetector; \
    . apidetector/bin/activate; \
    python3 -m pip install --upgrade pip; \
    python3 -m pip install -r requirements.txt; \
    python3 -m playwright install; \
    rm -rf /var/cache/apk/* /root/.cache/*

CMD [ "bash", "-c", "python3 app.py --port 8080 --host 0.0.0.0" ]
# podman build -t apidetector .
# podman run -it --name apidetector -p 8080:8080 apidetector