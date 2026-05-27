FROM docker.io/python:3.13.2-alpine3.21
WORKDIR /app
COPY ../.env .
RUN \
    python3 -m venv bootstrap; \
    . bootstrap/bin/activate; \
    python3 -m pip install --upgrade pip
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
CMD [ "python3", "main.py" ]