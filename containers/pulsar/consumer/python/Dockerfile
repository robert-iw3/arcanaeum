FROM python:3.14-rc-slim-bookworm
WORKDIR /usr/src/app
RUN pip install --no-cache-dir pulsar-client
COPY ..
CMD [ "python", "./consumer.py" ]