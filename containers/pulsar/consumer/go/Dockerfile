FROM golang:latest
RUN \
    mkdir goConsumer; \
    cd goConsumer; \
    go mod init goConsumer; \
    go get -u github.com/apache/pulsar-client-go

COPY main.go .
CMD ["go", "run", "./main.go"]