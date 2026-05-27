FROM golang:1.24.3-alpine3.21
RUN \
    mkdir goConsumer; \
    cd goConsumer; \
    go mod init goConsumer; \
    go get -u github.com/apache/pulsar-client-go

COPY main.go .
CMD ["go", "run", "./main.go"]