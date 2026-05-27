FROM rust:1.89 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/target/release/pcapan /usr/local/bin/pcapan
ENTRYPOINT ["pcapan"]