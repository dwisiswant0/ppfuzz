FROM rust as builder

LABEL description="Prototype Pollution Fuzzer"
LABEL repository="https://github.com/dwisiswant0/ppfuzz"
LABEL maintainer="dwisiswant0"

WORKDIR app
COPY . .
RUN cargo build --release --bin ppfuzz

FROM rust as runtime
WORKDIR app
COPY --from=builder /app/target/release/ppfuzz /usr/local/bin
ENTRYPOINT ["./usr/local/bin/ppfuzz"]