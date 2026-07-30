# Multi-arch (linux/amd64, linux/arm64) PQC mTLS Rust endpoints.
# Build context = repo root:  docker buildx build -f rust/Dockerfile .
# aws-lc-rs needs cmake + clang in the builder. Cross-arch builds run the
# builder stage under QEMU emulation (slow but correct). Mount certs at run:
#   -v $PWD/certs:/certs
FROM rust:1.95-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends cmake clang && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY rust/ ./
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=build /src/target/release/pqc-server /src/target/release/pqc-client /usr/local/bin/
ENV CERT_DIR=/certs ADDR=0.0.0.0:9443
EXPOSE 9443
ENTRYPOINT ["/usr/local/bin/pqc-server"]
