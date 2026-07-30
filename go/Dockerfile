# Multi-arch (linux/amd64, linux/arm64) PQC mTLS Go endpoints.
# Build context = repo root:  docker buildx build -f go/Dockerfile .
# Static binaries -> distroless. Mount certs at runtime: -v $PWD/certs:/certs
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go/ ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/pqc-server ./server && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/pqc-client ./client

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/pqc-server /out/pqc-client /usr/local/bin/
ENV CERT_DIR=/certs ADDR=:8443
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/pqc-server"]
