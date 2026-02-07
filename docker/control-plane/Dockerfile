FROM rust:1.89.0-slim-bookworm AS builder

WORKDIR /workspace

# Keep image reasonably small; no OpenSSL required (rustls).
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY . .

RUN cargo build -p briefcase-control-plane --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/target/release/briefcase-control-plane /usr/local/bin/briefcase-control-plane

# Run as non-root.
USER 65532:65532

EXPOSE 9797

ENTRYPOINT ["/usr/local/bin/briefcase-control-plane"]

