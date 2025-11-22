# Optimized Dockerfile for lean client only
# Builds lighthouse binary with lean_node subcommand
FROM rust:1.88.0-bullseye AS builder

WORKDIR /app
RUN apt-get update && apt-get -y upgrade && apt-get install -y cmake libclang-dev
COPY . .

# Build lighthouse binary (which includes lean_node subcommand)
# Note: This will build lean_client and its dependencies, but also the lighthouse binary
RUN cargo build --release -p lighthouse --locked

FROM ubuntu:22.04
RUN apt-get update && apt-get -y upgrade && apt-get install -y --no-install-recommends \
  libssl-dev \
  ca-certificates \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/lighthouse /usr/local/bin/lighthouse
ENTRYPOINT ["lighthouse", "lean_node"]
