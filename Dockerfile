FROM rust:1.44.1 AS builder
RUN apt-get update && apt-get install -y cmake
COPY . lighthouse
# TODO: enable PORTABLE in DockerHub environment instead
ENV PORTABLE true
RUN cd lighthouse && make
RUN cd lighthouse && make install-lcli

FROM debian:buster-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
  libssl-dev \
  ca-certificates \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/lighthouse /usr/local/bin/lighthouse
COPY --from=builder /usr/local/cargo/bin/lcli /usr/local/bin/lcli
