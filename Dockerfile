FROM rust:1.45.1 AS builder
RUN apt-get update && apt-get install -y cmake
COPY . lighthouse

ARG PORTABLE
ENV PORTABLE $PORTABLE
ARG TARGETPLATFORM
ENV TARGETPLATFORM $TARGETPLATFORM
ENV CROSS_DOCKER_IN_DOCKER=true

RUN cargo install cross
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
