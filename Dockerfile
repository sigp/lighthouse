FROM rust:1.53.0 AS builder
RUN apt-get update && apt-get -y upgrade && apt-get install -y cmake
COPY . lighthouse
ARG PORTABLE
ENV PORTABLE $PORTABLE
RUN cd lighthouse && make

FROM debian:buster-slim
RUN apt-get update && apt-get -y upgrade && apt-get install -y --no-install-recommends \
  libssl-dev \
  ca-certificates \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/lighthouse /usr/local/bin/lighthouse
