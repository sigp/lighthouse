FROM rust:1.78.0-bullseye AS builder
RUN apt-get update && apt-get -y upgrade && apt-get install -y cmake libclang-dev
COPY . lighthouse
ARG FEATURES
ARG PROFILE=release
ARG CARGO_USE_GIT_CLI=true
ENV FEATURES $FEATURES
ENV PROFILE $PROFILE
ENV CARGO_NET_GIT_FETCH_WITH_CLI=$CARGO_USE_GIT_CLI
RUN cd lighthouse && make

FROM ubuntu:22.04
RUN apt-get update && apt-get -y upgrade && apt-get install -y --no-install-recommends \
  libssl-dev \
  ca-certificates \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/lighthouse /usr/local/bin/lighthouse
