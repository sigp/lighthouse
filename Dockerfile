FROM rust:1.56.1-bullseye AS builder
RUN apt-get update && apt-get -y upgrade && apt-get install -y cmake libclang-dev
COPY . lighthouse
ARG PORTABLE
ENV PORTABLE $PORTABLE
RUN cd lighthouse && make

FROM ubuntu:latest
RUN apt-get update && apt-get -y upgrade && apt-get install -y --no-install-recommends \
  libssl-dev \
  ca-certificates \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/lighthouse /usr/local/bin/lighthouse
