# `lcli` requires the full project to be in scope, so this should be built either:
#  - from the `lighthouse` dir with the command: `docker build -f ./lcli/Dockerflie .`
#  - from the current directory with the command: `docker build -f ./Dockerfile ../`
FROM rust:1.62.1-bullseye AS builder
RUN apt-get update && apt-get -y upgrade && apt-get install -y cmake libclang-dev protobuf-compiler
COPY . lighthouse
ARG PORTABLE
ENV PORTABLE $PORTABLE
RUN cd lighthouse && make install-lcli

FROM ubuntu:22.04
RUN apt-get update && apt-get -y upgrade && apt-get clean && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/lcli /usr/local/bin/lcli
