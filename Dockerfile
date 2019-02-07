FROM rust:latest

RUN apt-get update && apt-get install -y clang libclang-dev cmake

