FROM rust:latest

RUN apt-get update && apt-get install -y clang libclang-dev cmake build-essential git unzip autoconf libtool awscli software-properties-common

RUN add-apt-repository -y ppa:git-core/ppa

RUN curl -s https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh | bash

RUN apt-get install -y git-lfs

RUN git clone https://github.com/google/protobuf.git && \
    cd protobuf && \
    ./autogen.sh && \
    ./configure && \
    make && \
    make install && \
    ldconfig && \
    make clean && \
    cd .. && \
    rm -r protobuf


RUN mkdir -p /cache/cargocache && chmod -R ugo+rwX /cache/cargocache

ENV CARGO_HOME /cache/cargocache

RUN rustup component add rustfmt clippy
