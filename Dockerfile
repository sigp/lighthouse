FROM rust:latest

RUN apt-get update && apt-get install -y clang libclang-dev cmake build-essential git unzip autoconf libtool

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


RUN mkdir /cargocache && chmod 777 /cargocache
