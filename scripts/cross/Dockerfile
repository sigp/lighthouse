ARG CROSS_BASE_IMAGE
FROM $CROSS_BASE_IMAGE

RUN apt-get update -y && apt-get upgrade -y

RUN apt-get install -y unzip && \
    PB_REL="https://github.com/protocolbuffers/protobuf/releases" && \
    curl -L $PB_REL/download/v3.15.8/protoc-3.15.8-linux-x86_64.zip -o protoc.zip && \
    unzip protoc.zip -d /usr && \
    chmod +x /usr/bin/protoc

RUN apt-get install -y \
    apt-transport-https \
    ca-certificates \
    gnupg-agent \
    software-properties-common

RUN curl -L https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
    apt-add-repository "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-5.0 main" && \
    apt-get update && \
    apt-get install -y clang-5.0

RUN apt-get install -y cmake

ENV PROTOC=/usr/bin/protoc
