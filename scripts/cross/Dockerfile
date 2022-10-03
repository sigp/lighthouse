ARG CROSS_BASE_IMAGE
FROM $CROSS_BASE_IMAGE

RUN apt-get update -y && apt-get upgrade -y

RUN apt-get install -y unzip && \
    PB_REL="https://github.com/protocolbuffers/protobuf/releases" && \
    curl -L $PB_REL/download/v3.15.8/protoc-3.15.8-linux-x86_64.zip -o protoc.zip && \
    unzip protoc.zip -d /usr && \
    chmod +x /usr/bin/protoc

RUN apt-get install -y cmake clang-3.9

ENV PROTOC=/usr/bin/protoc
