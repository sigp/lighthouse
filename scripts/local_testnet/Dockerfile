FROM rust:1.50.0 AS builder
RUN apt-get update && apt-get install -y cmake
# COPY lighthouse lighthouse
RUN git clone https://github.com/sigp/lighthouse
ARG PORTABLE
ENV PORTABLE $PORTABLE
RUN cd lighthouse && make
RUN env
RUN cd lighthouse && make install-lcli

FROM debian:buster-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
  libssl-dev \
  ca-certificates \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/lighthouse /usr/local/bin/lighthouse
COPY --from=builder /usr/local/cargo/bin/lcli /usr/local/bin/lcli
COPY --from=builder /lighthouse /lighthouse

ADD vars.env /lighthouse/scripts/local_testnet/vars.env
WORKDIR /lighthouse/scripts/local_testnet/
