FROM rust:1.43.1 AS builder
RUN apt-get update && apt-get install -y cmake git
RUN git clone https://github.com/sigp/lighthouse
RUN echo "nameserver 8.8.8.8" > /etc/resolv.conf
RUN cd lighthouse && make
RUN cd lighthouse && cargo install --path lcli --locked

FROM debian:buster-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
  libssl-dev \
  ca-certificates \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/lighthouse /usr/local/bin/lighthouse
COPY --from=builder /usr/local/cargo/bin/lcli /usr/local/bin/lcli
