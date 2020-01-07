FROM rust:1.39.0 AS builder
COPY . lighthouse
RUN cd lighthouse && make && cargo clean

FROM debian:buster-slim
RUN apt-get update && apt-get install -y libssl-dev
COPY --from=builder /usr/local/cargo/bin/lighthouse /usr/local/bin/lighthouse
