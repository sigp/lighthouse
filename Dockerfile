FROM rust:latest

COPY . lighthouse
RUN cd lighthouse && cargo install --path lighthouse
