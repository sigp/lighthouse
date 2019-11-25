FROM rust:latest

COPY . lighthouse
RUN cd lighthouse && make
