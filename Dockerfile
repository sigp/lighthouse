FROM rust:1.39.0


COPY . lighthouse
RUN cd lighthouse && make
