FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y llvm clang linux-headers-4.4.0-98-generic make binutils curl musl musl-tools musl-dev coreutils libclang-3.9-dev
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
RUN . $HOME/.cargo/env && rustup target add x86_64-unknown-linux-musl

ENV RUST_BACKTRACE=full

WORKDIR /src
CMD . $HOME/.cargo/env && make realclean all