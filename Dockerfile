FROM ubuntu:22.04

RUN apt-get update
RUN apt-get install -y make llvm clang libclang-dev binutils coreutils

WORKDIR /src
CMD make dev
