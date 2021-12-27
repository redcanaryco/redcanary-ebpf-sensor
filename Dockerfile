FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y llvm-8 clang-8 libclang-8-dev \
    linux-headers-4.11.0-14-generic linux-headers-4.10.0-14-generic \
    make binutils curl coreutils

WORKDIR /src
CMD make realclean all