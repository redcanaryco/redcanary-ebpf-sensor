SHELL=/bin/bash -o pipefail

ARCH ?= $(shell uname -m)
OBJDIR ?= build/$(ARCH)
SRC = src
SRCS = $(wildcard $(SRC)/*.c)
OBJS = $(patsubst $(SRC)/%.c,$(SRC)/%,$(SRCS))

ifdef CLANG_VER
CC = clang-$(CLANG_VER)
LLC = llc-$(CLANG_VER)
OPT = opt-$(CLANG_VER)
LLVM_DIS = llvm-dis-$(CLANG_VER)
LLVM = llvm-$(CLANG_VER)
LIBCLANG_DEV = libclang-$(CLANG_VER)-dev
else
CC = clang
LLC = llc
OPT = opt
LLVM_DIS = llvm-dis
LLVM = llvm
LIBCLANG_DEV = libclang-dev
endif

# If cross-compiling from an M1/M2 Mac then default to aarch64
ifeq ($(ARCH),arm64)
ARCH = aarch64
endif

ifeq ($(ARCH),aarch64)
KERNEL_ARCH_NAME = arm64
else ifeq ($(ARCH),x86_64)
KERNEL_ARCH_NAME = x86
else
$(error Unknown architecture $(ARCH))
endif

CFLAGS += \
        -D__TARGET_ARCH_$(KERNEL_ARCH_NAME) \
	-DBPF_NO_PRESERVE_ACCESS_INDEX \
	-Wall \
	-Werror \
	-fno-stack-protector \
	-Xclang -disable-llvm-passes \
	-O2

TARGET = -target $(ARCH)
INCLUDES = -I $(SRC)

clean:
	rm -rf $(OBJDIR)

realclean: clean
	@:

$(OBJDIR):
	mkdir -p $@
	mkdir -p $@/wrapped

depends:
	apt-get update
	apt-get install -y $(LLVM) $(CC) $(LIBCLANG_DEV) binutils coreutils

no_wrapper:
	$(MAKE) $(OBJS)

wrapper:
	OBJDIR=build/$(ARCH)/wrapped  CFLAGS="-DCONFIG_SYSCALL_WRAPPER" $(MAKE) $(OBJS)


$(OBJS): %: %.c
	$(CC) $(TARGET) $(CFLAGS) -emit-llvm -c $< $(INCLUDES) -o - | \
	$(OPT) -O2 -mtriple=bpf-pc-linux | $(LLVM_DIS) | \
	$(LLC) -march=bpf -filetype=obj -o $(OBJDIR)/$(notdir $@)


all: depends $(OBJDIR) wrapper no_wrapper
	@:

dev: $(OBJDIR) wrapper no_wrapper
	@:

.PHONY: all realclean clean ebpf ebpf_verifier depends
