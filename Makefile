SHELL=/bin/bash -o pipefail

ARCH ?= $(shell uname -p)
OBJDIR ?= build/$(ARCH)
SRC = src
SRCS = $(wildcard $(SRC)/*.c)
OBJS = $(patsubst $(SRC)/%.c,$(SRC)/%,$(SRCS))
OBJS_WRAPPED = $(OBJS)
CLANG_VER ?= 8
CC = clang-$(CLANG_VER)
LLC = llc-$(CLANG_VER)
OPT = opt-$(CLANG_VER)
LLVM_DIS = llvm-dis-$(CLANG_VER)
CFLAGS += \
	-D__KERNEL__ \
	-D__BPF_TRACING__ \
	-Wunused \
	-Wall \
	-Werror \
	-Wno-pointer-sign \
	-Wno-address-of-packed-member \
	-Wno-compare-distinct-pointer-types \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-sometimes-uninitialized \
	-Wno-tautological-compare \
	-fno-stack-protector \
	-Xclang -disable-llvm-passes \
	-O2

ifeq ($(shell test $(CLANG_VER) -gt 10; echo $$?),0)
  CFLAGS += \
	-Wno-frame-address
endif

KERNEL_HEADER_VERSION ?= 4.11.0-14-generic

ifeq ($(ARCH),aarch64)
CFLAGS += \
	-DCONFIG_ARM64_PAGE_SHIFT=12 \
	-DCONFIG_ARM64_VA_BITS=48
KERNEL_ARCH_NAME = arm64
TARGET = -target aarch64
else ifeq ($(ARCH),x86_64)
CFLAGS += -D__ASM_SYSREG_H
KERNEL_ARCH_NAME = x86
TARGET = -target x86_64
else
$(error Unknown architecture $(ARCH))
endif

CFLAGS += -D__TARGET_ARCH_$(KERNEL_ARCH_NAME)

KERNEL_HEADERS_ROOT ?= /usr/src/linux-headers-$(KERNEL_HEADER_VERSION)

INCLUDES = -I src/ \
	-I $(KERNEL_HEADERS_ROOT)/arch/$(KERNEL_ARCH_NAME)/include \
	-I $(KERNEL_HEADERS_ROOT)/arch/$(KERNEL_ARCH_NAME)/include/uapi \
	-I $(KERNEL_HEADERS_ROOT)/arch/$(KERNEL_ARCH_NAME)/include/generated \
	-I $(KERNEL_HEADERS_ROOT)/arch/$(KERNEL_ARCH_NAME)/include/generated/uapi \
	-I $(KERNEL_HEADERS_ROOT)/include \
	-I $(KERNEL_HEADERS_ROOT)/include/uapi \
	-I $(KERNEL_HEADERS_ROOT)/include/generated \
	-I $(KERNEL_HEADERS_ROOT)/include/generated/uapi

clean:
	rm -rf $(OBJDIR)

realclean: clean
	@:

$(OBJDIR):
	mkdir -p $@
	mkdir -p $@/wrapped

check_headers:
ifeq ($(ARCH),aarch64)
	cd $(KERNEL_HEADERS_ROOT) && \
		make ARCH=arm64 headers_check
else
	@:
endif

depends:
	apt-get update
	apt-get install -y llvm-$(CLANG_VER) clang-$(CLANG_VER) libclang-$(CLANG_VER)-dev \
		linux-headers-$(KERNEL_HEADER_VERSION) \
		make binutils curl coreutils gcc

no_wrapper:
	$(MAKE) $(OBJS)

wrapper:
	OBJDIR=build/$(ARCH)/wrapped  CFLAGS="-DCONFIG_SYSCALL_WRAPPER" $(MAKE) $(OBJS)


$(OBJS): %: %.c
	$(CC) $(TARGET) $(CFLAGS) -emit-llvm -c $< $(INCLUDES) -o - | \
	$(OPT) -O2 -mtriple=bpf-pc-linux | $(LLVM_DIS) | \
	$(LLC) -march=bpf -filetype=obj -o $(OBJDIR)/$(notdir $@)


all: depends check_headers $(OBJDIR) wrapper no_wrapper
	@:

dev:
	KERNEL_HEADER_VERSION=$(shell uname -r) CLANG_VER=14 $(MAKE) $(OBJDIR) wrapper no_wrapper

.PHONY: all realclean clean ebpf ebpf_verifier depends check_headers
