SHELL=/bin/bash -o pipefail

ARCH ?= x86_64
OBJDIR ?= build/$(ARCH)
SRC = src
SRCS = $(wildcard $(SRC)/*.c)
OBJS = $(patsubst $(SRC)/%.c,$(SRC)/%.o,$(SRCS))
OBJS_WRAPPED = $(OBJS)
CC = clang-6.0
LLC = llc-6.0
OPT = opt-6.0
LLVM_DIS = llvm-dis-6.0
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

ifeq ($(ARCH),aarch64)
CFLAGS += \
	-DCONFIG_ARM64_PAGE_SHIFT=12 \
	-DCONFIG_ARM64_VA_BITS=48
KERNEL_ARCH_NAME = arm64
KERNEL_HEADER_VERSION ?= 4.10.0-14-generic
TARGET = -target aarch64
else ifeq ($(ARCH),x86_64)
CFLAGS += -D__ASM_SYSREG_H
KERNEL_ARCH_NAME = x86
KERNEL_HEADER_VERSION ?= 4.4.0-98-generic
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
	mkdir -p "$@"

check_headers:
ifeq ($(ARCH),aarch64)
	cd $(KERNEL_HEADERS_ROOT) && \
		make ARCH=arm64 headers_check
else
	@:
endif

depends:
	apt-get update
	apt-get install -y llvm-6.0 clang-6.0 libclang-6.0-dev \
		linux-headers-4.4.0-98-generic linux-headers-4.10.0-14-generic \
		make binutils curl coreutils gcc

# $(OBJDIR)/ebpf-verifier-%: check_headers
# 	sed -r 's/SEC\(\"maps\/\w+\"\)/SEC("maps")/g' $(SOURCES) | \
# 		$(CC) $(TARGET) $(CFLAGS) -emit-llvm $(INCLUDES) -c -x c - -o - | \
# 		$(OPT) -O2 -mtriple=bpf-pc-linux | $(LLVM_DIS) | \
# 		$(LLC) -march=bpf -filetype=obj -o $@

$(OBJS): %.o: %.c
	$(CC) $(TARGET) $(CFLAGS) -emit-llvm -c $< $(INCLUDES) -o - | \
	$(OPT) -O2 -mtriple=bpf-pc-linux | $(LLVM_DIS) | \
	$(LLC) -march=bpf -filetype=obj -o $(OBJDIR)/$(notdir $@)

#	Run the same command but with the CONFIG_SYSCALL_WRAPPER flag enabled
	CFLAGS="-DCONFIG_SYSCALL_WRAPPER" \
	$(CC) $(TARGET) $(CFLAGS) -emit-llvm -c $< $(INCLUDES) -o - | \
	$(OPT) -O2 -mtriple=bpf-pc-linux | $(LLVM_DIS) | \
	$(LLC) -march=bpf -filetype=obj -o $(OBJDIR)/wrapped-$(notdir $@)

all: depends check_headers $(OBJDIR) $(OBJS)
	@:

.PHONY: all realclean clean ebpf ebpf_verifier depends check_headers