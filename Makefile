ARCH ?= x86_64
OBJDIR ?= build/$(ARCH)
CC = clang-6.0
LLC = llc-6.0

SOURCES ?= -c src/programs.c

ifeq ($(ARCH),aarch64)
CFLAGS += \
	-DCONFIG_ARM64_PAGE_SHIFT=12 \
	-DCONFIG_ARM64_VA_BITS=48 
KERNEL_ARCH_NAME = arm64
KERNEL_HEADER_VERSION ?= 4.10.0-14-generic
TARGET = --target=aarch64-linux-gnu
else ifeq ($(ARCH),x86_64)
CFLAGS += -D__ASM_SYSREG_H
KERNEL_ARCH_NAME = x86
KERNEL_HEADER_VERSION ?= 4.4.0-98-generic
else
$(error Unknown architecture $(ARCH))
endif

KERNEL_HEADERS_ROOT ?= /usr/src/linux-headers-$(KERNEL_HEADER_VERSION)

CFLAGS += -D__KERNEL__ \
	-Wunused \
	-Wall \
	-Werror \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-unused-value \
	-Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wno-address-of-packed-member \
	-Wno-sometimes-uninitialized \
	-O2

INCLUDES ?= -I src/ \
	-I $(KERNEL_HEADERS_ROOT)/arch/$(KERNEL_ARCH_NAME)/include \
	-I $(KERNEL_HEADERS_ROOT)/arch/$(KERNEL_ARCH_NAME)/include/uapi \
	-I $(KERNEL_HEADERS_ROOT)/arch/$(KERNEL_ARCH_NAME)/include/generated \
	-I $(KERNEL_HEADERS_ROOT)/arch/$(KERNEL_ARCH_NAME)/include/generated/uapi \
	-I $(KERNEL_HEADERS_ROOT)/include \
	-I $(KERNEL_HEADERS_ROOT)/include/uapi \
	-I $(KERNEL_HEADERS_ROOT)/include/generated \
	-I $(KERNEL_HEADERS_ROOT)/include/generated/uapi \
	-I $(KERNEL_HEADERS_ROOT)/tools/testing/selftests/bpf

clean:
	rm -rf $(OBJDIR)

realclean: clean
	@:

$(OBJDIR):
	mkdir -p "$@"

gen_headers:
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
		make binutils curl coreutils

ebpf: gen_headers
	$(CC) $(TARGET) $(CFLAGS) -emit-llvm $(SOURCES) $(INCLUDES) -o $(OBJDIR)/redcanary-ebpf-programs.llvm
	$(LLC) $(OBJDIR)/redcanary-ebpf-programs.llvm -march=bpf -filetype=obj -o $(OBJDIR)/redcanary-ebpf-programs

all: $(OBJDIR) depends ebpf
	@:

.PHONY: all realclean clean ebpf depends gen_headers
