KERNEL_HEADER_VERSION ?= 4.4.0-98-generic
KERNEL_HEADERS_ROOT ?= /usr/src/linux-headers-$(KERNEL_HEADER_VERSION)

ARCH ?= x86_64
OBJDIR ?= build/$(ARCH)
CC = clang

SOURCES ?= -c src/programs.c

INCLUDES ?= -I src/ \
	-I $(KERNEL_HEADERS_ROOT)/arch/x86/include \
	-I $(KERNEL_HEADERS_ROOT)/include \
	-I $(KERNEL_HEADERS_ROOT)/arch/x86/include/generated \
	-I $(KERNEL_HEADERS_ROOT)/include/generated/uapi \
	-I $(KERNEL_HEADERS_ROOT)/include/uapi


CFLAGS ?= -D__KERNEL__ \
	-D__ASM_SYSREG_H \
	-Wno-unused-value \
	-Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wunused \
	-Wall \
	-Werror \
	-O2

clean:
	rm -rf $(OBJDIR)

realclean: clean
	@:

$(OBJDIR):
	mkdir -p "$@"

ebpf:
	$(CC) $(CFLAGS) -emit-llvm $(SOURCES) $(INCLUDES) -o $(OBJDIR)/redcanary-ebpf-programs.llvm
	llc $(OBJDIR)/redcanary-ebpf-programs.llvm -march=bpf -filetype=obj -o $(OBJDIR)/redcanary-ebpf-programs

all: $(OBJDIR) ebpf
	@:

.PHONY: all realclean clean ebpf