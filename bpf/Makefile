# Makefile for compiling eBPF programs

CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool
LLVM_OBJDUMP ?= llvm-objdump

# Flags for BPF target (self-contained, no kernel headers needed)
CLANG_FLAGS = -O2 -target bpf -g -c \
	-D__KERNEL__ \
	-Wno-unknown-attributes \
	-Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wno-address-of-packed-member

all: filter.o engine.o

filter.o: filter.c
	$(CLANG) $(CLANG_FLAGS) -o $@ $<

engine.o: engine.c
	$(CLANG) $(CLANG_FLAGS) -o $@ $<

clean:
	rm -f *.o

verify: filter.o engine.o
	$(LLVM_OBJDUMP) -S filter.o engine.o

.PHONY: all clean verify
