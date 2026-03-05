# Makefile for compiling the XDP eBPF program and its loader

# Compiler for BPF target
CLANG = clang
# Compiler for user-space loader
GCC = gcc
# BPF tool
BPFTOOL = bpftool

# BPF C flags
BPF_CFLAGS = -g -O2 -target bpf -I/usr/include/$(shell uname -m)-linux-gnu
# Loader C flags
LDR_CFLAGS = -g -O2
# Loader libraries
LDR_LIBS = -lbpf -lelf

# Target names
BPF_TARGET = l3_reflector.bpf.o
LDR_TARGET = xdp_loader

.PHONY: all clean

all: $(BPF_TARGET) $(LDR_TARGET)

$(BPF_TARGET): l3_reflector.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(LDR_TARGET): xdp_loader.c
	$(GCC) $(LDR_CFLAGS) -o $@ $< $(LDR_LIBS)

clean:
	rm -f $(BPF_TARGET) $(LDR_TARGET)
