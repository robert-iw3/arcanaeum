BPF_OBJ = c2_probe.bpf.o
SKEL = c2_probe.skel.h
VMLINUX = vmlinux.h

# Compilers & Tools
CLANG ?= clang
BPFTOOL ?= bpftool

# Architectures
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

all: $(BPF_OBJ) $(SKEL)

$(VMLINUX):
	@echo "[-] Generating vmlinux.h from kernel BTF..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): c2_probe.bpf.c | $(VMLINUX)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I . -c $< -o $@

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

clean:
	rm -f $(BPF_OBJ) $(SKEL) $(VMLINUX)