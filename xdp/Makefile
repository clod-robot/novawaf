# NovaWAF XDP 过滤器 Makefile
# 依赖: clang, llvm, libbpf-dev, linux-headers
CLANG ?= clang
CFLAGS := -O2 -target bpf -Wall -Wno-unused-value -Wno-pointer-sign

all: novawaf_kern.o

novawaf_kern.o: novawaf_kern.c
	$(CLANG) $(CFLAGS) -c $< -o $@

# 加载到网卡（需 root）
load: novawaf_kern.o
	@echo "用法: make load IFACE=eth0"
	# 手动: ip link set dev $(IFACE) xdp obj novawaf_kern.o sec xdp

# 卸载
unload:
	@echo "用法: make unload IFACE=eth0"
	# 手动: ip link set dev $(IFACE) xdp off

clean:
	rm -f novawaf_kern.o

.PHONY: all load unload clean
