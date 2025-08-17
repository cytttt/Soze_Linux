ifneq ($(KERNELRELEASE),)

# Kernel module build flags
ccflags-y := -I$(src)

obj-m := ccll.o

else

PKG_NAME := ccll
dkms_package_version := $(shell awk -F= '$$1 == "PACKAGE_VERSION" { gsub("\"", "", $$2); print $$2 }' dkms.conf)

KDIR ?= /lib/modules/$(shell uname -r)/build

RX_IF ?= eth0
TX_IF ?= eth1
# Auto-detect ARCH for eBPF (uname -m -> bpf target arch)
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
  DEFAULT_EBPF_ARCH := x86
else ifeq ($(UNAME_M),aarch64)
  DEFAULT_EBPF_ARCH := arm64
else
  # Fallback; override with ARCH=... if needed
  DEFAULT_EBPF_ARCH := x86
endif
ARCH ?= $(DEFAULT_EBPF_ARCH)
RECV_IF ?= veth-r
SEND_IF ?= veth-s

# Optional: operate inside network namespaces
RECV_NS ?= recv
SEND_NS ?= send

NS_RECV := $(if $(RECV_NS),ip netns exec $(RECV_NS),)
NS_SEND := $(if $(SEND_NS),ip netns exec $(SEND_NS),)

EBPF_SRC    := ebpf/atu_tcp_option_skeleton.c
EBPF_RX_OBJ := ebpf/atu_rx.o
EBPF_TX_OBJ := ebpf/atu_tx.o

DAEMON_SRC := daemon/ccll_atu_daemon.c
DAEMON_BIN := ccll_atu_daemon

CLANG ?= clang
BPFTOOL ?= bpftool

# Prefer UAPI/tools headers for eBPF builds (avoid /usr/src/linux-headers/*)
MULTIARCH := $(shell dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo "")
BPF_INC_FLAGS := -I/usr/include -I/usr/include/$(MULTIARCH) -I/usr/include/bpf \
                  -nostdinc -isystem $(shell $(CLANG) -print-file-name=include)
# Common eBPF CFLAGS (suppress some noisy warnings on various distros)
BPF_CFLAGS := -O2 -g -target bpf \
              -D__TARGET_ARCH_$(shell echo $(ARCH) | tr a-z A-Z) \
              $(BPF_INC_FLAGS) \
              -Wno-address-of-packed-member -Wno-gnu-variable-sized-type-not-at-end

# Test-mode toggle (0=off, 1=on). When on, RX fills default numer/denom if TLV missing.
ATU_TEST_MODE ?= 1
BPF_CFLAGS += -DATU_TEST_MODE=$(ATU_TEST_MODE)

# Sender-side sk_storage toggle (0=omit, 1=include). Some kernels reject SK_STORAGE at tc.
SEND_USE_SK_STORAGE ?= 0

.PHONY: all kmod insmod rmmod ebpf ebpf-rx ebpf-tx daemon attach attach-recv attach-send pin pin-recv pin-send detach detach-recv detach-send status status-recv status-send clean \
        dkms-add dkms-build dkms-install dkms-remove dkms-reinstall install uninstall

all: kmod ebpf daemon

kmod:
	$(MAKE) -C $(KDIR) M=$$PWD modules

insmod: kmod
	sudo insmod ./ccll.ko || true

rmmod:
	sudo rmmod ccll || true

ebpf: ebpf-rx ebpf-tx

ebpf-rx:
	$(CLANG) $(BPF_CFLAGS) -DBUILD_SEND=0 -DUSE_SK_STORAGE=0 -c $(EBPF_SRC) -o $(EBPF_RX_OBJ)

ebpf-tx:
	$(CLANG) $(BPF_CFLAGS) -DBUILD_SEND=1 -DUSE_SK_STORAGE=$(SEND_USE_SK_STORAGE) -c $(EBPF_SRC) -o $(EBPF_TX_OBJ)

daemon:
	$(CC) -O2 -g -o $(DAEMON_BIN) $(DAEMON_SRC) -lbpf

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
	rm -f $(EBPF_RX_OBJ) $(EBPF_TX_OBJ) $(DAEMON_BIN)

endif
