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

attach:
	# Add clsact qdisc on RX_IF and TX_IF
	sudo $(NS_RECV) tc qdisc add dev $(RECV_IF) clsact 2>/dev/null || true
	sudo $(NS_SEND) tc qdisc add dev $(SEND_IF) clsact 2>/dev/null || true
	# Load TC BPF programs
	sudo $(NS_RECV) tc filter add dev $(RECV_IF) ingress bpf da obj $(EBPF_RX_OBJ) sec tc/rx_ingress_cache_atu || true
	sudo $(NS_RECV) tc filter add dev $(RECV_IF) egress  bpf da obj $(EBPF_RX_OBJ) sec tc/rx_egress_add_ack_opt  || true
	sudo $(NS_SEND) tc filter add dev $(SEND_IF) ingress bpf da obj $(EBPF_TX_OBJ) sec tc/tx_ingress_parse_ack_opt || true

# Attach only on receiver side (ingress cache, egress add-ack-opt)
attach-recv: ebpf
	sudo $(NS_RECV) tc qdisc add dev $(RECV_IF) clsact 2>/dev/null || true
	sudo $(NS_RECV) tc filter add dev $(RECV_IF) ingress bpf da obj $(EBPF_RX_OBJ) sec tc/rx_ingress_cache_atu || true
	sudo $(NS_RECV) tc filter add dev $(RECV_IF) egress  bpf da obj $(EBPF_RX_OBJ) sec tc/rx_egress_add_ack_opt  || true

# Attach only on sender side (ingress parse-ack-opt)
attach-send: ebpf
	sudo $(NS_SEND) tc qdisc add dev $(SEND_IF) clsact 2>/dev/null || true
	sudo $(NS_SEND) tc filter add dev $(SEND_IF) ingress bpf da obj $(EBPF_TX_OBJ) sec tc/tx_ingress_parse_ack_opt || true

pin:
	# Ensure bpffs exists in the chosen namespace (sender side by default)
	sudo $(NS_SEND) sh -c 'mkdir -p /sys/fs/bpf; mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true'
	# Load eBPF object and pin maps inside the namespace
	sudo $(NS_SEND) $(BPFTOOL) prog loadall $(EBPF_TX_OBJ) /sys/fs/bpf/$(PKG_NAME) || true
	sudo $(NS_SEND) $(BPFTOOL) map pin id $(shell sudo $(NS_SEND) $(BPFTOOL) map show | grep -m1 ack_atu_by_flow | awk '{print $$1}') /sys/fs/bpf/ack_atu_by_flow || true
	# sk_atu_store is optional; this will be a no-op if SEND_USE_SK_STORAGE=0
	sudo $(NS_SEND) $(BPFTOOL) map pin id $(shell sudo $(NS_SEND) $(BPFTOOL) map show | grep -m1 sk_atu_store   | awk '{print $$1}') /sys/fs/bpf/sk_atu_store   || true

pin-recv: pin
pin-send: pin

detach:
	# Delete filters and qdiscs on RX_IF and TX_IF
	sudo $(NS_RECV) tc filter del dev $(RECV_IF) ingress || true
	sudo $(NS_RECV) tc filter del dev $(RECV_IF) egress  || true
	sudo $(NS_SEND) tc filter del dev $(SEND_IF) ingress || true
	sudo $(NS_RECV) tc qdisc  del dev $(RECV_IF) clsact  || true
	sudo $(NS_SEND) tc qdisc  del dev $(SEND_IF) clsact  || true

# Detach only on receiver side
detach-recv:
	sudo $(NS_RECV) tc filter del dev $(RECV_IF) ingress || true
	sudo $(NS_RECV) tc filter del dev $(RECV_IF) egress  || true
	sudo $(NS_RECV) tc qdisc  del dev $(RECV_IF) clsact  || true

# Detach only on sender side
detach-send:
	sudo $(NS_SEND) tc filter del dev $(SEND_IF) ingress || true
	sudo $(NS_SEND) tc qdisc  del dev $(SEND_IF) clsact  || true

status:
	# Show qdisc and filters
	echo "Qdisc and filters on $(RECV_IF):"
	sudo $(NS_RECV) tc qdisc show dev $(RECV_IF) || true
	sudo $(NS_RECV) tc filter show dev $(RECV_IF) || true
	echo "Qdisc and filters on $(SEND_IF):"
	sudo $(NS_SEND) tc qdisc show dev $(SEND_IF) || true
	sudo $(NS_SEND) tc filter show dev $(SEND_IF) || true
	echo "Pinned eBPF maps (in $(if $(SEND_NS),ns $(SEND_NS),host)):" 
	sudo $(NS_SEND) $(BPFTOOL) map show pinned /sys/fs/bpf/ || true

# Receiver-only status
status-recv:
	@echo "Qdisc and filters on $(RECV_IF):"
	sudo $(NS_RECV) tc qdisc show dev $(RECV_IF) || true
	sudo $(NS_RECV) tc filter show dev $(RECV_IF) ingress || true
	sudo $(NS_RECV) tc filter show dev $(RECV_IF) egress  || true

# Sender-only status
status-send:
	@echo "Qdisc and filters on $(SEND_IF):"
	sudo $(NS_SEND) tc qdisc show dev $(SEND_IF) || true
	sudo $(NS_SEND) tc filter show dev $(SEND_IF) ingress || true

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
	rm -f $(EBPF_RX_OBJ) $(EBPF_TX_OBJ) $(DAEMON_BIN)

dkms-add:
	sudo dkms add -m $(PKG_NAME) -v $(dkms_package_version)

dkms-build:
	sudo dkms build -m $(PKG_NAME) -v $(dkms_package_version)

dkms-install:
	sudo dkms install -m $(PKG_NAME) -v $(dkms_package_version)

dkms-remove:
	sudo dkms remove -m $(PKG_NAME) -v $(dkms_package_version) --all

dkms-reinstall: dkms-remove dkms-add dkms-build dkms-install

install: dkms-install

uninstall: dkms-remove

endif
