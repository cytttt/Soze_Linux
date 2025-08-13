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
ARCH ?= arm64
RECV_IF ?= $(RX_IF)
SEND_IF ?= $(TX_IF)

EBPF_OBJ := ebpf/atu_tcp_option_skeleton.o
EBPF_SRC := ebpf/atu_tcp_option_skeleton.c

DAEMON_SRC := daemon/ccll_atu_daemon.c
DAEMON_BIN := ccll_atu_daemon

CLANG ?= clang
BPFTOOL ?= bpftool

.PHONY: all kmod insmod rmmod ebpf daemon attach attach-recv attach-send pin pin-recv pin-send detach detach-recv detach-send status status-recv status-send clean \
        dkms-add dkms-build dkms-install dkms-remove dkms-reinstall install uninstall

all: kmod ebpf daemon

kmod:
	$(MAKE) -C $(KDIR) M=$$PWD modules

insmod: kmod
	sudo insmod ./ccll.ko || true

rmmod:
	sudo rmmod ccll || true

ebpf:
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(shell echo $(ARCH) | tr a-z A-Z) \
		-I/usr/src/linux-headers-$(shell uname -r)/arch/$(ARCH)/include \
		-I/usr/src/linux-headers-$(shell uname -r)/arch/$(ARCH)/include/generated \
		-I/usr/src/linux-headers-$(shell uname -r)/include \
		-I/usr/src/linux-headers-$(shell uname -r)/include/generated \
		-c $(EBPF_SRC) -o $(EBPF_OBJ)

daemon:
	$(CC) -O2 -g -o $(DAEMON_BIN) $(DAEMON_SRC) -lbpf

attach:
	# Add clsact qdisc on RX_IF and TX_IF
	sudo tc qdisc add dev $(RX_IF) clsact 2>/dev/null || true
	sudo tc qdisc add dev $(TX_IF) clsact 2>/dev/null || true
	# Load TC BPF programs
	sudo tc filter add dev $(RX_IF) ingress bpf da obj $(EBPF_OBJ) sec tc/rx_ingress_cache_atu || true
	sudo tc filter add dev $(RX_IF) egress bpf da obj $(EBPF_OBJ) sec tc/rx_egress_add_ack_opt || true
	sudo tc filter add dev $(TX_IF) ingress bpf da obj $(EBPF_OBJ) sec tc/tx_ingress_parse_ack_opt || true

# Attach only on receiver side (ingress cache, egress add-ack-opt)
attach-recv: ebpf
	sudo tc qdisc add dev $(RECV_IF) clsact 2>/dev/null || true
	sudo tc filter add dev $(RECV_IF) ingress bpf da obj $(EBPF_OBJ) sec tc/rx_ingress_cache_atu || true
	sudo tc filter add dev $(RECV_IF) egress  bpf da obj $(EBPF_OBJ) sec tc/rx_egress_add_ack_opt || true

# Attach only on sender side (ingress parse-ack-opt)
attach-send: ebpf
	sudo tc qdisc add dev $(SEND_IF) clsact 2>/dev/null || true
	sudo tc filter add dev $(SEND_IF) ingress bpf da obj $(EBPF_OBJ) sec tc/tx_ingress_parse_ack_opt || true

pin:
	# Load eBPF object and pin maps
	sudo $(BPFOOL) prog loadall $(EBPF_OBJ) /sys/fs/bpf/$(PKG_NAME) || true
	sudo $(BPFOOL) map pin id $(shell sudo $(BPFOOL) map show | grep ack_atu_by_flow | awk '{print $$1}') /sys/fs/bpf/ack_atu_by_flow || true
	sudo $(BPFOOL) map pin id $(shell sudo $(BPFOOL) map show | grep rx_flow_atu | awk '{print $$1}') /sys/fs/bpf/rx_flow_atu || true
	sudo $(BPFOOL) map pin id $(shell sudo $(BPFOOL) map show | grep sk_atu_store | awk '{print $$1}') /sys/fs/bpf/sk_atu_store || true

pin-recv: pin
pin-send: pin

detach:
	# Delete filters and qdiscs on RX_IF and TX_IF
	sudo tc filter del dev $(RX_IF) ingress || true
	sudo tc filter del dev $(RX_IF) egress || true
	sudo tc filter del dev $(TX_IF) ingress || true
	sudo tc qdisc del dev $(RX_IF) clsact || true
	sudo tc qdisc del dev $(TX_IF) clsact || true

# Detach only on receiver side
detach-recv:
	sudo tc filter del dev $(RECV_IF) ingress || true
	sudo tc filter del dev $(RECV_IF) egress  || true
	sudo tc qdisc del dev $(RECV_IF) clsact   || true

# Detach only on sender side
detach-send:
	sudo tc filter del dev $(SEND_IF) ingress || true
	sudo tc qdisc del dev $(SEND_IF) clsact   || true

status:
	# Show qdisc and filters
	echo "Qdisc and filters on $(RX_IF):"
	sudo tc qdisc show dev $(RX_IF)
	sudo tc filter show dev $(RX_IF)
	echo "Qdisc and filters on $(TX_IF):"
	sudo tc qdisc show dev $(TX_IF)
	sudo tc filter show dev $(TX_IF)
	# Show pinned maps summary
	echo "Pinned eBPF maps:"
	sudo $(BPFOOL) map show pinned /sys/fs/bpf/

# Receiver-only status
status-recv:
	@echo "Qdisc and filters on $(RECV_IF):"
	sudo tc qdisc show dev $(RECV_IF) || true
	sudo tc filter show dev $(RECV_IF) ingress || true
	sudo tc filter show dev $(RECV_IF) egress  || true

# Sender-only status
status-send:
	@echo "Qdisc and filters on $(SEND_IF):"
	sudo tc qdisc show dev $(SEND_IF) || true
	sudo tc filter show dev $(SEND_IF) ingress || true

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
	rm -f $(EBPF_OBJ) $(DAEMON_BIN)

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
