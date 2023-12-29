# Copyright 2021-2022 Intel Corporation
# SPDX-License-Identifier:  Apache-2.0

USER_OBJ = tools/tcp_int.o
USER_TARGETS = tools/tcp_int
SKELETON_HEADERS = bpf/tcp_int.skel.h
BPF_OBJS = $(SKELETON_HEADERS:.skel.h=.bpf.o)

PREFIX ?= /usr/local
INSTALLPATH = $(PREFIX)/lib/bpf/tcp-int
LIBS = -lbpf
BPFTOOL ?= /usr/sbin/bpftool
CC := gcc
VMLINUX ?= /sys/kernel/btf/vmlinux
VMLINUX_H ?= ../include/vmlinux.h

.PHONY: all clean install uninstall

all: $(USER_TARGETS)

$(USER_TARGETS):  %: %.c $(wildcard ../include/*.h) $(SKELETON_HEADERS)
	$(CC) -Wall $(CFLAGS) $(LDFLAGS) -I../include -I. -o $@ $< $(LIBS)

$(SKELETON_HEADERS): %.skel.h: %.bpf.c $(wildcard ../include/*.h) $(VMLINUX_H)
	$(eval $@_BPF_OBJ := $(@:.skel.h=.bpf.o))
	clang $(CFLAGS) -I../include -g -target bpf -Wall -O3 -c $< -o $($@_BPF_OBJ)
	llvm-strip -g $($@_BPF_OBJ)
	$(BPFTOOL) gen skeleton $($@_BPF_OBJ) > $@

# Only building this if VMLINUX_H was not set to a different path by the user
../include/vmlinux.h: $(VMLINUX)
	$(BPFTOOL) btf dump file $< format c > $@

clean:
	rm -f $(BPF_OBJS) $(SKELETON_HEADERS) $(USER_OBJ) $(USER_TARGETS) ../include/vmlinux.h

install: $(USER_TARGETS)
	install -d $(INSTALLPATH)
	install $^ $(INSTALLPATH)

uninstall: $(BPF_OBJS) $(OBJS) $(USER_TARGETS)
	rm -rf $(INSTALLPATH)
