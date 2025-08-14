#!/bin/bash
ip netns del send 2>/dev/null
ip netns del recv 2>/dev/null
umount /sys/fs/bpf 2>/dev/null || true
rm -rf /sys/fs/bpf/tc
