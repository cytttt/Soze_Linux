#!/bin/bash

insmod ccll.ko

MAJOR=$(dmesg | grep "ccll_ctl char device registered with major" | tail -1 | sed 's/.*major \([0-9]*\).*/\1/')

if [ -z "$MAJOR" ]; then
    echo "Error: Could not find ccll_ctl major device number in dmesg"
    exit 1
fi

mknod /dev/ccll_ctl c $MAJOR 0
chmod 666 /dev/ccll_ctl
sysctl -w net.ipv4.tcp_congestion_control=ccll
