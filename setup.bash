#!/bin/bash
ip netns add send
ip netns add recv
ip link add veth-s type veth peer name veth-r
ip link set veth-s netns send
ip link set veth-r netns recv

ip netns exec send ip addr add 10.0.0.2/24 dev veth-s
ip netns exec recv ip addr add 10.0.0.1/24 dev veth-r
ip netns exec send ip link set veth-s up
ip netns exec recv ip link set veth-r up