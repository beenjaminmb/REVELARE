#!/bin/bash

# Remove tap from br0
ip link set tap0 nomaster
ip tuntap del tap0 mode tap
# Bring down the bridge and remove it
ip link set dev br0 down
ip link delete br0 type bridge

ip route del 192.168.123.0/24 scope link dev tap0
