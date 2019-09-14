#!/bin/bash

# MAC=52:54:00:d1:1A:4C

MAC=52:54:00:06:c9:92
# Create the tap interface
ip tuntap add tap0 mode tap
ip link set tap0 address $MAC

# Bring up the tap interface
ip link set tap0 up

# Add the tap to the bridge
ip link set tap0 master virbr0

# Bring the tap device up
# ip addr add 192.168.123.1/24 dev tap0
