#!/bin/bash

MAC=$1
# Create the tap interface. This should be for the host? 
ip tuntap add tap0 mode tap user `whoami`
ip link set tap0 address $MAC

# Bring up the tap interface
ip link set tap0 up

# Add the tap to the bridge
# ip link set tap1 master br0

# Bring the tap device up
ip addr add 192.168.123.1/24 dev tap0
