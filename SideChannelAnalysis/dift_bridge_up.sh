#!/bin/bash

# Create a bridge
ip link add br0 type bridge

# Bring up the bridge
ip link set br0 up

