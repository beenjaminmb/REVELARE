#!/bin/bash



# MAC=52:54:00:d1:1A:4C
MAC=52:54:00:06:c9:92

# The above is the same as fe:54:00:06:c9:92 after virt-manager spins up the network


# 52:54:00:1a:f3:f9

sudo ./build/x86_64-softmmu/qemu-system-x86_64\
    -hda /var/lib/libvirt/images/ubuntu16.04.qcow2\
    -m 4096\
    --replay test.ssh -S -s -panda checkpoint
    # -nographic\
# -netdev tap,id=mynet0,ifname=tap0,script=no,downscript=no -device e1000,netdev=mynet0,mac=52:55:00:d1:55:01
# -netdev tap,fd=26,id=hostnet0,vhost=on,vhostfd=28\
# -device virtio-net-pci,netdev=hostnet0,id=net0,mac=52:54:00:06:c9:92,bus=pci.0,addr=0x3\
