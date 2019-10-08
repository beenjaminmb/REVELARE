#!/bin/bash

QEMU=/home/nhtvl/git/panda/build/x86_64-softmmu/panda-system-x86_64
SERVER_IMG=/home/nhtvl/school/qemu/ubuntu-1804-dift.qcow2
sudo $QEMU\
    -hda $SERVER_IMG\
    -m 4096\
    --replay test.ssh -S -s -panda checkpoint
