# Introduction

This work aims to infer the presence of side-channels in the Linux network
stack using VDIFT. Requirements for testing this code are in detailed below in
the Requirements Section. We imeplemented our system using radare2 and r2pipe.


# Requirements

1. QEMU
2. Modified Linux Kernel installed on guest virtual machine
3. Radare2 installed on the host operating system
4. r2pipe installed on the host operating system

## Environment Setup

1. Install a version of Ubuntu linux as the guest
2. Copy the `make_kernel.sh` script provided in this directory to the
virtual machine
3. Get a copy of the Linux kernel to the guest machine
4. You may need to copy the vanilla linux 

