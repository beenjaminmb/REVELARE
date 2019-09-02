#!/bin/bash
cd linux
# cp /boot/config-`uname -r` .config
# make clean
make -j `getconf _NPROCESSORS_ONLN` deb-pkg LOCALVERSION=-custom
cd ..
sudo dpkg -i linux-*.deb
