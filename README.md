# Requirements:

Python 3 or higher.
r2pipe (see https://github.com/radare/radare2-r2pipe/tree/master/python)
May need libc6-dev-i386.

# Installation

There is a script in the directory "install". You can use it to pull r2 from
github and install r2. If you do not use the script, r2 will not work for BT,
SYSCALL, or SYSENTER.

For example if you are in the install directory run:

```
$ ./install --git
$ sudo ./install --install
```

Once everything is installed you should be able to run universal_dift.py on a C
program. If you need a C program look in test_files for simpreadwrite.Make
should make everything in the folder. The file ctest.c is just me playing
around with r2 in C to see if it's worth it.

Currently I have tested vdift on simpreadwrite (running 64 bit, non static). It outputs
array_output and should be a matrix with 1's along the diagonal.