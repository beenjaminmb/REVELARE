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

# Sample Use

./universal_dift.py "./simpreadwrite32" dift_functions > out

Assuming simpreadwrite32 was compiled from the test_files directory and moved into
your working directory along wiht the file HI from the test_files directory.

# How the code works

DIFT_r2 uses the radare2 hexadecimal editor, disassembler and debugger to
translate any [supported](https://github.com/radare/radare2#architectures)
architecture to radare2's intermediate language ESIL (for documentation of ESIL
see the radare2
[book](https://radare.gitbooks.io/radare2book/disassembling/esil.html) ). The
code then separates all ESIL instructions into the type of dependency the
instruction is (load address, store address, computation or copy). The control
dependency has yet to be implemented.

The user can then implement their own DIFT system in a file that contains
a python class called DIFT. DIFT must implement the following functions:

* DIFT_copy_dependency

* DIFT_computation_dependency

* DIFT_load_address_dependency

* DIFT_store_address_dependency

* DIFT_taint_source

For an exmaple see dift_functions.py which implements
[VDIFT](https://www.cs.unm.edu/~amajest/VDIFT.pdf). 
