#! /usr/bin/env python3
from dift_functions import *

def main():
    d = DIFT()
    #GPR test first
    to = d.get_reg_length("rdx")
    if not ( to == 8):
        print("len rdx failed")
        print(to)
        exit()
    to = d.get_reg_length("edx")
    if not ( to == 4):
        print("len edx failed")
        print(to)
        exit()
    to = d.get_reg_length("dx")
    if not ( to == 2):
        print("len dx failed")
        print(to)
        exit()
    to = d.get_reg_length("dl")
    if not ( to == 1):
        print("len dl failed")
        print(to)
        exit()
    to = d.get_reg_length("dh")
    if not ( to == 1):
        print("len dh failed")
        print(to)
        exit()
    to = d.get_reg_length("r12")
    if not ( to == 8):
        print("len r12 failed")
        print(to)
        exit()
    to = d.get_reg_length("r12d")
    if not ( to == 4):
        print("len r12d failed")
        print(to)
        exit()
    to = d.get_reg_length("r12w")
    if not ( to == 2):
        print("len r12w failed")
        print(to)
        exit()
    to = d.get_reg_length("r12l")
    if not ( to == 1):
        print("len r12l failed")
        print(to)
        exit()
    #rsp rbp
    to = d.get_reg_length("rsp")
    if not ( to == 8):
        print("len rsp failed")
        print(to)
        exit()
    to = d.get_reg_length("esp")
    if not ( to == 4):
        print("len esp failed")
        print(to)
        exit()
    to = d.get_reg_length("sp")
    if not ( to == 2):
        print("len sp failed")
        print(to)
        exit()
    to = d.get_reg_length("spl")
    if not ( to == 1):
        print("len spl failed")
        print(to)
        exit()
    to = d.get_reg_length("rbp")
    if not ( to == 8):
        print("len rbp failed")
        print(to)
        exit()
    to = d.get_reg_length("ebp")
    if not ( to == 4):
        print("len ebp failed")
        print(to)
        exit()
    to = d.get_reg_length("bp")
    if not ( to == 2):
        print("len bp failed")
        print(to)
        exit()
    to = d.get_reg_length("bpl")
    if not ( to == 1):
        print("len bpl failed")
        print(to)
        exit()
    #rsi rdi
    to = d.get_reg_length("rsi")
    if not ( to == 8):
        print("len rsi failed")
        print(to)
        exit()
    to = d.get_reg_length("esi")
    if not ( to == 4):
        print("len esi failed")
        print(to)
        exit()
    to = d.get_reg_length("si")
    if not ( to == 2):
        print("len si failed")
        print(to)
        exit()
    to = d.get_reg_length("sil")
    if not ( to == 1):
        print("len sil failed")
        print(to)
        exit()
    to = d.get_reg_length("rdi")
    if not ( to == 8):
        print("len rdi failed")
        print(to)
        exit()
    to = d.get_reg_length("edi")
    if not ( to == 4):
        print("len edi failed")
        print(to)
        exit()
    to = d.get_reg_length("di")
    if not ( to == 2):
        print("len di failed")
        print(to)
        exit()
    to = d.get_reg_length("dil")
    if not ( to == 1):
        print("len dil failed")
        print(to)
        exit()
    #rip
    to = d.get_reg_length("rip")
    if not ( to == 8):
        print("len rip failed")
        print(to)
        exit()
    to = d.get_reg_length("eip")
    if not ( to == 4):
        print("len eip failed")
        print(to)
        exit()
    to = d.get_reg_length("ip")
    if not ( to == 2):
        print("len ip failed")
        print(to)
        exit()
    #test get_len
    to = d.get_len("ip")
    print('{} = d.get_len("ip")'.format(to))
    if not ( to == 2):
        print("len ip failed")
        print(to)
        exit()
    to = d.get_len("rdi")
    if not ( to == 8):
        print("len rdi failed")
        print(to)
        exit()
    # print(d.get_reg_name("eax"))
    print("BEFORE r.taint = {}".format(d.taint))
    #test DIFT_copy_dependency
    #this is setting a random vector for eax

    # d.taint["rax", 0] = d.get_random_taint_vector()
    # d.taint["rax", 1] = d.get_random_taint_vector()
    # d.taint["rax", 2] = d.get_random_taint_vector()
    # d.taint["rax", 3] = d.get_random_taint_vector()

    d.taint["rax", 4] = d.get_random_taint_vector()
    d.taint["rax", 5] = d.get_random_taint_vector()
    d.taint["rax", 6] = d.get_random_taint_vector()
    d.taint["rax", 7] = d.get_random_taint_vector()

    pstr = {k: len(l) for k, l in d.taint.items() if l != None}
    print("AFTER r.taint = {}".format(pstr))
    # print(d.taint)
    #the 1 is nothing that is used right now but 4 is the
    #number of bytes


    # BUG: Current error is because a check attempts to retrieve ('rax', 0), which doesn't 
    # exist. Only ('rax', 4) - ('rax', 7) do?
    d.DIFT_copy_dependency("0x2020202", "eax", 4, 1, True)
    # stupid floating point numbers are never 1 when they should be    
    cossim = d.cossim(d.taint["rax", 4], d.taint[0x2020202])
    if  not(.9999999999 < cossim <= 1.000000000001):
        print("error1")
        print(float(cossim))

    cossim = d.cossim(d.taint["rax", 5], d.taint[0x2020203])
    if  not(.9999999999 < cossim <= 1.0000000001):
        print("error2")
        print(float(cossim))
    cossim = d.cossim(d.taint["rax", 6], d.taint[0x2020204])
    if  not(.9999999999 < cossim <= 1.0000000001):
        print("error3")
        print(float(cossim))
    cossim = d.cossim(d.taint["rax", 7], d.taint[0x2020205])
    if  not(.9999999999 < cossim <= 1.0000000001):
        print("error4")
        print(float(cossim))
    d.taint["rax", 4] = d.get_random_taint_vector()
    d.taint["rax", 5] = d.get_random_taint_vector()
    d.taint["rax", 6] = d.get_random_taint_vector()
    d.taint["rax", 7] = d.get_random_taint_vector()
    #made new random vectors so we should not have
    #the same cossim
    cossim = d.cossim(d.taint["rax", 4], d.taint[0x2020202])
    if  .9999999999 < cossim <= 1:
        print("error1")
    cossim = d.cossim(d.taint["rax", 5], d.taint[0x2020203])
    if  .9999999999 < cossim <= 1:
        print("error2")
    cossim = d.cossim(d.taint["rax", 6], d.taint[0x2020204])
    if  .9999999999 < cossim <= 1:
        print("error3")
    cossim = d.cossim(d.taint["rax", 7], d.taint[0x2020205])
    if  .9999999999 < cossim <= 1:
        print("error4")
    #test copy from reg, to register
    d.taint["rcx", 4] = d.get_random_taint_vector()
    d.taint["rcx", 5] = d.get_random_taint_vector()
    d.taint["rcx", 6] = d.get_random_taint_vector()
    d.taint["rcx", 7] = d.get_random_taint_vector()
    d.DIFT_copy_dependency("eax", "ecx", -1, 1)
    cossim = d.cossim(d.taint["rax", 4], d.taint["rcx", 4])
    if  not(.9999999999 < cossim <= 1.000000000001):
        print("error1")
        print(float(cossim))
    cossim = d.cossim(d.taint["rax", 5], d.taint["rcx", 5])
    if  not(.9999999999 < cossim <= 1.0000000001):
        print("error2")
        print(float(cossim))
    cossim = d.cossim(d.taint["rax", 6], d.taint["rcx", 6])
    if  not(.9999999999 < cossim <= 1.0000000001):
        print("error3")
        print(float(cossim))
    cossim = d.cossim(d.taint["rax", 7], d.taint["rcx", 7])
    if  not(.9999999999 < cossim <= 1.0000000001):
        print("error4")
        print(float(cossim))
    #d.taint["rcx", 4] = d.get_random_taint_vector()
    #d.taint["rcx", 5] = d.get_random_taint_vector()
    #d.taint["rcx", 6] = d.get_random_taint_vector()
    #d.taint["rcx", 7] = d.get_random_taint_vector()
    reg = True
    t = taint_mark("ecx", reg)
    d.taint_register(t)
    cossim = d.cossim(d.taint["rax", 4], d.taint["rcx", 4])
    if  .9999999999 < cossim <= 1.000000000001:
        print("error1")
        print(float(cossim))
    cossim = d.cossim(d.taint["rax", 5], d.taint["rcx", 5])
    if  .9999999999 < cossim <= 1.0000000001:
        print("error2")
        print(float(cossim))
    cossim = d.cossim(d.taint["rax", 6], d.taint["rcx", 6])
    if  .9999999999 < cossim <= 1.0000000001:
        print("error3")
        print(float(cossim))
    cossim = d.cossim(d.taint["rax", 7], d.taint["rcx", 7])
    if  .9999999999 < cossim <= 1.0000000001:
        print("error4")
        print(float(cossim))
    tm = taint_mark("0x2020202", False)
    tm.len = 4
    d.DIFT_copy_dependency("ebx", tm, 4, 1)
    cossim = d.cossim(d.taint["rbx", 4], d.taint[0x2020202])
    if  not(.9999999999 < cossim <= 1.000000000001):
        print("error1")
        print(float(cossim))
    cossim = d.cossim(d.taint["rbx", 5], d.taint[0x2020203])
    if  not(.9999999999 < cossim <= 1.0000000001):
        print("error2")
        print(float(cossim))
    cossim = d.cossim(d.taint["rbx", 6], d.taint[0x2020204])
    if  not(.9999999999 < cossim <= 1.0000000001):
        print("error3")
        print(float(cossim))
    cossim = d.cossim(d.taint["rbx", 7], d.taint[0x2020205])
    if  not(.9999999999 < cossim <= 1.0000000001):
        print("error4")
        print(float(cossim))
    d.DIFT_copy_dependency("ebx", "8", 4, 1)
    for i in range (len(d.taint["rbx", 4])):
        r4 = d.taint["rbx", 4][i]
        r5 = d.taint["rbx", 5][i]
        r6 = d.taint["rbx", 6][i]
        r7 = d.taint["rbx", 7][i]
        if r4 != r5 != r6 != r7 != 0:
            print("zero out vector not working")
    #need to mem loc from taint mark
    tm = taint_mark("eax", True)
    tm.len = 4
    d.DIFT_copy_dependency("0x4020202", tm, 4, 1)
    cossim = d.cossim(d.taint["rax", 4], d.taint[0x4020202])
    if  not(.9999999999 < cossim <= 1.00000001):
        print(cossim)
        print("error1")
    cossim = d.cossim(d.taint["rax", 5], d.taint[0x4020203])
    if  not(.9999999999 < cossim <= 1.00000001):
        print(cossim)
        print("error2")
    cossim = d.cossim(d.taint["rax", 6], d.taint[0x4020204])
    if  not(.9999999999 < cossim <= 1.00000001):
        print(cossim)
        print("error3")
    cossim = d.cossim(d.taint["rax", 7], d.taint[0x4020205])
    if  not(.9999999999 < cossim <= 1.00000001):
        print(cossim)
        print("error4")

    y = d.get_random_taint_vector()
    z = d.get_random_taint_vector()
    w = d.combine_taint(y,z)
    print(d.get_taint_magnitude(y, w))
    print(d.get_taint_magnitude(z, w))

    tm = taint_mark(0x32, False)
    d.taint_mem_range(tm, 4)
    for i in range(0,4):
        if type(d.taint.get(tm.mem + i)) == None:
            print("Didn't taint memory error in taint_mem_range()")

if __name__ == "__main__":
    main()

