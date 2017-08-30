#! /usr/bin/env python
def main():
    # TODO
    # conditional jumps, example "jnz ebp"
    # REP parsing
    print("deleted stuff")

def parse_and_print(es):
    print("------inst start-------")
    zs = parse_esil(es, "a")[0]
    for z in zs:
        print("element: {}".format(z))
        pprint(z)
        print()
        print(print_dependency(z))
        print()
    print("======inst end======")

def esil_tuples(es):
    z = parse_esil(es, "a")
    return z

def print_dependency(tup,r2):
    opp = tup[0]
    ret_str = ""

    #first case is copy
    if opp == "=":
        dst = tup[1]
        src= tup[2]
        if type(src) == tuple:
            src = print_dependency(src,r2)
        if type(dst) == tuple:
            dst = print_dependency(dst,r2)
        ret_str = "copy dependency(to={},from={})".format(dst,src)

    #catch load address dependencies
    if is_lad(opp):
        src = tup[1]
        if type(src) == tuple:
            src2 = print_dependency(src,r2)
            src = r2.cmd("ae {}".format(esil_from_tuple(src)))
        else:
            src2 = src
            if is_reg(src):
                src = r2.cmd("dr? {}".format(src))
        ret_str = "load address dependency (address={},dataToCalcAdd={})".format(src,src2)

    #case where we have [+,-,*,/,xor,and,or]
    #a naked computation dependency
    if simple_computation(opp):
        lhs = tup[1]
        rhs = tup[2]
        #if the LHS is not in its simplest form
        if type(lhs) == tuple:
            lhs = print_dependency(lhs,r2)
        #if the RHS is not in its simplest form
        if type(rhs) == tuple:
            rhs = print_dependency(rhs,r2)
        if is_a_constant(lhs) and not is_a_constant(rhs):
            return rhs
        if is_a_constant(rhs) and not is_a_constant(lhs):
            return lhs
        ret_str = "computation dependency ({},{})".format(lhs,rhs)

    #Is a store address dependency
    if is_sad(opp):
        lhs = tup[1]
        rhs = tup[2]
        lhs2 = ""
        if type(lhs) == tuple:
            lhs2 = print_dependency(lhs,r2)
            lhs = r2.cmd("ae {}".format(esil_from_tuple(lhs)))
        else:
            lhs2 = lhs
            lhs = r2.cmd("dr? {}".format(lhs))
        #if the RHS is not in its simplest form
        if type(rhs) == tuple:
            rhs = print_dependency(rhs,r2)
        ret_str = "copy dependency(to={},from=store address dependency(data={},dataToCalcAdd={})))".format(lhs,rhs,lhs2)

    #Is computation that sets a value/ends in copy dependency
    if is_comp_opp(opp):
        lhs = tup[1]
        rhs = tup[2]
        if type(lhs) == tuple:
            lhs = print_dependency(lhs,r2)
        if type(rhs) == tuple:
            rhs = print_dependency(rhs,r2)
        else:
            if is_a_constant(rhs):
                rhs = "constant"
        ret_str = "copy dependency(to={},from=(computation dependency ({},{}))))".format(lhs,lhs,rhs)

    # Will need to step instruction to see how many bytes were
    # actually read and written to and tell the calling function
    # to not "ds" for next instruction
    # need to consider other syscalls that are sources or sinks
    if opp == "SPECIAL" or opp == "SYSCALL":
        a_reg = get_register_A_name(r2)
        a_val = int(r2.cmd("dr? {}".format(a_reg)), 16)

        if a_reg == "rax":
            if a_val == 1:#WRITE
                ret_str = "SINK"

            if a_val == 0:#READ
                ret_str = "SOURCE"

        if a_reg == "eax":
            if a_val == 4:#WRITE
                ret_str = "SINK"

            if a_val == 3:#READ
                ret_str = "SOURCE"
    return ret_str


def apply_dependency(tup, r2, vdift):
    opp = tup[0]
    ret_val = ""

    #first case is copy
    if opp == "=":
        dst = tup[1]
        src= tup[2]
        if type(src) == tuple:
            src = apply_dependency(src, r2, vdift)
        if type(dst) == tuple:
            dst = apply_dependency(dst, r2, vdift)
        #ret_val = "copy dependency(to={},from={})".format(dst,src)
        r, dst_len = vdift.get_reg_name(dst)
        ret_val = vdift.DIFT_copy_dependency(src, dst, dst_len, r2)

    #catch load address dependencies
    if is_lad(opp):
        src = tup[1]
        if type(src) == tuple:
            src2 = apply_dependency(src, r2, vdift)
            src = r2.cmd("ae {}".format(esil_from_tuple(src)))
        else:
            src2 = src
            if is_reg(src):
                src = r2.cmd("dr? {}".format(src))
        #ret_val = "load address dependency (address={},dataToCalcAdd={})".format(src,src2)
        ret_val = vdift.DIFT_load_address_dependency(src, src2, opp, r2)

    #case where we have [+,-,*,/,xor,and,or]
    #a naked computation dependency
    if simple_computation(opp):
        lhs = tup[1]
        rhs = tup[2]
        #if the LHS is not in its simplest form
        if type(lhs) == tuple:
            lhs = apply_dependency(lhs, r2, vdift)
        #if the RHS is not in its simplest form
        if type(rhs) == tuple:
            rhs = apply_dependency(rhs, r2, vdift)
        if is_a_constant(lhs) and not is_a_constant(rhs):
            return rhs
        if is_a_constant(rhs) and not is_a_constant(lhs):
            return lhs
        #ret_val = "computation dependency ({},{})".format(lhs,rhs)
        ret_val = vdift.DIFT_computation_dependency(lhs, rhs, r2)

    #Is a store address dependency
    if is_sad(opp):
        lhs = tup[1]
        rhs = tup[2]
        lhs2 = ""
        if type(lhs) == tuple:
            lhs2 = apply_dependency(lhs, r2, vdift)
            lhs = r2.cmd("ae {}".format(esil_from_tuple(lhs)))
        else:
            lhs2 = lhs
            lhs = r2.cmd("dr? {}".format(lhs))
        #if the RHS is not in its simplest form
        if type(rhs) == tuple:
            rhs = apply_dependency(rhs, r2, vdift)
        #ret_val = "copy dependency(to={},from=store address dependency(data={},dataToCalcAdd={})))".format(lhs,rhs,lhs2)
        ret_val = vdift.DIFT_store_address_dependency(rhs, lhs2, opp, r2)
        #ret_val.len should work because its a taint mark and has a .len
        ret_val = vdift.DIFT_copy_dependency(lhs, ret_val, ret_val.len, r2)

    #Is computation that sets a value/ends in copy dependency
    if is_comp_opp(opp):
        lhs = tup[1]
        rhs = tup[2]
        if type(lhs) == tuple:
            lhs = apply_dependency(lhs, r2, vdift)
        if type(rhs) == tuple:
            rhs = apply_dependency(rhs, r2, vdift)
        else:
            if is_a_constant(rhs):
                rhs = "constant"
        #ret_val = "copy dependency(to={},from=(computation dependency ({},{}))))".format(lhs,lhs,rhs)
        ret_val = vdift.DIFT_computation_dependency(lhs, rhs, r2)
        ret_val = vidft.DIFT_copy_dependency(lhs, ret_val, ret_val.len, r2)

    # Will need to step instruction to see how many bytes were
    # actually read and written to and tell the calling function
    # to not "ds" for next instruction
    # need to consider other syscalls that are sources or sinks
    if opp == "SPECIAL" or opp == "SYSCALL":
        a_reg = get_register_A_name(r2)
        a_val = int(r2.cmd("dr? {}".format(a_reg)), 16)
        if a_reg == "rax":
            #syscall for x86_64 rax = 1 means write
            #rdi = file descriptor to write to
            #rsi = mem location of string
            #rdx = number of bytes to write
            if a_val == 1:#WRITE
                ao = open("array_output", "a")
                rsi = int(r2.cmd("dr? rsi"), 16)
                rdx = int(r2.cmd("dr? rdx"), 16)
                vdift.DIFT_print_cossim(rsi, rdx, ao)
                close(ao)

            #syscall for x86_64 rax = 0 means read
            #rdi = file descript
            #rsi = buffer to read into
            #rdx = number of bytes to read
            if a_val == 0:#READ
                rdx = int(r2.cmd("dr? rdx"), 16)
                rsi = int(r2.cmd("dr? rsi"), 16)
                vdift.DIFT_taint_source(rsi, rdx)

        if a_reg == "eax":
            #syscall for x86_32 eax = 4 means write
            #ebx = file descriptor to write to
            #ecx = mem location of string
            #edx = number of bytes to write
            if a_val == 4:#WRITE
                ao = open("array_output", "a")
                ecx = int(r2.cmd("dr? edx"), 16)
                edx = int(r2.cmd("dr? ecx"), 16)
                vdift.DIFT_print_cossim(ecx, edx, ao)
                close(ao)

            #syscall for x86_32 eax = 3 means read
            #ebx = file descriptor
            #ecx = buffer to read into
            #edx = number of bytes to read
            if a_val == 3:#READ
                edx = int(r2.cmd("dr? edx"), 16)
                ecx = int(r2.cmd("dr? ecx"), 16)
                vdift.DIFT_taint_source(ecx, edx)

    return ret_val

#get eax rax; arch dependant
def get_register_A_name(r2):
    iA = r2.cmd("iA")
    if "x86_32" in iA:
        return "eax"
    if "x86_64" in iA:
        return "rax"

def is_a_constant(s):
    if type(s) != str:
        return False
    if s.startswith("0x"):
        return True
    if s.isdigit():
        return True
    return False

def is_lad(opp):
    instructions = set(["[]", "[1]", "[2]", "[4]", "[8]"])
    if opp in instructions:
        return True
    return False

def is_sad(opp):
    instructions = set(["=[]", "=[1]", "=[2]", "=[4]", "=[8]"])
    if opp in instructions:
        return True
    return False

def is_comp_opp(opp):
    instructions = set(["+=", "-=", "/=", "%=","<<=", ">>=", "&=", "|=", "^=",
        "++=","--=", "*=", "<=", ">="])
    if opp in instructions:
        return True
    return False

# Does not include single argument opperations
def simple_computation(opp):
    instructions = set(["+", "-", "*", "/", "&", "^", "%", ">", "<", "==",
        ">>", "<<", "<<<", ">>>", "|"])
    if opp in instructions:
        return True
    return False

def pprint(tup):
    inst = tup[0]

    #case for opperations that have 2 arguements
    if arg_number(inst) == 2:
        dst_source1 = tup[1]
        source2 = tup[2]

        #make sure the dst is not something we have to calculate
        if type(dst_source1) == tuple:
            print("(", end="")
            pprint(dst_source1)
            print(")",end="")
            print(inst, end=" ")
        else:
            print(dst_source1 +" "+ inst, end=" ")

        #make sure the src is not something we have to calculate
        if type(source2) == tuple:
            print("(", end="")
            pprint(source2)
            print(")",end="")
        else:
            print(source2, end="")

    #case for operations that have 1 argument
    if arg_number(inst) == 1:
        arg = tup[1]
        #the one argument an instruction -> need to evaluate
        if type(arg) == tuple:
            print(inst,end="(")
            pprint(arg)
            print(")",end="")
        else:
            #the arguemnt is not an instruction
            print(inst + " " + arg, end="")


def parse_esil(inp, regs):
    s = inp.split(",")
    ret_list = []
    argstack = []

    for i in s:
        if is_instruction(i):
            #pop args off stack
            if arg_number(i) == 1:
                #pop off 1 arg
                r = (i, argstack.pop())
            else:
                #pop off 2 args
                r = (i, argstack.pop(), argstack.pop())
            #if it is an opperation that sets a value or SYSCALL
            if is_computation_dep(i) or is_store_address_dep(i) or is_copy_dep(i) or i == "SPECIAL":
                ret_list.append(r)
            #if it is an opperation that puts its value on the stack
            else:
                argstack.append(r)
        else:#is arg
            #print("{} is arg".format(i))
            argstack.append(i)
    return ret_list, argstack

def is_instruction(i):
    instructions = ["=", "-","==", "<=", "<", ">=", ">", "<<", ">>", "<<<",
            ">>>","&", "|", "^", "+", "-", "*", "/", "%", "!", "++", "--",
            "+=", "-=", "/=", "%=", "*=", "<<=", ">>=", "&=", "|=", "^=",
            "++=", "--=", "!=", "=[]", "=[*]", "=[1]", "=[2]", "=[4]", "=[8]",
            "[]", "[1]", "[2]","[4]", "[8]", "SPECIAL"]
    if i in instructions:
        return True
    return False

def is_copy_dep(i):
    instructions = set(["="])
    if i in instructions:
        return True
    return False

def is_address_dep(i):
    if is_store_address_dep(i) or is_load_address_dep(i):
        return True;
    return False

def is_store_address_dep(i):
    instructions = set(["=[]", "=[1]", "=[2]", "=[4]", "=[8]"])
    if i in instructions:
        return True
    return False

def is_load_address_dep(i):
    instructions = set(["[]", "[1]", "[2]", "[4]", "[8]"])
    if i in instructions:
        return True
    return False

def is_computation_dep(i):
    instructions = set(["<=", ">=","+=", "-=", "/=", "%=","<<=", ">>=", "&=",
        "|=", "^=", "++=","--=", "!="])
    if i in instructions:
        return True
    return False

#right now only the x86 instruction CALL makes this happen
#may need to add more registers if other archetectures end up
#pushing onto stack in this way
def is_reg(i):
    regs = set(["rax", "eax", "ax", "ah", "al",
                "rbx", "ebx", "bx", "bh", "bl",
                "rcx", "ecx", "cx", "ch", "cl",
                "rdx", "edx", "dx", "dh", "dl",
                "r8", "r8d", "r8w", "r8l",
                "r9", "r9d", "r9w", "r9l",
                "r10", "r10d", "r10w", "r10l",
                "r11", "r11d", "r11w", "r11l",
                "r12", "r12d", "r12w", "r12l",
                "r13", "r13d", "r13w", "r13l",
                "r14", "r14d", "r14w", "r14l",
                "r15", "r15d", "r15w", "r15l",
                "rsp", "esp", "sp", "spl",
                "rbp", "ebp", "bp", "bpl",
                "rsi", "esi", "si", "sil",
                "rdi", "edi", "ri", "ril",
                "rip","eip","ip"])
    if i in regs:
        return True
    return False

def is_eflag(r):
    eflags = set(['zf', 'cf', 'pf', 'sf', 'of'])
    if r in eflags:
        return True
    return False

def arg_number(arg):
    one_args = set(["[]", "[1]", "[2]", "[4]", "[8]", "push", "!", "++=",
        "--=","SPECIAL"])

    if arg in one_args:
        return 1
    return 2

def esil_from_tuple(tup):
    opp = tup[0]
    rets = ""

    if arg_number(opp) != 1:
        arg1 = tup[1]
        arg2 = tup[2]
        if type(arg1) == tuple:
            arg1 = esil_from_tuple(arg1)
        if type(arg2) == tuple:
            arg2 = esil_from_tuple(arg2)
        rets = "{},{},{}".format(arg2,arg1,opp)
    else:
        arg1 = tup[1]
        if type(arg1) == tuple:
            arg1 = esil_from_tuple(arg1)
        rets = "{},{}".format(arg1,opp)

    return rets

if __name__ == "__main__":
    main()
