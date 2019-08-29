#! /usr/bin/env python3
def main():
    # TODO
    # conditional jumps, example "jnz ebp"
    # REP parsing
    print("deleted stuff")




# class ParseLib:
#     def __init__(self):
#         """ 
#         """
#         self.parse_lib=None 


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
    # print("Tup: {}, Opp: {}".format(tup, opp))
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
        #need special case for ++=, --=, and !=
        #these are nothing to me but possible control dependencies
        if len(tup) == 2:
            print("Control Dependency")
            ret_str = "Control Dependency"
        else:
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


def apply_dependency(tup, r2, vdift, *largs):
    opp = tup[0]
    ret_val = ""
    space = largs[0] if largs and len(largs) > 0 else ''
    space += ' '
    #first case is copy
    if opp == "=":
        dst = tup[1]
        src = tup[2]
        if type(src) == tuple:
            print(space + 'apply_dependancy.148. before call. type(src)=tuple, src={}'.format(src))
            src = apply_dependency(src, r2, vdift, space)
            print(space + 'apply_dependancy.150. after call. new src={}'.format(src))
        if type(dst) == tuple:
            print(space + 'apply_dependancy.152. before call. before call type(dst)=tuple, dst={}'.format(src))
            dst = apply_dependency(dst, r2, vdift, space)
            print(space + 'apply_dependancy.154. before call. after call new dst={}'.format(src))
        #ret_val = "copy dependency(to={},from={})".format(dst,src)
        r, dst_len = get_reg_name(dst)
        print(space + 'apply_dependancy.157. before copy dependency. opp="=" src={}, dst={}, r={}'.format(src, dst, r))
        ret_val = vdift.DIFT_copy_dependency(dst, src, dst_len, r2, space=space)
        print(space + 'apply_dependancy.159. after copy dependency. opp="=" ret_val={}'.format(ret_val))

    #catch load address dependencies
    if is_lad(opp):
        print(space  + 'apply_dependancy.163.is_lad. opp={}, tup={}'.format(opp, tup))
        src = tup[1]
        if type(src) == tuple:
            src2 = apply_dependency(src, r2, vdift, space)
            #The following is necessary cause r2 seems to mess up
            #what it returns after a while
            for i in range(5):
                t = r2.cmd("ae {}".format(esil_from_tuple(src)))
                if not t.startswith("address"):
                    src = t
                    break
        else:
            src2 = src
            if is_reg(src):
                #The following is necessary cause r2 seems to mess up
                #what it returns after a while
                #my calls after a while
                for i in range(5):
                    t = r2.cmd("dr? {}".format(src))
                    if t.startswith("0x"):
                        src = t
                        break
        print(space + "apply_dependancy.185.is_lad. src={}, src2={}".format(src, src2))
        #ret_val = "load address dependency (address={},dataToCalcAdd={})".format(src,src2)
        ret_val = vdift.DIFT_load_address_dependency(src, src2, opp, r2)

    #case where we have [+,-,*,/,xor,and,or]
    #a naked computation dependency
    if simple_computation(opp):
        lhs = tup[1]
        rhs = tup[2]
        print(space + "apply_dependancy.193.simple_computation. lhs={}, rhs={}".format(lhs, rhs))
        #if the LHS is not in its simplest form
        if type(lhs) == tuple:
            lhs = apply_dependency(lhs, r2, vdift, space)
        #if the RHS is not in its simplest form
        if type(rhs) == tuple:
            rhs = apply_dependency(rhs, r2, vdift, space)
        if is_a_constant(lhs) and not is_a_constant(rhs):
            print(space + 'apply_dependancy.202. lhs is constant and rhs is not a constant')
            return rhs
        if is_a_constant(rhs) and not is_a_constant(lhs):
            print(space, 'apply_dependancy.205. rhs is a constant and lhs is not a constant')
            return lhs
        if is_a_constant(rhs) and is_a_constant(lhs) and (lhs == -1 or lhs =='-1'):
           return str(int(lhs) ^ int(rhs))
        #ret_val = "computation dependency ({},{})".format(lhs,rhs)
        ret_val = vdift.DIFT_computation_dependency(lhs, rhs, r2)
        print(space + 'apply_dependancy.211.simple_computation.opp={}, ret_val={}, lhs={}, rhs={}'.format(opp, ret_val, lhs, rhs))
    #Is a store address dependency
    if is_sad(opp):
        lhs = tup[1]
        rhs = tup[2]
        lhs2 = ""
        print(space + 'apply_dependancy.217.is_sad: lhs={}, rhs={}'.format(lhs, rhs))
        if type(lhs) == tuple:
            lhs2 = apply_dependency(lhs, r2, vdift, space)
            print(space + "apply_dependency.220. type(lhs2)={}, lhs2={}".format(type(lhs2), lhs2))
            lhs = r2.cmd("ae {}".format(esil_from_tuple(lhs)))
            print(space + "apply_dependency.222. type(lhs2)={}, lhs={}".format(type(lhs), lhs))
        else:
            lhs2 = lhs
            print(space + "apply_dependency.225.else lhs={} {}".format(type(lhs), lhs))
            lhs = r2.cmd("dr? {}".format(lhs))
        if lhs.startswith('address'):
            # BEN ADDED THIS CHECK
            # Radare appears to return an address: 0XNNNNNNNNN\nopcode value
            lhs = lhs.split(' ')
            lhs = lhs[1].split('\n')
            lhs = lhs[0]
        print(space + "apply_dependancy.233.else type(lhs)={}, lhs={}".format(type(lhs), lhs))
        #if the RHS is not in its simplest form
        if type(rhs) == tuple:
            rhs = apply_dependency(rhs, r2, vdift, space)
        #ret_val = "copy dependency(to={},from=store address dependency(data={},dataToCalcAdd={})))".format(lhs,rhs,lhs2)
        print(space + "apply_dependency.238 if type(rhs)==typle: rhs={}, lhs2={}, opp={}".format(rhs, lhs2, opp))
        ret_val = vdift.DIFT_store_address_dependency(rhs, lhs2, opp, r2)
        #ret_val.len should work because its a taint mark and has a .len
        print(space + "apply_dependency.241: type(ret_val)={}, ret_val = store_address_dependancy(rhs, lhs2)={}, lhs={}".format(type(ret_val), ret_val, lhs))
        # ret_val.len is not returned properly
        ret_val = vdift.DIFT_copy_dependency(lhs, ret_val, ret_val.len, r2, space=space)

    #Is computation that sets a value/ends in copy dependency
    if is_comp_opp(opp):
        if len(tup) == 2:
            #Skip for now this is just a control dependency if we
            #caure to have EIP/RIP affect everything
            return
        else:
            lhs = tup[1]
            rhs = tup[2]
            if type(lhs) == tuple:
                lhs = apply_dependency(lhs, r2, vdift, space)
            if type(rhs) == tuple:
                rhs = apply_dependency(rhs, r2, vdift, space)
            else:
                if is_a_constant(rhs):
                    rhs = "constant"
            #ret_val = "copy dependency(to={},from=(computation dependency ({},{}))))".format(lhs,lhs,rhs)
            ret_val = vdift.DIFT_computation_dependency(lhs, rhs, r2)
            print(space + 'apply_dependancy.263. lhs={}, ret_val={}'.format(lhs, ret_val))
            ret_val = vdift.DIFT_copy_dependency(lhs, ret_val, ret_val.len, r2, space=space)

    # Will need to step instruction to see how many bytes were
    # actually read and written to and tell the calling function
    # to not "ds" for next instruction
    # need to consider other syscalls that are sources or sinks
    if opp == "SPECIAL" or opp == "SYSCALL" or opp == '$':
        a_reg = get_register_A_name(r2)
        a_val = int(r2.cmd("dr? {}".format(a_reg)), 16)
        print(space + 'apply_dependency.273: a_reg={}, a_val={}'.format(a_reg, a_val))
        if a_reg == "rax":
            #syscall for x86_64 rax = 1 means write
            #rdi = file descriptor to write to
            #rsi = mem location of string
            #rdx = number of bytes to write
            if a_val == 1:#WRITE
                ao = open("array_output", "a")
                # write (fd, buf, count)
                rsi = int(r2.cmd("dr? rsi"), 16) # buf
                rdx = int(r2.cmd("dr? rdx"), 16) # count
                if vdift.debug_help:
                    print(rsi)
                    print(rdx)
                    print(vdift.taint)
                    print(vdift.origtaint)
                vdift.DIFT_print_cossim(rsi, rdx, ao)
                ao.close()

            #syscall for x86_64 rax = 0 means read
            #rdi = file descript
            #rsi = buffer to read into
            #rdx = number of bytes to read
            if a_val == 0:#READ
                # read(fd, buf, count)
                rdx = int(r2.cmd("dr? rdx"), 16) # count
                rsi = int(r2.cmd("dr? rsi"), 16) # buf
                vdift.DIFT_taint_source(rsi, rdx)

        if a_reg == "eax":
            #syscall for x86_32 eax = 4 means write
            #ebx = file descriptor to write to
            #ecx = mem location of string
            #edx = number of bytes to write
            if a_val == 4:#WRITE
                ao = open("array_output", "a")
                edx = int(r2.cmd("dr? edx"), 16)# Tony had the string as edx and
                ecx = int(r2.cmd("dr? ecx"), 16)# switched for this one also.
                vdift.DIFT_print_cossim(ecx, edx, ao)
                ao.close()

            #syscall for x86_32 eax = 3 means read
            #ebx = file descriptor
            #ecx = buffer to read into
            #edx = number of bytes to read
            if a_val == 3:#READ
                edx = int(r2.cmd("dr? edx"), 16)
                ecx = int(r2.cmd("dr? ecx"), 16)
                vdift.DIFT_taint_source(ecx, edx)
        if a_reg == "x8":
            if a_val == 63: # READ
               count = int(r2.cmd("dr? x2"), 16) # count
               buf   = int(r2.cmd("dr? x1"), 16) # buf
               vdift.DIFT_taint_source(buf, count)
               # 63 = syscall read according to include/uapi/asm-generic/usid.h:203
            if a_val == 64: # WRITE
               print('apply_dependancy.329.a_val==64')
               ao = open("array_output", "a")
               count = int(r2.cmd("dr? x2"), 16) # count
               buf =   int(r2.cmd("dr? x1"), 16)
               vdift.DIFT_print_cossim(buf, count, ao)
               ao.close()
               # 64 = syscall write " " 
            print(space + "apply_dependency.335. opp={}, tup={}".format(opp, tup))
    # if opp=='DUP':
    #     src = tup[1]
    #     ret_val=apply_dependency(src, r2, vdift)
    print(space + "apply_dependancy.339: opp={}, ret_val={}, tup={}".format(opp, ret_val, tup))
    return ret_val

#get eax rax; arch dependant
def get_register_A_name(r2):
    iA = r2.cmd("iA")
    if "x86_32" in iA:
        return "eax"
    if "x86_64" in iA:
        return "rax"
    print("get_register_A_name.317. iA={}".format(iA))
    if "arm_64" in iA:
        return "x8"
    else:
        return "x8"

def is_a_constant(s):
    if type(s) == str:
        print('is_a_constant.308: type(s)={}, startswith()={}, s = {}'.format(type(s), s.startswith("0x"), s))
    if s == "constant":
        return True
    if type(s) != str:
        return False
    if s.startswith("0x"):
        return True
    if s.isdigit():
        return True
    if s.startswith("-") and s[1:].isdigit():
        return True
    return False

def is_lad(opp):
    instructions = set(["[]", "[1]", "[2]", "[4]", "[8]", "[16]"])
    if opp in instructions:
        return True
    return False

def is_sad(opp):
    instructions = set(["=[]", "=[1]", "=[2]", "=[4]", "=[8]", "=[16]"])
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
                        ">>", "<<", "<<<<", "<<<", ">>>", ">>>>", "|"])
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

# def parse_esil(arch='arm64', inp, regs):
#     """
#     TODO: Implement generic interface for parsing esil based on architecture?
#     """
#     if 'x86' in  arch:
#         return x86_parse_esil()
#             print("opcode:{}".format(d.get('opcode')))


# def _parse_x86_esil():
#     """
#     """


def parse_esil(inp, regs):
    s = inp.split(",")
    r=None
    ret_list = []
    argstack = []
    pq = False
    pq_list = ""
    print('parse_esil.401. s={}, regs={}'.format(s, regs))  
    for i in s:
        if type(i) == str and i =='':
            continue
        if i == '$':
            # BEN ADDED THIS BECUASE $ is syscall in esil and ARM compiles to that.
            print('parse_esil.419: i={}, argstack={}, ret_list={}, s={}'.format(i, argstack, ret_list, s))
            r = ("SPECIAL", argstack.pop())
            ret_list.append(r)

        """ This is what I'm working on to parse control dependencies.
            The issue I have is extra esli commansd that are not implemented
            I also need a way to signal to the parser with the returned value that
            we have a control dependency. This could be as simple as
            (CTRL,(conditional statemnt as ESIL),(ESIL COMMDNSD if condition is true)) 
        """
        if i == '?{':
            pq = True
            continue
        if i == "}":
            pq = False
            a,b = parse_esil(pq_list,"1")
            argstack.append(a[0])
            continue
        if pq:
            pq_list += ","+i
            continue

        elif is_instruction(i):
            #pop args off stack
            if arg_number(i) == 0:
                dup = argstack[-1]
                r = dup
            elif arg_number(i) == 1:
                #pop off 1 arg
                r = (i, argstack.pop())
            else:
                # Is the & operation a 2 or 1 instruction operation?
                #pop off 2 args
                print("parse_esil.429.i={}, arg_number(i)={}, len(argstack)={}, argstack={}".format(i, arg_number(i), len(argstack),  argstack))
                r = (i, argstack.pop(), argstack.pop())
            #if it is an opperation that sets a value or SYSCALL
            if is_computation_dep(i, argstack) or is_store_address_dep(i) or is_copy_dep(i) or i == "SPECIAL": 
                ret_list.append(r)
                print('parse_esil.434: i={}, r={}, argstack={}, ret_list={}'.format(i, r, argstack, ret_list))
            #if it is an opperation that puts its value on the stack
            else:
                argstack.append(r)
                print('parse_esil.438.instruction not comp-storaddr-copy:i={}, r={},  argstack={}, ret_list={}'.format(i, r, argstack, ret_list))
        else:#is arg
            argstack.append(i)
            print('parse_esil.441.not instruction: i={}, r={}, argstack={}, ret_list={}'.format(i, r, argstack, ret_list))
    return ret_list, argstack

def is_instruction(i):
    instructions = ["=", "-","==", "<=", "<", ">=", ">", "<<", ">>", "<<<", "<<<<",
                    ">>>", ">>>>","&", "|", "^", "+", "-", "*", "/", "%", "!", "++", "--",
                    "+=", "-=", "/=", "%=", "*=", "<<=", ">>=", "&=", "|=", "^=",
                    "++=", "--=", "!=", "=[]", "=[*]", "=[1]", "=[2]", "=[4]", "=[8]", "=[16]",
                    "[]", "[1]", "[2]","[4]", "[8]", "[16]", "SPECIAL", "DUP"]
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
    instructions = set(["=[]", "=[1]", "=[2]", "=[4]", "=[8]", "=[16]"])
    if i in instructions:
        return True
    return False

def is_load_address_dep(i):
    instructions = set(["[]", "[1]", "[2]", "[4]", "[8]", "[16]"])
    if i in instructions:
        return True
    return False

def is_computation_dep(i, argstack=None):
    instructions = set(["<=", ">=","+=", "-=", "/=", "%=","<<=", ">>=", "&=",
        "|=", "^=", "++=","--=", "!="])
    # BEN: Added the check for all immediate operands below because TBZ/TBNZ instructions generate %d, 1, <<=, RN, &, ... in anal_arm_cs.c
    has_all_imm_operands = True
    if not (argstack == [] or argstack == None):
        has_all_imm_operands = all(list([not is_reg(i) for i in argstack if type(i) != tuple]))
    if i in instructions:
        if has_all_imm_operands:
            return False
        return True
    return False

#right now only the x86 instruction CALL makes this happen
#may need to add more registers if other archetectures end up
#pushing onto stack in this way

def is_reg(i):
    # TODO: Add ARM or RISC-V registers here.
    regs = set(["rax", "eax", "ax", "ah", "al",
                "rbx", "ebx", "bx", "bh", "bl",
                "rcx", "ecx", "cx", "ch", "cl",
                "rdx", "edx", "dx", "dh", "dl",
                "r8", "r8b", "r8d", "r8w", "r8l",
                "r9", "r9b", "r9d", "r9w", "r9l",
                "r10", "r10b", "r10d", "r10w", "r10l",
                "r11", "r11b", "r11d", "r11w", "r11l",
                "r12", "r12b", "r12d", "r12w", "r12l",
                "r13", "r13b", "r13d", "r13w", "r13l",
                "r14", "r14b", "r14d", "r14w", "r14l",
                "r15", "r15b", "r15d", "r15w", "r15l",
                "rsp", "esp", "sp", "spl",
                "rbp", "ebp", "bp", "bpl",
                "rsi", "esi", "si", "sil",
                "rdi", "edi", "ri", "ril",
                "rip","eip","ip", "of", "pf",
                "zf", "sf", "cf", "xmm0",
                "xmm1", "xmm2", "xmm3", "xmm4",
                "xmm5", "xmm6", "xmm7", "xmm8",
                "xmm9"])
    arm_regs = set(['x{}'.format(i) for i in range(32)])
    arm_regs |= set(['w{}'.format(i) for i in range(32)])
    arm_regs |= set(['sp', 'lr', 'pc', 'xzr', 'wzr', 'tmp'])
    arm_regs |= set(['b{}'.format(i) for i in range(32)])
    arm_regs |= set(['q{}'.format(i) for i in range(32)])
    regs |= arm_regs
    if i in regs:
        return True
    if i.startswith("$"):
        return True
    return False

def is_eflag(r):
    eflags = set(['zf', 'cf', 'pf', 'sf', 'of'])
    if r in eflags:
        return True
    return False

def arg_number(arg):
    zero_args =set(["DUP"])
    one_args = set(["[]", "[1]", "[2]", "[4]", "[8]", "[16]", "push", "!", "++=",
        "--=","SPECIAL"])
    print("arg_number.565. arg={}".format(arg))
    if arg in zero_args:
        return 0
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
    print('esil_from_tuple.604. tup={}, rets={}'.format(tup, rets))
    return rets


def get_reg_name(reg):
    # reg_name = get_x86_64_reg_name(reg)
    # if reg_name == None:
    reg_name = get_arm64_reg_name(reg)
    print('get_reg_name.615.reg={}, reg_name={}'.format(reg, reg_name))
    return reg_name

def get_arm64_reg_name(reg):
    if reg.startswith("vdtmp"):
        print("get_arm_reg_name.619. if get_reg_name : reg.startswith('vdtmp') {}".format(reg))
        return (reg, 0)
    if reg.endswith("vdtmp"):
        # Haven't hit this case yet....
        print("get_arm_64_reg_name.619 or if get_reg_name : reg.endswith('vdtmp') {}".format(reg))
        return (reg, 3)
    if reg.startswith('x'):
        return (reg, 7)
    if reg.startswith('b'):
        return (reg, 1)
    if reg.startswith("w"):
        return (reg,3)
    return (reg, 7)

def get_x86_64_reg_name(reg):
    #treats everything like its in the 64bit namespace
    isGPR = False
    midletter = ""
    start = ""
    end = ""
    gprs = set(["a","b","c","d"])
    if reg.startswith("vdtmp"):
        print("get_x86_64_reg_name.622. if get_reg_name : reg.startswith('vdtmp') {}".format(reg))
        return (reg, 0)
    if reg.endswith("vdtmp"):
        # Haven't hit this case yet....
        print("get_x86_64_reg_name. or if get_reg_name : reg.endswith('vdtmp') {}".format(reg))
        return (reg, 3)
    if len(reg) == 2:
        midletter = reg[0]
        end = reg[1]
    else:
        if len(reg) == 3:
            midletter = reg[1]
            start = reg[0]
            end = reg[2]
    if midletter in gprs:
        isGPR = True
    else:
        isGPR = False
    #for GPR's
    if isGPR and len(reg) == 3:
        if start == "e":
            #replace the e with an r
            return ("r" + reg[1:], 3)
        if start == "r":
            return (reg, 7)
    else:
        if isGPR and len(reg) == 2:
            if end == "x":
                return ("r" + reg, 1)
            elif end == "l":
                return ("r" + reg[0] + "x", 0)
            elif end == "h":
                return ("r" + reg[0] + "x" , 1)
    #for x86_64 r8,r9,...r15
    if reg[1].isdigit():
        if reg.endswith("d"):
            return (reg[:-1], 3)
        elif reg.endswith("w"):
            return (reg[:-1],1)
        elif reg.endswith("l"):
            return (reg[:-1],0)
        else:
            return (reg,7)
    #Stack, base and instruction pointer
    #R?P, E?P, ?P, ?PL -> ? = (S|B)
    #R?I, E?I, ?I, ?IL -> ? = (S|D)
    pil = set(["p", "i", "l"])
    if end in pil:
        if len(reg) == 3:
            if reg[0] == "r":
                return (reg, 7)
            elif reg[0] == "e":
                return ("r" + reg[1:], 3)
            elif reg.endswith("l"):
                return ("r" + start + midletter, 0)
        elif len(reg) == 2:
            return ("r" + start + reg[-1], 1)
    if reg.endswith("f"):
        return (reg, 3)
    if reg.startswith("xmm"):
        return (reg, 3)
    if reg.startswith("$"):
        return (reg, 3)
    # TODO: Add ARM and RISC-V here.
    return None

if __name__ == "__main__":
    main()
