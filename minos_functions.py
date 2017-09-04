#! /usr/bin/env python
import random
import math
import numpy as np
from parse_lib import is_a_constant
from parse_lib import is_reg
from parse_lib import get_register_A_name
from numpy import linalg as LA

#only have one bool here that states wheather or not we are a register
#if its a mem value then we make self.mem
#if its a reg then we make self.reg
class taint_mark():
    #initialize a taint mark, make it a mem value by default
    def __init__(self):
        self.is_reg = False

    #initialize a taint mark, but make it a reg/mem and give value
    def __init__(self, val, reg_t):
        self.is_reg = reg_t
        if reg_t:
            self.reg = val
        else:
            if type(val) == int:
                self.mem = val
            else:
                self.mem = int(val,16)
    #Need MINOS re-write
    def get_taint_rep(self, mode, i):
        if self.is_reg:
            if mode == 32:
                # taint_mark is a register
                r,p = DIFT.get_reg_name(1,self.reg)
                return(r,4)
            if mode == 64:
                #need to return r,0 if rax and r,4 otherwise(eg. eax, ax, al..)
                r,p = DIFT.get_reg_name(1,self.reg)
                if p == 0 and i == 0:
                    #the upper 32 bits
                    return (r,0)
                else:
                    #the lower 32 bits
                    return (r,4)
        else:
            #self.mem should always be 32 bit alligned
            return self.mem
class DIFT():

    def __init__ (self):
        self.taint = {}

    def __init__ (self, r2):
        self.taint = set()
        a = get_register_A_name(r2)
        if a == "eax":
            self.mode = 32
        elif a == "rax":
            self.mode = 64
        else:
            print("DANGER")
            exit()

    def DIFT_copy_dependency(self, toLocation, fromData, to_len, r2):
        """
        For MINOS if copy to memory is not 32 bit alligned it is tainted
        8 and 16 bit pieces of data taint all 32 bits of data they go
        """
        r = 0
        to_taint_mark = None
        from_taint_mark = None

        #fromData can be a reg, a mem location or a taint_mark from a previous
        #calculation
        if is_reg(fromData):
            from_taint_mark = taint_mark(fromData, True)
        elif is_a_constant(fromData):
            self.clear_taint(to_taint_mark)
            return
        elif type(fromData) == taint_mark:
            from_taint_mark = fromData
            r = fromData.len
        else:
            print("NOPE")
            exit()
        if r == 0:
            r = self.get_reg_length(toLocation)

        #make sure taint mark exists first
        #return otherwise
        if self.taint.get(from_taint_mark) == None:
            return

        #toLocation can only be a register or a mem location I think
        if is_reg(toLocation):
            to_taint_mark = taint_mark(toLocation, True)
        elif is_a_constant(toLocation):
            to_taint_mark = taint_mark(int(toLocation, 16), False)
            r = to_len
        else:
            print("Make sure toLocation is not a taint_mark?")
            exit()

        #Do the actual taint copying
        for i in range(r):
            to = to_taint_mark.get_taint_rep(i)
            frm = from_taint_mark.get_taint_rep(i)
            self.taint[to] = self.taint[frm]


    def DIFT_computation_dependency(self, arg1, arg2, r2):
        #always return a taint_mark
        #unless you throw an error and die
        dst_tm = taint_mark()
        src_tm = taint_mark()

        #arg1 seems to always be a reg
        if is_reg(arg1):
            dst_tm = taint_mark(arg1, True)
        else:
            print("The sky is falling!")
            exit()

        if is_a_constant(arg2):
            #if arg2 is a constant we just return src_tm
            dst_tm.len = get_arg_length(arg1)
            return dst_tm
        elif is_reg(arg2):
            src_tm = taint_mark(arg2, True)
        elif type(tm) == taint_mark:
            src_tm = arg2
        else:
            print("danger danger")
            exit()

        r = get_arg_length(arg1)
        for i in range(r):
            to = dst_tm.get_taint_rep(i)
            frm = src_tm.get_taint_rep(i)
            self.taint["tmp", i] = combine_taint(to,frm)

        rt = taint_mark("tmp", True)
        rt.len = r
        return rt

    def DIFT_load_address_dependency(self, address, calcAddress, opp, r2):
        """
        8 and 16 bit immediate values taint their destinations
        """
        address_tm = taint_mark(int(address, 16), False)
        calc_tm = taint_mark()
        r = get_len(opp)

        if type(calcAddress) == taint_mark:
            calc_tm = calcAddress()
        elif is_reg(calcAddress):
            calc_tm = taint_mark(calcAddress, True)
        elif is_a_constant(calcAddress):
            #if we don't use anything to calculate address return
            return address_tm
        else:
            print("the wrong way")

        for i in range(r):
            to = address_tm.get_taint_rep(i)
            frm = calc_tm.get_taint_rep(i)
            self.taint["tmp", i] = combine_taint(to,frm)

        rt = taint_mark("tmp", True)
        rt.len = r
        return rt

    def DIFT_store_address_dependency(self, data, calcAddress, opp, r2):
        r = get_len(opp)
        calc_tm = taint_mark()
        data_tm = taitn_mark()

        #calcAddress can either be a reg or taint mark
        if is_reg(calcAddress):
            cacl_tm = taint_mark(calcAddress, True)
        elif type(calcAddress) == taint_mark:
            calc_tm = calcAddress
        else:
            print("what I really want to know")

        #data is either constant, reg, or tm
        if is_reg(data):
            data_tm = taint_mark(data, True)
        elif type(data) == taint_mark:
            data_tm = data
        #minos cares about the size of a constant
        #so we will need to adjust this
        elif is_a_constant(data):
            return calc_tm
        else:
            print("can't find that Hannah")
        #fix this to work with 32 and 64 bit modes
        to = data_tm.get_taint_rep(i, self.mode)
        frm = calc_tm.get_taint_rep(i, self.mode)
        self.taint["tmp", i] = combine_taint(to,frm)

        rt = taint_mark("tmp", True)
        rt.len = r
        return rt

    def sizeof(self, constant):
        if constant <= 0xf:
            return 8
        elif constant <= 0xff:
            return 16
        elif constant <= 0xffff:
            return 32

    def combine_taint(self, mark1, mark2):
        ret_mark = mark | mark

        return ret_mark

    def DIFT_taint_source(self, startAddress, elements):
        #number of 32 bit elements
        elements = math.ceil((elements * 8) / 32)
        #start address 32 bit alligned
        startAddress = 32 * math.floor(startAddress / 32)
        for i in range (elements):
            loc =  startAddress + (i * 32)
            self.taint[loc] = 1
            self.origtaint[loc] = 1

    def get_len(self, arg):
        #if we have a tupel
        if type(arg) == tuple:
            self.get_arg_length(arg[0])
        else:
            return self.get_reg_length(arg)

    def get_arg_length(self, arg):
        if arg == "[]" or arg == "[8]" or arg == "=[]" or arg == "=[8]":
            return 8
        elif arg == "[4]" or arg == "=[4]":
            return 4
        elif arg == "[2]" or arg == "=[2]":
            return 2
        elif arg == "[1]" or arg == "=[1]":
            return 1
        return -1

    def get_reg_length(self, reg):
        if reg.startswith("r") and not reg[1].isdigit():
            return 8
        elif reg.startswith("r") and reg[1:].isdigit():
            return 8
        elif reg.startswith("e"):
            return 4
        elif reg.endswith("d"):
            return 4
        elif reg.endswith("ip"):
            return 2
        elif len(reg) == 2 or reg.startswith("r"):
            if reg.endswith("x"):
                return 2
            elif reg.endswith("w"):
                return 2
            elif reg.endswith("p"):
                return 2
            elif reg.endswith("i"):
                return 2
        return 1

    #treats everything like its in the 64bit namespace
    def get_reg_name(self, reg):
        isGPR = False
        midletter = ""
        start = ""
        end = ""
        gprs = set(["a","b","c","d"])
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
                return ("r" + reg[1:], 4)
            if start == "r":
                return (reg, 0)
        else:
            if isGPR and len(reg) == 2:
                if end == "x":
                    return ("r" + reg, 6)
                elif end == "l":
                    return ("r" + reg[0] + "x", 7)
                elif end == "h":
                    return ("r" + reg[0] + "x" , 6)
        #for x86_64 r8,r9,...r15
        if reg[1].isdigit():
            if reg.endswith("d"):
                return (reg[:-1], 4)
            elif reg.endswith("w"):
                return (reg[:-1],6)
            elif reg.endswith("l"):
                return (reg[:-1],7)
            else:
                return (reg,0)
        #Stack, base and instruction pointer
        #R?P, E?P, ?P, ?PL -> ? = (S|B)
        #R?I, E?I, ?I, ?IL -> ? = (S|D)
        pil = set(["p", "i", "l"])
        if end in pil:
            if len(reg) == 3:
                if reg[0] == "r":
                    return (reg, 0)
                elif reg[0] == "e":
                    return ("r" + reg[1:], 4)
                elif reg.endswith("l"):
                    return ("r" + start + midletter, 7)
            elif len(reg) == 2:
                return ("r" + start + reg[-1], 6)

