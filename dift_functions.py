#! /usr/bin/env python
import random
import math
import numpy as np
from parse_lib import is_a_constant
from parse_lib import is_reg
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

    def get_taint_rep(self,i):
        if self.is_reg:
            # taint_mark is a register
            r,p = DIFT.get_reg_name(1,self.reg)
            return(r,p+i)
        else:
            # taint is a mem location
            return (self.mem + i)

class DIFT():
    MAXLEN = 8
    DIM = 200

    def __init__ (self):
        self.taint = {}
        self.origtaint = {}

    def taint_register(self, reg_taint):
        #make sure its a register first
        if reg_taint.is_reg == False:
            print("ERROR")
        else:
            #get the mark number and register name
            r, p = DIFT.get_reg_name(self, reg_taint.reg)
            for i in range(p, self.MAXLEN):
                self.taint[(r,i)] = self.get_random_taint_vector()

    def taint_mem_range(self, mem_taint, num):
        for i in range(0, num):
            self.taint[mem_taint.get_taint_rep(i)] = \
                self.get_random_taint_vector()

    def DIFT_copy_dependency(self, toLocation, fromData, to_len, r2):
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
            print("SHIT BALLS. Make sure toLocation is not a taint_mark?")
            exit()

        #Do the actual taint copying
        for i in range(r):
            to = to_taint_mark.get_taint_rep(i)
            frm = from_taint_mark.get_taint_rep(i)
            self.taint[to] = self.taint[frm]

    #need to make sure that tm actuall exists I think
    def clear_taint(self, tm):
        l = 0
        if tm.is_reg:
            l = self.get_reg_length(tm.reg)
        else:
            print("OMG")
            exit()
        for i in range(l):
            loc = tm.get_taint_rep(i)
            self.taint[loc] = self.taint[loc] * 0


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
        elif is_a_constant(data):
            return calc_tm
        else:
            print("can't find that Hannah")

        for i in range(r):
            to = data_tm.get_taint_rep(i)
            frm = calc_tm.get_taint_rep(i)
            self.taint["tmp", i] = combine_taint(to,frm)

        rt = taint_mark("tmp", True)
        rt.len = r
        return rt

    def DIFT_taint_source(self, startAddress, elements):
        print("TAINT SOURCE")
        print(startAddress)
        print(elements)
        for i in range (elements):
            self.taint[startAddress + i] = self.get_random_taint_vector()
            self.origtaint[startAddress + i] = self.taint[startAddress + i]

    def get_random_taint_vector(self):
        sqrsum = 0
        nv = []
        for i in range(self.DIM):
            x = random.gauss(0,1)
            nv.append(x)
            sqrsum += x*x
        sqrsum = 1.0 / math.sqrt(sqrsum) * self.MAXLEN

        nv = [i * sqrsum for i in nv]
        return np.array(nv)

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

    #LA.norm(x) = norm
    #np.dot(x,y) = dot product

    def cossim(self, mat1, mat2):
        denom = LA.norm(mat1) * LA.norm(mat2)
        ret = np.dot(mat1, mat2) / denom
        return ret

    def DIFT_print_cossim(self, address, length, fd):
        """
        xaxis = in bytes
        yaxis = out bytes
        """
        inbytes = self.origtaint.values()
        for i in range(length):
            outbyte = self.taint.get(address + i)
            for b in inbytes:
                val = self.cossim(b,outbyte)
                fd.write(str(val) + " ")
                print(val, end="\t")
            print()
            fd.write("\n")

    def get_taint_magnitude(self, mat1, mat2):
        norm1 = LA.norm(mat1)
        norm2 = LA.norm(mat2)
        return (max(norm1, norm2) + min(norm1,norm2) * (1.0 - math.pow(self.cossim(mat1,mat2),self.DIM)))

    def combine_taint(self, mat1, mat2):
        ret_vec = mat1 + mat2

        #see if we want to be able to go beyond MAXLEN
        tm = self.get_taint_magnitude(mat1, mat2)
        if tm > self.MAXLEN:
            tm = self.MAXLEN
        scale = self.get_scale_value(tm, ret_vec)
        ret_vec = ret_vec * scale

        return ret_vec

    def get_scale_value(self, taintMag, mat):
        return (math.sqrt(taintMag * taintMag))/(np.dot(mat,mat)) * self.MAXLEN

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

