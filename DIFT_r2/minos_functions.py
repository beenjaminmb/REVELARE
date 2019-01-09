#! /usr/bin/env python
import random
import math
import numpy as np
from parse_lib import is_a_constant
from parse_lib import is_reg
from parse_lib import get_register_A_name
from parse_lib import get_reg_name

from numpy import linalg as LA

#only have one bool here that states wheather or not we are a register
#if its a mem value then we make self.mem
#if its a reg then we make self.reg
class taint_mark():
    #initialize a taint mark, make it a mem value by default
    def __init__(self):
        self.is_reg = False
        self.is_init = False

    def get_taint_rep(self, i):
        if self.is_reg:
            # taint_mark is a register
            r,p = get_reg_name(self.reg)
            return(r,3)
        else:
            if i == 0:
                #self.mem should always be 32 bit alligned
                return self.mem
            else:
                return int((self.mem + i) /32)

    def set_taint(self, val, reg_t):
        self.is_init = True
        self.len = 0
        self.is_reg = reg_t
        if reg_t:
            self.reg = val
        else:
            #first allign value if un-aligned
            #also make field .was_alligned accordingly
            if type(val) == int:
                self.mem = val
            else:
                self.mem = int(val,16)
            if self.mem % 32 == 0:
                self.was_alligned = 1
            else:
                self.mem = self.mem - (self.mem % 32)
                self.was_alligned = 0

class DIFT():

    def __init__ (self):
        self.taint = {}
        self.min_size_cutoff = 4
        self.size = 1

    def clear_taint(self, taint):
        if not taint.is_init:
            return
        loc = taint.get_taint_rep(0)
        if type(loc) == int:
            self.taint[loc] = 0

    def DIFT_copy_dependency(self, toLocation, fromData, to_len, r2):
        """
        For MINOS if copy to memory is not 32 bit alligned it is tainted
        8 and 16 bit pieces of data taint all 32 bits of data
        """
        r = 0
        to_taint_mark = taint_mark()
        from_taint_mark = taint_mark()

        #fromData can be a reg, a mem location or a taint_mark from a previous
        #calculation
        if type(fromData) == taint_mark:
            from_taint_mark = fromData
            r = fromData.len
        elif is_reg(fromData):
            from_taint_mark.set_taint(fromData, True)
        elif is_a_constant(fromData):
            #I might need to fix this so that if it is a immediate < 32 bits
            #we taint it
            self.clear_taint(to_taint_mark)
            return
        else:
            print("Error.88")
            exit()
        if r == 0:
            r = self.get_reg_length(toLocation)

        #make sure taint mark exists first
        #return otherwise
        if (not from_taint_mark.is_init) or (type(self.taint.get(from_taint_mark.get_taint_rep(0))) != int ):
            return

        #toLocation can only be a register or a mem location I think

        if is_reg(toLocation):
            to_taint_mark.set_taint(toLocation, True)
            #the following is the integrety check for functions that change (R|E)IP
            #need a check here to make sure the register is not rip/eip
            #if so we need need to throw an allert to warn of
            #"integrety check failed"
            reg_name, dc = to_taint_mark.get_taint_rep(0)
            if reg_name == "rip":
                #instruction is a ret nothing else should set rip
                #check from location
                fmt = from_taint_mark.get_taint_rep(0)
                tm = self.taint.get(fmt)
                if tm == 1:
                    print("Integrety Check Failed exiting!")
                    print(from_taint_mark.get_taint_rep(0))
                    return
        elif is_a_constant(toLocation):
            to_taint_mark.set_taint(int(toLocation, 16), False)
            r = to_len
        elif type(toLocation) == taint_mark:
            r = toLocation.len
        else:
            print("Make sure toLocation is not a taint_mark?")
            exit()

        #Do the actual taint copying
        for i in range(self.size):
            to = to_taint_mark.get_taint_rep(i)
            frm = from_taint_mark.get_taint_rep(i)
            try:
                self.taint[to] = self.taint[frm]
            except KeyError:
                break

    #MINOS does nothing special for computation dependency
    def DIFT_computation_dependency(self, arg1, arg2, r2):
        #always return a taint_mark
        #unless you throw an error and die
        dst_tm = taint_mark()
        src_tm = taint_mark()

        #arg1 seems to always be a reg
        if is_reg(arg1):
            dst_tm.set_taint(arg1, True)
        else:
            print("Error in DIFT_computation_dependency line 145")
            exit()

        if is_a_constant(arg2):
            #if arg2 is a constant we just return src_tm
            dst_tm.len = self.get_arg_length(arg1)
            return dst_tm
        elif type(arg2) == taint_mark:
            src_tm = arg2
        elif is_reg(arg2):
            src_tm.set_taint(arg2, True)
        else:
            print("Error in DIFT_computation_dependency line 157")
            exit()

        r = self.get_arg_length(arg1)
        for i in range(self.size):
            to = dst_tm.get_taint_rep(i)
            frm = src_tm.get_taint_rep(i)
            try:
                self.taint["tmp1", i] = self.combine_taint(to,frm)
            except KeyError:
                break

        rt = taint_mark()
        rt.set_taint("tmp1", True)
        rt.len = r
        return rt

    #Say what this function does and double check before testing.
    #This function:
    #Skips all LAD that deal with 32 bits
    #Anything with a constant is treated as taint if it is less than 32 bits
    def DIFT_load_address_dependency(self, address, calcAddress, opp, r2):
        """
        8 and 16 bit immediate values taint their destinations
        """
        address_tm = taint_mark()
        address_tm.set_taint(int(address, 16), False)
        calc_tm = taint_mark()
        r = self.get_arg_length(opp)
        skip = 0
        #print("len opp was {}".format(r))
        """
        if r >= self.min_size_cutoff:
            #skip the rest cause we are 32 or 64 bit and don't care
            self.taint["LADtmp", 3] = 0
            rt = taint_mark()
            rt.set_taint("LADtmp", True)
            rt.len = 1
            return rt
        """

        if type(calcAddress) == taint_mark:
            calc_tm = calcAddress
        elif is_reg(calcAddress):
            calc_tm.set_taint(calcAddress, True)
        elif is_a_constant(calcAddress):
            if r < 4:
                self.taint["LADtmp", 3] = 1
                skip = 1
            else:
                self.taint["LADtmp", 3] = 0
                skip = 1

        else:
            print("Error.211")

        if not skip:
            #Always do the lower 32 bits ex (eax)
            to = address_tm.get_taint_rep(0)
            frm = calc_tm.get_taint_rep(0)
            self.taint["LADtmp", 3] = self.combine_taint(to,frm)

        rt = taint_mark()
        rt.set_taint("LADtmp", True)
        rt.len = r
        return rt

    #Ignoring 32 bit stores
    #tainting IFF a constant acts on a 16 or 8 bit value(opp is[1],[2])
    #tainting anything that loads a 1-2 byte immediate value into the address
    #tainting everything else normally
    def DIFT_store_address_dependency(self, data, calcAddress, opp, r2):
        r = self.get_arg_length(opp)
        calc_tm = taint_mark()
        data_tm = taint_mark()
        skip = 0
        #as long as get_len() works correctly the following should be good
        """
        if r >= self.min_size_cutoff:
            #skip the rest cause we are 32 or 64 bit and don't care
            self.taint["SADtmp", 3] = 0
            rt = taint_mark()
            rt.set_taint("SADtmp", True)
            rt.len = 1
            return rt
        """

        #calcAddress can either be a reg or taint mark
        if is_reg(calcAddress):
            calc_tm.set_taint(calcAddress, True)
        elif type(calcAddress) == taint_mark:
            calc_tm = calcAddress
        else:
            print("Error.250")

        #data is either constant, reg, or taint mark
        if type(data) == taint_mark:
            data_tm = data
        elif is_reg(data):
            data_tm.set_taint(data, True)
        #minos cares about the size of a constant
        #so we will need to adjust this
        elif is_a_constant(data):
            if r < 4:
                self.taint["SADtmp", 3] = 1
                skip = 1
            else:
                self.taint["SADtmp", 3] = 0
                skip = 1

        else:
            print("Error.268")

        if not skip:
            #Always do the lower 32 bits ex (eax and less)
            to = data_tm.get_taint_rep(0)
            frm = calc_tm.get_taint_rep(0)
            self.taint["SADtmp", 3] = self.combine_taint(to,frm)
        rt = taint_mark()
        rt.set_taint("SADtmp", True)
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
        tm1 = self.taint.get(mark1)
        tm2 = self.taint.get(mark2)
        if tm1 == None and tm2 == None:
            return 0
        elif tm1 == None and tm2 != None:
            return tm2
        elif tm1 != None and tm2 == None:
            return tm1
        else:
            ret_mark = tm1 | tm2

        return ret_mark

    def DIFT_taint_source(self, startAddress, elements):
        #number of 32 bit elements
        elements = math.ceil((elements * 8) / 32)
        #start address 32 bit alligned
        startAddress = 32 * math.floor(startAddress / 32)
        for i in range (elements):
            loc =  startAddress + (i * 32)
            self.taint[loc] = 1

    def get_len(self, arg):
        #if we have a tupel
        if type(arg) == tuple:
            return self.get_arg_length(arg[0])
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

