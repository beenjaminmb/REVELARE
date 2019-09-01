#! /usr/bin/env python3

# 3rd party imports
import random
import math
import numpy as np
import sys
from numpy import linalg as LA

#only have one bool here that states wheather or not we are a register
#if its a mem value then we make self.mem
#if its a reg then we make self.reg
class taint_mark(object):
    #initialize a taint mark, make it a mem value by default
    def __init__(self):
        self.is_reg = False
        self.is_init = False

    #initialize a taint mark, but make it a reg/mem and give value
    def set_vals(self, val, reg_t):
        self.is_init = True
        self.len = 0
        self.is_reg = reg_t
        if reg_t:
            self.reg = val
        else:
            if type(val) == int:
                self.mem = val
            else:
                self.mem = int(val,16)


    def get_taint_rep(self, i, dift, debug=False):
        if self.is_reg:
            # taint_mark is a register
            r, p = dift.get_reg_name(self.reg)
            if debug:
                print("\tget_taint_rep: r={} p={} i={}".format(r,p, i))
            return(r,i)
        else:
            # taint is a mem location
            return (self.mem + i)

class DIFT():
    MAXLEN = 8
    DIM = 100
    arrtype = type(np.zeros(1))
    debug_help = 0

    def __init__ (self, parser):
        self.taint = {}
        self.origtaint = {}
        self.parser = parser
    def get_reg_name(self, reg):
        return self.parser.get_reg_name(reg)

    def get_arg_length(self, arg):
        return self.get_arg_length(arg)

    def is_a_constant(self, val):
        return self.parser.is_a_constant(val)

    def is_reg_fn(self, val):
        return self.parser.is_reg(val)

    def taint_register(self, reg_taint):
        #make sure its a register first
        if reg_taint.is_reg == False:
            print("ERROR")
        else:
            #get the mark number and register name
            r, p = self.get_reg_name(reg_taint.reg)
            for i in range(p, self.MAXLEN):
                self.taint[(r,i)] = self.get_random_taint_vector()

    def taint_mem_range(self, mem_taint, num):
        for i in range(0, num):
            self.taint[mem_taint.get_taint_rep(i, self)] = \
                self.get_random_taint_vector()


    def DIFT_control_dependancy(self, to, frm, to_len, r2, debug=False, space=''):
        """DIFT_control_dependancy: 

       :param to (taint_mark, str): The location to which taint propogates
       :param frm (taint_mark, str): The location from which taint is propogated
       :to_len (int) The number of bytes of bytes to propogate to 'to' from 'frm'

        TODO: Implement control dependency information flow.
        """

    def DIFT_copy_dependency(self, toLocation, fromData, to_len, r2, debug=False, space=''):
        # Ignore xmm registers.
        r = 0
        to_taint_mark = taint_mark()
        from_taint_mark = taint_mark()
        space += ' '
        # toLocation=w2
        # fromData=vdtmp1 // The taint we want to propogate from the add ldrb w2, w1, w0
        print(space + "DIFT_copy_dependancy:83. toLocation={}, type()={}, fromData={}, type={},  to_len={}".format(toLocation, type(toLocation), fromData, type(fromData), to_len))
        #fromData can be a reg, a mem location or a taint_mark from a previous
        #calculation
        # toLocation=tmp, fromData=sp (offset of 44)
        if type(fromData) == taint_mark:
            from_taint_mark = fromData
            r = fromData.len
        elif self.is_reg_fn(fromData):
            if True:
                print("fromData is register: {}".format(fromData))
            from_taint_mark.set_vals(fromData, True)
        elif self.is_a_constant(fromData):
            self.clear_taint(to_taint_mark)
            return None

        else:
            print(space + "DIFT_copy_dependency:100.FUCK toLocation={}, fromData={}".format(toLocation, fromData))
            exit()

        if self.debug_help:
            print("TO LOCATION")
            print(toLocation)
            print("FROM DATA")
            print(fromData)
            if type(fromData) == taint_mark:
                print(fromData.get_taint_rep(0, self))
                if self.taint.get(fromData.get_taint_rep(0, self)) != self.arrtype:
                    print(self.taint.get(from_taint_mark.get_taint_rep(0, self)))

        #make sure taint mark exists first
        #return otherwise

        if (not from_taint_mark.is_init) or\
           (type(self.taint.get(from_taint_mark.get_taint_rep(0, self))) != self.arrtype):
            if self.debug_help or debug:
                pstr = {k: len(l) for k, l in self.taint.items() if l != None}
                print("DEBUG - self.taint: {}".format(pstr))
                print("DEBUG - self.taint.get(FTM) = {}".format(
                    self.taint.get(from_taint_mark.get_taint_rep(0, self))
                ))
                print("DEBUG - from_taint_mark.get_taint_rep(0) = {}".format(from_taint_mark.get_taint_rep(0, self)))

                print("\n\t{}\n\t{}".format(
                    type(self.taint.get(from_taint_mark.get_taint_rep(0, self))),
                    self.arrtype)
                )
            print(space + 'DIFT_copy_dependancy.130. return nothing {}'.format(from_taint_mark.is_init))
            return

        #toLocation can only be a register or a mem location I think
        if self.is_reg_fn(toLocation):
            to_taint_mark.set_vals(toLocation, True)
        elif self.is_a_constant(toLocation):
            to_taint_mark.set_vals(int(toLocation, 16), False)
            r = to_len
        elif type(toLocation) == taint_mark:
            r = toLocation.len
        else:
            print(space + "DIFT_copy_dependancy.140: type(toLocation)={}, toLocation={}, self.is_a_constant(toLocation)={}".format(type(toLocation), toLocation, self.is_a_constant(toLocation)))
            exit()
        if r == 0:
            r = self.get_reg_length(toLocation)

        print(space + 'DIFT_copy_dependancy.146. r={}'.format(r))
        #Do the actual taint copying
        for i in range(r):
            to = to_taint_mark.get_taint_rep(i, self)
            frm = from_taint_mark.get_taint_rep(i, self)
            print(space + 'DIFT_copy_dependancy.152. to={}, from={}'.format(to, frm))
            try:
                self.taint[to] = self.taint[frm]
                print(space + 'DIFT_copy_dependancy.155. taint[to]=taint=[frm], taint[to]={}, taint[frm]={}'.format(self.taint[to], self.taint[frm]))
                #print(self.taint[to])
            except KeyError:
                print(space + 'DIFT_copy_dependancy.158. KeyError')
                #continue
                break
        # print(space + "DIFT_copy_dependancy.161. to={}, r={}, self.taint[to]".format(to, r, self.taint[to])) 
    #need to make sure that tm actuall exists I think
    def clear_taint(self, tm):
        l = 0
        if tm.is_reg:
            l = self.get_reg_length(tm.reg)
        else:
            return
        for i in range(l):
            loc = tm.get_taint_rep(i, self)
            self.taint[loc] = self.taint[loc] * 0


    def DIFT_computation_dependency(self, dst, src, r2):
        """ DIFT_computation_dependency 
        : dst = arg1 :
        : arg1 :
        """
        #always return a taint_mark
        #unless you throw an error and die
        dst_tm = taint_mark()
        src_tm = taint_mark()

        #arg1 must always be a reg
        if is_reg(dst):
            dst_tm.set_vals(dst, True)
        else:
            print("DIFT_computation_dependency.193. dst={}, src={}".format(dst, src))
            exit() # I commented this out, evidentally...

        if self.is_a_constant(src):
            #if arg2 is a constant we just return dst_tm
            dst_tm.len = self.get_len(dst)
            return dst_tm
        elif type(src) == taint_mark:
            src_tm = src
        elif is_reg(src):
            src_tm.set_vals(src, True)
        else:
            print("Arg2: {}, Arg2 type: {}".format(src, type(src)))
            print("Danger, Will Robinson! Danger!")
            exit()

        r = self.get_arg_length(dst)
        for i in range(r):
            to = dst_tm.get_taint_rep(i, self)
            frm = src_tm.get_taint_rep(i, self)
            self.taint["vdtmp2", i] = self.combine_taint(to,frm)
        rt = taint_mark()
        rt.set_vals("vdtmp2", True)
        rt.len = r
        return rt

    def DIFT_load_address_dependency(self, address, calcAddress, opp, r2):
        address_tm = taint_mark()
        address_tm.set_vals(int(address, 16), False)
        calc_tm = taint_mark()
        r = self.get_len(opp)
        taint_rep = calcAddress.get_taint_rep(0, self) if type(calcAddress) ==taint_mark else calcAddress
        print("DIFT_load_address_dependancy.219. address={}, calcAddress={}, opp={}, r={}".format(address,taint_rep,opp, r))
        if type(calcAddress) == taint_mark:
            calc_tm = calcAddress
        elif is_reg(calcAddress):
            calc_tm.set_vals(calcAddress, True)
        elif self.is_a_constant(calcAddress):
            #if we don't use anything to calculate address return
            return address_tm
        else:
            print("the wrong way")

        for i in range(r):
            to = self.taint.get(address_tm.get_taint_rep(i, self))
            frm = self.taint.get(calc_tm.get_taint_rep(i, self))
            self.taint["vdtmp1", i] = self.combine_taint(to,frm)
            print("DIFT_load_address_dependancy.233. i={}, to={}, frm={}, taint={}".format(i, to, frm, self.taint["vdtmp1", i]))

        rt = taint_mark()
        rt.set_vals("vdtmp1", True)
        rt.len = r
        return rt

    def DIFT_store_address_dependency(self, data, calcAddress, opp, r2):
        r = self.get_len(opp)
        calc_tm = taint_mark()
        data_tm = taint_mark()

        print("DIFT_store_address_dependancy.219. data={}, calcAddress={}, opp={}".format(data,calcAddress,opp))
        #calcAddress can either be a reg or taint mark
        if type(calcAddress) == taint_mark:
            calc_tm = calcAddress
            print("DIFT_store_address_dependency.256 if calc_tm : {}".format(calcAddress))
        elif is_reg(calcAddress):
            calc_tm.set_vals(calcAddress, True)
            print("DIFT_store_address_dependency.258 elif calc_tm : {}".format(calc_tm))

        else:
            print("DIFT_store_address_dependency.262 else: {} {} ".format(type(calcAddress), calcAddress))
            calc_tm.set_vals(calcAddress, False)
            # calcAddress is a memory address..., but nothing is happening here. 
        #data is either constant, reg, or tm
        if type(data) == taint_mark:
            data_tm = data
            print("DIFT_store_address_dependency.267. elif\n\tstore_address_dep: {} {}".format(data, calcAddress)) # Tony, who
        elif is_reg(data):
            data_tm.set_vals(data, True)
            print("DIFT_store_address_dependency.270. elif\n\tstore_address_dep: {} {}".format(data, calcAddress)) # Tony, who the fuck is hannah
        elif self.is_a_constant(data):
            print("DIFT_store_address_dependency.272. elif\n\t data==const: data={}, "
                  "calcAddress={}, type(calcAddress)={}".format(
                      data, calcAddress, type(calcAddress))) # Tony, who the fuck is hannah
            return calc_tm
        else:
            print("DIFT_store_address_dependency.275. data={}".format(data))

        for i in range(r):
            to = self.taint.get(data_tm.get_taint_rep(i, self))
            frm = self.taint.get(calc_tm.get_taint_rep(i, self))

            self.taint["vdtmp", i] = self.combine_taint(to,frm)
        rt = taint_mark()
        # The fuck is tmp here and up there for?!?!
        rt.set_vals("vdtmp", True)
        rt.len = r
        return rt

    def DIFT_taint_source(self, startAddress, elements):
        print("DIFT_taint_source.285. startAddress={}, elements={}".format(startAddress, elements))
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
        if type(arg) == tuple or (type(arg)==str and (arg.startswith('[') or arg.startswith('=['))):
            if type(arg)==str:
                return self.get_arg_length(arg)
            return self.get_arg_length(arg[0])
        else:
            return self.get_reg_length(arg)
    #LA.norm(x) = norm
    #np.dot(x,y) = dot product

    def cossim(self, mat1, mat2):
        if np.count_nonzero(mat2) == 0:
            return ''
        denom = LA.norm(mat1) * LA.norm(mat2)
        ret = np.dot(mat1, mat2) / denom
        return ret

    def DIFT_print_cossim(self, address, length, fd):
        """
        xaxis = in bytes
        yaxis = out bytes
        """
        # address = address + 8
        print("DIFT_print_cossim.323: address={}, length={}, taint={}\n\n\n\torigtaint={}".format(address, length, self.taint, self.origtaint))
        inbytes = self.origtaint.values()
        for i in range(length):
            outbyte = self.taint.get(address + i)
            print("DIFT_print_cossim.327: address={}, outbytes={}".format(address + i, outbyte))
            for b in inbytes:
                val = self.cossim(b,outbyte)
                #  print("\tDIFT_print_cossim.330: address={}, val={}, outbytes={}, b={}\n".format(address + i, val, outbyte, b))
                fd.write(str(val) + " ")
            print()
            fd.write("\n")

    def get_taint_magnitude(self, mat1, mat2):
        norm1 = LA.norm(mat1)
        norm2 = LA.norm(mat2)
        return (max(norm1, norm2) + min(norm1,norm2) * (1.0 - math.pow(self.cossim(mat1,mat2),self.DIM)))

    def combine_taint(self, mat1, mat2):
        if type(mat1) == self.arrtype  and type(mat2) != self.arrtype:
            if self.debug_help:
                print("dift_function.combine_taint.360. mat1={}".format(mat1))
            return mat1
        elif type(mat2) == self.arrtype and type(mat1) != self.arrtype:
            if self.debug_help:
                print("dift_function.combine_taint.360. mat2={}".format(mat2))
            return(mat2)
        elif type(mat1) != self.arrtype and type(mat2) != self.arrtype:
            return np.zeros(self.DIM)

        ret_vec = mat1 + mat2
        if np.array_equal(mat1, np.zeros(self.DIM)):
            return ret_vec
        elif np.array_equal(mat2, np.zeros(self.DIM)):
            return ret_vec

        #see if we want to be able to go beyond MAXLEN
        taint_magnitude = self.get_taint_magnitude(mat1, mat2)
        if taint_magnitude > self.MAXLEN:
            taint_magnitude = self.MAXLEN
        scale = self.get_scale_value(taint_magnitude, ret_vec)
        ret_vec = ret_vec * scale

        return ret_vec

    def get_scale_value(self, taintMag, mat):
        return (math.sqrt(taintMag * taintMag))/(np.dot(mat,mat)) * self.MAXLEN
