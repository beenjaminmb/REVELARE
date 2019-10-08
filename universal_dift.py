#!/usr/bin/python3 
#author EZE
#author 1207
import r2pipe
import sys
import json
from parse_lib import Parser, dprint 

#from dift_functions import *

def parse_args():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-c','--conf', dest="conf", default="./conf.json",
            help="The configuration file")
    parser.add_argument('-v','--verbose', dest="verbose", default=False,
            help="Print verbose output")
    return parser.parse_args()

def parse_conf(conf=None):
    """
    1. Name of program
    r2 -e dbg.exe.path=./vmlinux -e dbg.bpinmaps=0 -d gdb://127.0.0.1:1234
    """
    conf_dict = None
    if conf:
        with open(conf) as f:
            conf_dict = json.load(f)
    else:
        conf_dict = {
                "program" : 'gdb://127.0.0.1:1234',
                "r2args" : ['-d',
                    '-e', 'dbg.exe.path=./vmlinux',
                    '-e', 'dbg.bpinmaps=0'],
                "program_args" : None,
                "outfile" : "dift_out",
                "dift_lib" : "dift_functions",
                "arch" : {"pc" : "x86_64"},
                "sources" : ["ip_rcv"],
                "sinks" : ["ip_local_out"]
                }
    return conf_dict

def main():
    args = parse_args()
    conf = parse_conf(args.conf)
    #pass program as input
    args = conf.get("program_args")
    program = conf.get("program")
    if not program:
        dprint("Error")
        exit()
    # import the DIFT module
    dift_lib = __import__(conf.get("dift_lib"))

    #if they provide a second arg name the output it
    of =""
    if conf.get("outfile"):
        of = open(conf.get("outfile"), "w")
    else:
        of = open("dift_out", "w")

    #start up r2
    r2 = r2pipe.open(program, ["-d"])
    """
    #reopen in debug mode
    if args == "":
        r2.cmd("ood")
    else:
        print ("ood {}".format(args))
        r2.cmd("ood {}".format(args))
    """
    #r2.cmd("aaaa") # annalyize
    r2.cmd("db main") # set breakpoint at main
    r2.cmd("dc") # run the program

    # print(r2.cmd("aaa; pdf")) #print memory map

    # ip = instruction pointer
    ip = getIPname(r2)

    eip = r2.cmd("dr?" + ip) # get instruction pointer
    r2.cmd("s "+eip) # seek to IP
    parser = Parser(conf)
    vdift = dift_lib.DIFT()
    ao_output, d, e, run_loop, skip = run_ao_command(r2)
    while(run_loop):
        try:
            if skip:
                # Debug step
                r2.cmd("ds;s `dr? {}`".format(ip))
                print("universal_dift.run_loop.58. skip=True")
                ao_output, d, e, run_loop, skip = run_ao_command(r2)
                print('main.60. d={}. e={}'.format(d, e))
                continue
            esil_instructions = e[0]
            # print("===start x86 instruction===")
            # print_stack(4, r2)
            print("main.64 e={}, opecode={}, esil:{}".format(e, d.get('opcode'), d.get('esil')))
            # print(ao_output)
            for e in esil_instructions:
                # pass
                # print("parsed esil:",end="")
                # print(e)
                # print("FOO BAR: {}".format(e))
                # print("dependency : {}".format(print_dependency(e, r2)))
                # This is the important dift function call.
                print("main.73.apply_dependancy: e={}".format(e))
                apply_dependency(e, r2, vdift)
                # print("---end x86 instruction---")
            r2.cmd("ds;s `dr? {}`".format(ip))
            #debug setp, seek to eip
            ao_output, d, e, run_loop, skip = run_ao_command(r2)
            print('main.80: d={}, e={}'.format(d, e))
        except UnicodeError as e:
            print(e)
            exit()
    of.close()
    r2.quit()
    for k, v in vdift.taint.items():
        print("vdift.taint.key =  : {}".format(k))

def print_stack(n, r2):
    for i in range(5):
        pxo = r2.cmd("px {} @ esp".format(n))
        if pxo.startswith("- offset -"):
            print(pxo)
            break

def run_ao_command(r2):
    # analyze opcode
    # ~ == grep
    # esil
    ao1 = r2.cmd("ao~esil,address,opcode")
    #place output of above command into a dictionary
    d = parseao(ao1)
    e = ''
    to_continue = 1
    skip = 0
    if d.__contains__('esil'):
        """ """
        e = parse_esil(d.get('esil'),1) # BEN commented this out
        print("universal_dift.run_ao_command.109: d={}, e={}".format(d, e))
    else:
        to_continue = 0
        # The fuck is this crap? Why 5?!?!?!?
        for i in range(5):
            ao1 = r2.cmd("ao~esil,address,opcode")
            d = parseao(ao1)
            if type(d) == dict and d != {} and d.__contains__('esil'):
                e = parse_esil(d.get('esil'),1) # BEN commented this out
                to_continue = 1
                break
            elif d.__contains__('opcode'):
                to_continue = 1
                #print("skipped {}".format(d.get('opcode')))
                skip = 1
                break
    # ao1: last analyzed opcode
    # 
    return (ao1, d, e, to_continue, skip)


#seek through main and find the last ret
def find_end(r2, orig_ao, ip):
    ao = orig_ao
    loc = 0
    while True:
        d = parseao(ao)
        loc += int(d["size"])
        op = d["opcode"]
        if op.strip() == "ret":
            print("end found")
            print(d["address"])
            return  d["address"]
        else:
            r2.cmd("s `dr? {}` + {}".format(ip, loc))
            ao = r2.cmd("ao")

#get eip or rip; arch dependant
def getIPname(r2, debug=True):
    
    iA = r2.cmd("iA")
    if debug:
        print('universal_dift.getIP.instruction pointer {}'.format(iA))
    if "x86_32" in iA:
        return "eip"
    if "x86_64" in iA:
        return "rip"
    if "arm_64" in iA:
        return "pc"
    else:
        # Need to return EIP for ARCH and RISC-V
        return None

#make a dictionary of "ao" info
def parseao(info):
    try:
        sinfo = info.split("\n")
        d = {}
        if sinfo == ['']:
            return d
        for s in sinfo:
            sl = s.split(":")
            d[sl[0].strip()]=sl[1].strip()
        is_ldr = d.get('opcode') and 'str' in d['opcode']
        if is_ldr:
            # 'str w2, [x1, x2]'
            # ['', '[x1','x2]']
            is_immediate=False
            opcodes = d['opcode'].split(',')
            print('parseao.178.is_ldr.opcodes={}, d={}'.format(opcodes, d))
            if len(opcodes) == 3:
                offset = opcodes[2].strip()
                if offset.startswith('0x') or offset.startswith('#') or (offset[0] in set([str(i) for i in range(10)])):
                    is_immediate=True
            if len(opcodes) in [2, 4]:
                    return d
            print('parseao.183.is_ldr.is_immediate={}'.format(is_immediate))
            if not is_immediate and d.get('esil'):
                esil = d['esil'].split(',')
                esil=[esil[0], esil[1][1:]] + esil[2:] 
                d['esil']=','.join(esil)
            print('parseao.188.is_ldr. d={}'.format(d))
            
        return d
    except IndexError:
        return ''


if __name__=="__main__":
    main()
