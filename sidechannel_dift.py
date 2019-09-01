#!/usr/bin/python3
#author EZE
#author 1207
import r2pipe
import sys
from parse_lib import Parser, dprint
import json
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

def do_load_headers(r2, conf=None):
    ret = r2.cmd('to ./skbuff_all.h')
    dprint("ret={}".format(ret), conf=conf)

def set_breakpoint(r2, addr, conf=None):
    ret = r2.cmd('db {}'.format(addr))
    dprint(ret, conf)

def _do_set_breakpoints(r2, s, conf=None):
    for addr in s:
        dprint('debug!!!. addr = {}'.format(addr), conf=conf)
        # r2 doesn't like this. Ip appears to be attempting to
        # break on the address of the previous address we set the
        # breakpoint for.
        ip_rcv_addr = r2.cmd('iE~{}:0[2]'.format(addr))
        dprint(ip_rcv_addr, conf=conf)
        set_breakpoint(r2, addr, conf=conf)

def do_set_sources(r2, sources, conf=None):
    # _do_set_breakpoints(r2, sources, conf=conf)
    do_set_ip_rcv_addr(r2, conf=conf)

def do_set_ip_rcv_addr(r2, conf=None):
    ret = r2.cmd('db 0xffffffff81890880')
    dprint('ret={}'.format(ret), conf=conf)


def do_set_sinks(r2, sinks, conf=None):
    # _do_set_breakpoints(r2, sinks, conf=conf)
    do_set_ip_local_out_addr(r2, conf=conf)

def do_set_ip_local_out_addr(r2, conf=None):
    ret = r2.cmd('db 0xffffffff81895ba0')
    dprint('ret={}'.format(ret), conf=conf)

def main():
    args = parse_args()
    conf = parse_conf(args.conf)
    dift_lib = __import__(conf.get("dift_lib"))

    #if they provide a second arg name the output it
    of = open(conf.get('outfile'), "w")

    #start up r2
    r2 = r2pipe.open(conf.get("program"), conf.get("r2args"))
    parser = Parser(conf)
    vdift = dift_lib.DIFT(parser)
    do_load_headers(r2, conf=conf)
    do_set_sources(r2, conf.get('sources'), conf=conf)
    do_set_sinks(r2, conf.get('sinks'), conf=conf)
    run_loop = True
    pc = getIPname(r2, conf)

    r2.cmd("dc") # run the program
    # We will continue until we hit one of the taint sources
    # for the first time. Then we  have to single step through the execution
    while(run_loop):
        ao_output, ddict, esil, run_loop, skip = run_ao_command(r2, parser, conf=conf)
        parser.apply_dependency(esil, r2, vdift, conf=conf)
        # Im not sure why we need to seek to the pc if we're already there...
        r2.cmd("ds")
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

def run_ao_command(r2, parser, conf=None):
    # analyze opcode
    # ~ == grep
    # esil
    # I think we can get this as json
    # ao1 = r2.cmd("ao~esil,address,opcode")
    ao1 = r2.cmd("aoj")
    ao1 = json.loads(ao1)
    ao1 = ao1[0] if ao1 else None
    if not ao1:
        dprint("aoj returned nothing...", conf=conf)
        exit()
    #place output of above command into a dictionary
    d = parseao(ao1, conf=conf)
    e = ''
    run_loop = 1
    skip = 0
    if d.get('esil'):
        """ """
        e = parser.parse_esil(d.get('esil'),1) # BEN commented this out
        dprint("universal_dift.137: d={}, e={}".format(d, e),
                conf=conf)
    else:
        dprint('hit else. d={}'.format(d), conf=conf)
        run_loop = 0
        ao5 = r2.cmd("aoj")
        ao5 = json.loads(ao5)
        for ao in ao5:
            d = parseao(ao)
            if type(d) == dict and d != {} and d.get('esil'):
                e = parser.parse_esil(d.get('esil'),1) # BEN commented this out
                run_loop = 1
                break
            elif d.__contains__('opcode'):
                run_loop = 1
                #print("skipped {}".format(d.get('opcode')))
                skip = 1
                break
    # ao1: last analyzed opcode
    return (ao1, d, e, run_loop, skip)


"""
def run_ao_command(r2, conf=None):
    # analyze opcode
    # ~ == grep
    # esil
    # I think we can get this as json
    # ao1 = r2.cmd("ao~esil,address,opcode")
    ao1 = r2.cmd("aoj")
    ao1 = json.loads(ao1)
    ao1 = ao1[0] if ao1 else None
    if not ao1:
        dprint("aoj returned nothing...", conf=conf)
        exit()
    #place output of above command into a dictionary
    d = parseao(ao1, conf=conf)
    e = ''
    to_continue = 1
    skip = 0
    if d.get('esil'):
        """ """
        e = parse_esil(d.get('esil'),1) # BEN commented this out
        dprint("universal_dift.run_ao_command.109: d={}, e={}".format(d, e), conf=conf)
    else:
        to_continue = 0
        for i in range(5):
            ao1 = r2.cmd("ao~esil,address,opcode")
            d = parseao(ao1)
            if type(d) == dict and d != {} and d.get('esil'):
                e = parse_esil(d.get('esil'),1) # BEN commented this out
                to_continue = 1
                break
            elif d.__contains__('opcode'):
                to_continue = 1
                #print("skipped {}".format(d.get('opcode')))
                skip = 1
                break
    # ao1: last analyzed opcode
    return (ao1, d, e, to_continue, skip)
"""

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
def getIPname(r2, conf):
    return conf.get("arch").get("pc")

#make a dictionary of "ao" info
def parseao(ao1, conf=None):
    dprint('ao1={}'.format(json.dumps(ao1, indent=4)), conf=conf)
    d = {
            "esil" : ao1.get("esil"),
            "address" : ao1.get("addr"),
            "opcode" : ao1.get("opcode")
            }
    return d

"""
def parseao(info, conf=None):
    try:
        dprint('ao1={}'.format(json.dumps(info)), conf=conf)
        sinfo = info.split(\n)
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
"""

if __name__=="__main__":
    main()
