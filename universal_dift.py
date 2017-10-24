#!/usr/bin/python
#author EZE
import r2pipe
import sys
from parse_lib import *
#from dift_functions import *

def main():
    #pass program as input
    if len(sys.argv) < 2:
        exit(0)

    #get the program and the args
    a1 = sys.argv[1] #always the program
    args = ""
    for i in range(1, len(sys.argv[1:])):
        args += sys.argv[i] + " "
    args = args.strip()

    # import the DIFT module
    dift_lib = __import__(sys.argv[2])

    #if they provide a second arg name the output it
    of =""
    if len(sys.argv) == 4:
        of = open(sys.argv[3], "w")
    else:
        of = open("dift_out", "w")

    #start up r2
    r2 = r2pipe.open(a1, ["-d"])
    """
    #reopen in debug mode
    if args == "":
        r2.cmd("ood")
    else:
        print ("ood {}".format(args))
        r2.cmd("ood {}".format(args))
    """
    #r2.cmd("aaaa") #annalyize
    r2.cmd("db main")# set breakpoint at main
    r2.cmd("dc") #run the program

    print(r2.cmd("aaa; pdf")) #print memory map

    #ip = instruction pointer
    ip = getIPname(r2)

    eip = r2.cmd("dr?" + ip)#get instruction pointer
    r2.cmd("s "+eip) #seek to IP
    vdift = dift_lib.DIFT()
    ao_output, d, e, run_loop, skip = run_ao_command(r2)
    while(run_loop):
        try:
            if skip:
                r2.cmd("ds;s `dr? {}`".format(ip))
                ao_output, d, e, run_loop, skip = run_ao_command(r2)
                continue
            esil_instructions = e[0]
            print("===start x86 instruction===")
            #print_stack(4, r2)
            print("esil:{}".format(d.get('esil')))
            print("opcode:{}".format(d.get('opcode')))
            print(ao_output)
            for e in esil_instructions:
                #print("parsed esil:",end="")
                #print(e)
                #print("dependency:{}".format(print_dependency(e, r2)))
                apply_dependency(e, r2, vdift)
            print("---end x86 instruction---")
            r2.cmd("ds;s `dr? {}`".format(ip))
            #debug setp, seek to eip
            ao_output, d, e, run_loop, skip = run_ao_command(r2)
        except UnicodeError as e:
            print(e)
            exit()
    of.close()
    r2.quit()

def print_stack(n, r2):
    for i in range(5):
        pxo = r2.cmd("px {} @ esp".format(n))
        if pxo.startswith("- offset -"):
            print(pxo)
            break

def run_ao_command(r2):
    ao1 = r2.cmd("ao~esil,address,opcode")
    #place output of above command into a dictionary
    d = parseao(ao1)
    e = ''
    to_continue = 1
    skip = 0
    if d.__contains__('esil'):
        e = parse_esil(d.get('esil'),1)
    else:
        to_continue = 0
        for i in range(5):
            ao1 = r2.cmd("ao~esil,address,opcode")
            d = parseao(ao1)
            if type(d) == dict and d != {} and d.__contains__('esil'):
                e = parse_esil(d.get('esil'),1)
                to_continue = 1
                break
            elif d.__contains__('opcode'):
                to_continue = 1
                #print("skipped {}".format(d.get('opcode')))
                skip = 1
                break
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
def getIPname(r2):
    iA = r2.cmd("iA")
    if "x86_32" in iA:
        return "eip"
    if "x86_64" in iA:
        return "rip"

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
        return d
    except IndexError:
        return ''


if __name__=="__main__":
    main()
