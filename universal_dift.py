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

    print(r2.cmd("pd")) #print memory map

    #ip = instruction pointer
    ip = getIPname(r2)

    inum = 1
    eip = r2.cmd("dr?" + ip)#get instruction pointer
    r2.cmd("s "+eip) #seek to IP
    ao = r2.cmd("ao") #print ESIL and other info
    of.write(ao)
    of.write("\n----------------\n")
    d = parseao(ao)
    end_addr = find_end(r2, ao, ip)
    vdift = dift_lib.DIFT()
    while(d != {}):
        inum += 1
        #this is not working for some reason
        #if d["address"] == end_addr:
            #if here we are at the end of main
        #    break;
        try:
            r2.cmd("ds;s `dr? {}`".format(ip))
            #this makes it so we only get esil and address info
            ao1 = r2.cmd("ao~esil,address,opcode")
            #print instruction number for debuggin, probably remove later
            of.write("Instruction number:{}\n".format(str(inum)))
            d = parseao(ao1)
            #try:
            print(d)
            if d.__contains__('esil'):
                e = parse_esil(d.get('esil'),1)
            else:
                print("skipping:{}".format(d.get('opcode')))
                continue
            #of.write(e[0])
            es = e[0]
            print("===start x86 instruction===")
            for e in es:
                print("parsed esil:",end="")
                print(e)
                print("dependency:{}".format(print_dependency(e, r2)))
                apply_dependency(e, r2, vdift)
            print("esil:{}".format(d.get('esil')))
            print("opcode:{}".format(d.get('opcode')))
            print("---end x86 instruction---")
            #except:
            #e = sys.exc_info()[0]
            #print(e)
            print(ao1)
            of.write("\n------end-------\n")
        except UnicodeError as e:
            print("NOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO")
            print("shit")
            print(e)
            exit()
    of.close()
    r2.quit()

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
    sinfo = info.split("\n")
    d = {}
    if sinfo == ['']:
        return d
    for s in sinfo:
        sl = s.split(":")
        d[sl[0].strip()]=sl[1].strip()
    return d

if __name__=="__main__":
    main()
