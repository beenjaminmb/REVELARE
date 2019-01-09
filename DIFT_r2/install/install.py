#! /usr/bin/env python3
import subprocess
import os
import sys
file_path = "libr/anal/p/anal_x86_cs.c"
def main():
    if len (sys.argv) > 1 and "--help" in sys.argv or len(sys.argv) == 1:
        print("Download radare2 (using git) with the command:\n./install.py --git")
        print("Install radare2 with the command:\nsudo ./install.py --install")
        exit()
    if len (sys.argv) > 1 and "--git" in sys.argv:
        print ("download git repo first")
        cmd = "git clone https://github.com/radare/radare2"
        s,o = subprocess.getstatusoutput(cmd)
        os.chdir("radare2")
        #open file that needs changing
        cng = open(file_path, "r")
        add_insts(cng)
    #move to repo folder if needed
    if not os.getcwd().endswith("radare2"):
        os.chdir("radare2")
        print("changed dir")
    if len (sys.argv) > 1 and "--install" in sys.argv:
        print ("install r2")
        cmd = "./sys/install.sh"
        s,o = subprocess.getstatusoutput(cmd)
        print(o)
        #print(cmd)

def add_insts(f):
    lines = f.readlines()
    newf = ""
    i = 0
    seenyet = 0
    while i < len(lines):
        if "case X86_INS_SYSCALL:" in lines[i] and seenyet == 0:
            newf += """{}        esilprintf (op, "SYSCALL,SPECIAL")\
;\n        break;\n""".format(lines[i])
        elif "case X86_INS_SYSENTER:" in lines[i] and seenyet == 0:
            newf += """{}        esilprintf (op, "SYSENTER,SPECIAL")\
;\n        break;\n""".format(lines[i])
            seenyet = 1
        elif "case X86_INS_FCMOVU:" in lines[i] and seenyet == 0:
            newf += lines[i]
            i += 1
            newf += lines[i]
            newf += """    case X86_INS_BT:
        src = getarg (&gop, 1, 0, NULL, SRC_AR);
        dst = getarg (&gop, 0, 0, NULL, DST_AR);
        esilprintf (op, "1,%s,-,%s,>>,1,&,cf,=", src, dst);
        break;\n"""
        else:
            newf += lines[i]
        i += 1
    f.close()
    output = open(file_path, 'w')
    output.write(newf)
    output.close()

if __name__ == "__main__":
    main()

