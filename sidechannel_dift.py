#!/usr/bin/python3
#author EZE
#author 1207
import r2pipe
import sys
from parse_lib import Parser, dprint
import json
#from dift_functions import *


def get_skb_field_offset(field_name):
    # Note, these offsets are build specific. If compilation flags were used that
    # Change the sk_buff definition, these will need to be adjusted accordingly.
    # The skbuff_all.h file will need to be changed as well.
    skb_field_byte_count_map = [("filler" , 40), ("cb" , 48),  ("filler0" , 16),
            ("_nfct" , 8), ("len" , 4), ("data_len" , 4), ("max_len" , 2),
            ("hdr_len" , 2), ("queue_mapping" ,  2), ("__cloned_offset" , 1),
            ("active_extrnsions" , 1), ("header_start" , 4),
            ("__pkt_type_offset" , 1), ("__pkt_vlan_present_offset" , 1),
            ("tc_index" , 2), ("filler2" , 4), ("priority" , 4), ("skb_iif" , 4),
            ("hash" , 4), ("vlan_proto" , 2), ("vlan_tci", 2), ("filler3" , 4),
            ("secmark" , 4), ("filler4" , 6), ("inner_transport_header" , 2),
            ("inner_network_header" , 2), ("inner_mac_header" , 2),
            ("protocol" , 2), ("transport_header" , 2), ("network_header" , 2)]
    offset = 0
    for (cur_field, byte_count) in skb_field_byte_count_map:
        if cur_field == field_name:
            break
        offset += byte_count
    return offset

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

def print_stack(n, r2):
    for i in range(5):
        pxo = r2.cmd("px {} @ esp".format(n))
        if pxo.startswith("- offset -"):
            print(pxo)
            break

def run_ao_command(r2, parser, conf=None):
    ao1 = r2.cmd("aoj")
    ao1 = json.loads(ao1)
    if len(ao1) > 1:
        dprint('ao1={}'.format(ao1), conf=conf)
    ao1 = ao1[0] if ao1 else None
    if not ao1:
        dprint("aoj returned nothing...", conf=conf)
    d = parseao(ao1, conf=conf)
    e = ''
    run_loop = 1
    skip = 0
    e = parser.parse_esil(d.get('esil'),1)
    dprint("universal_dift.137: d={}, e={}".format(d, e), conf=conf)
    return (ao1, d, e, run_loop, skip)

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
    dprint('ao1={}'.format(ao1), conf=None)
    d = {
            "esil" : ao1.get("esil"),
            "address" : ao1.get("addr"),
            "opcode" : ao1.get("opcode")
            }
    return d

def make_addr(addr, offset):
    """Make a and return hex str from addr and offset
    : param addr : Hex encoded string of address
    : type str :  

    : param offset : the offset of the new address
    : type int :

    :return : The hex string of the new address
    """
    return hex(int(addr) + offset)

def get_mem_value(field_size, addr, r2):
    """Returns the value at the specified memory
    NOTE: Might need to include size or type
    """
    # field size.
    # We always start at 2
    value = r2.cmd("pd {} @ {}:1[2]".format(field_size, addr))
    print("get_mem_value.value = {}".format(value))
    return int(value)

def get_ip_hdr(rip_val, r2):
    """Return the address the ip_hdr is stored at in the sk_buff struct.

    network_header pointer offset is 178 bytes from skb_buff start.
    """
    network_header_offset = 178
    network_header_addr = make_addr(rip_val, network_header_offset)
    network_header_value = get_mem_value(network_header_addr)
    ip_hdr_addr = make_addr(rip_val, network_header_value)

    return hex(ip_hdr_addr)

def get_proto(rip_val, r2):
    """Returns the source address from the rip_val (sk_buff pointer).

    iph->proto = 9 bytes from start of network header
    """
    proto_offset = 9 # 0x9
    proto_addr = make_addr(get_ip_hdr(rip_val), proto_offset)
    proto = get_mem_value(proto_addr, r2)
    return proto

def get_saddr(rip_val, r2):
    """Returns the source address from the rip_val (sk_buff pointer).

    iph->saddr = 12 bytes from start of network header
    """
    saddr_offset = 12 # 0xC
    saddr_addr = make_addr(get_ip_hdr(rip_val), saddr_offset)
    saddr = get_mem_value(saddr_addr, r2)
    return saddr

def get_daddr(rip_val, r2):
    """Returns the destination address from the rip_val (sk_buff pointer).

    iph->daddr = 16 bytes from start of network header
    """
    daddr_offset = 16 # 0x10
    daddr_addr = make_addr(get_ip_hdr(rip_val), daddr_offset)
    daddr = get_mem_value(daddr_addr, r2)
    return saddr

def get_ip_fields(rip_val, r2):
    """
    1. Retrieving the ip header:

    struct iphdr *iph = ip_hdr(skb);

    static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
    {
        return (struct iphdr *)skb_network_header(skb);
    }

    static inline unsigned char *skb_network_header(const struct sk_buff *skb)
    {
        return skb->head + skb->network_header;
    }

    2. Retriving the IP source and dest addresses

    int ip_build_and_send_pkt(struct sk_buff *skb, const struct sock *sk,
                  __be32 saddr, __be32 daddr, struct ip_options_rcu *opt)
                  {

    ip_hdr(skb)->saddr,
    ip_hdr(skb)->daddr,
    ip_hdr(skb)->proto,
    """
    saddr = get_saddr(rip_val, r2)
    daddr = get_daddr(rip_val, r2)
    proto = get_proto(rip_val, r2)
    return saddr, daddr, proto


def get_tcp_hdr(rip_val, r2):
    tcp_hdr = None
    return tcp_hdr

def get_tcp_sport(rip_val, r2):
    """Return the source port for this sk_buff

    source port is 0 bytes from transport header
    """
    sport_offset = 0
    sport_addr = make_addr(get_tcp_hdr(rip_val, r2), sport_offset)
    sport = get_mem_value(sport_addr, r2)
    return sport

def get_tcp_dport(rip_val, r2):
    """Return the source port for this sk_buff

    destination port is 2 bytes from start of transport header
    """
    dport_offset = 2
    dport_addr = make_addr(get_tcp_hdr(rip_val, r2), dport_offset)
    dport = get_mem_value(dport_addr, r2)
    return dport


def get_tcp_fields(rip_val, r2):
    """

    """
    sport = get_tcp_sport(rip_val, r2)
    dport = get_tcp_dport(rip_val, r2)
    return sport, dport

def get_5tuple(rip_val, r2):
    """
    Extract
    1. IP Layer
    1.1. source IP address
    1.2. destination IP address
    1.3. layer 4 protocol

    2. Layer 4
    2.1. source port
    2.2. destination port
    """
    (saddr, daddr, proto) =  get_ip_fields(rip_val, r2)
    if proto is not PROTO_TCP:
        # Should do something else if the proto isn't tcp, but assume it is for now
        (sport, dport) = get_tcp_fields(rip_val, r2)
    else: # Default to TCP
        (sport, dport) = get_tcp_fields(rip_val, r2)
    return (saddr, daddr, proto, sport, dport)

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
    do_set_sources(r2, conf.get("sources"), conf=conf)
    do_set_sinks(r2, conf.get("sinks"), conf=conf)
    run_loop = True
    pc = getIPname(r2, conf)
    sources = set(["0xffffffff81890880"])
    sinks = set(["0xffffffff81895ba0"])

    r2.cmd("dc") # run the program
    # We will continue until we hit one of the taint sources or sink function(s)
    # for the first time. Then we  have to single step through the execution
    while(run_loop):
        rip_val = r2.cmd("dr {}".format(pc)).strip()
        dprint("rip={}, rip_val in sources={}, rip_val in sinks={}".format(rip_val,
            rip_val in sources, rip_val in sinks), conf=conf)
        if rip_val in sources:
            """
            Current source is:

            int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
                   struct net_device *orig_dev)
            x86_64 calling convention is (rdi, rsi, rdx)
            """
            rdi = r2.cmd("dr rdi")
            five_tuple = get_5tuple(rip_val, r2)
            vdift.DIFT_taint_source_from_5tuple(rip_val, r2, five_tuple, "bytes")
            # vdift.DIFT_taint_source_ip_rcv("register")
        elif rip_val in sinks:
            """
            Current sink is:

            int ip_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)

            x86_64 calling convention is (rdi, rsi, rdx)
            """
            rdx = r2.cmd("dr rdx")
        ao_output, ddict, esil, run_loop, skip = run_ao_command(r2, parser, conf=conf)
        esil_instructions = esil[0]
        dprint('esil_instructions={}'.format(esil_instructions), conf=conf)
        for esil_inst in esil_instructions:
            parser.apply_dependency(esil_inst, r2, vdift, conf=conf)
        # Im not sure why we need to seek to the pc if we're already there...
        r2.cmd("ds;s `dr? {}`".format(pc))
    of.close()
    r2.quit()
    for k, v in vdift.taint.items():
        print("vdift.taint.key =  : {}".format(k))

if __name__=="__main__":
    main()
