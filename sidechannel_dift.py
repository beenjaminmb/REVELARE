#!/usr/bin/python3
#author EZE
#author 1207
import r2pipe
import sys
from parse_lib import Parser, dprint
import json
import math
#from dift_functions import *
PROTO_TCP = 6
PROTO_UDP = 17

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
            ("protocol" , 2), ("transport_header" , 2), ("network_header" , 2),
            ("mac_header", 2), ("headers_end", 4), ("tail", 8), ("end", 8),
            ("head", 8)]
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
    """WARNING - HARD CODED VALUE - NEEDS CHANGED"""
    # ret = r2.cmd('db 0xffffffff81890880') # Old address
    ret = r2.cmd('db 0xffffffff81945a10')
    dprint('ret={}'.format(ret), conf=conf)

def do_set_sinks(r2, sinks, conf=None):
    # _do_set_breakpoints(r2, sinks, conf=conf)
    do_set_ip_local_out_addr(r2, conf=conf)

def do_set_ip_local_out_addr(r2, conf=None):
    """WARNING - HARD CODED VALUE - NEEDS CHANGED"""
    # ret = r2.cmd('db 0xffffffff81895ba0')
    ret = r2.cmd('db 0xffffffff8194b420')
    dprint('ret={}'.format(ret), conf=conf)

def print_stack(n, r2):
    for i in range(5):
        pxo = r2.cmd("px {} @ esp".format(n))
        if pxo.startswith("- offset -"):
            print(pxo)
            break

def run_ao_command(r2, parser, conf=None):
    ao1 = r2.cmd("aoj")
    e = ''
    run_loop = 1
    skip = 0
    dprint('BEFORE.ao1={}'.format(ao1), conf=conf)
    ao1 = json.loads(ao1)
    dprint('AFTER.ao1={}'.format(ao1), conf=conf)
    if len(ao1) > 1:
        dprint('ao1={}'.format(ao1), conf=conf)
    ao1 = ao1[0] if ao1 else None
    if not ao1:
        dprint("aoj returned nothing...", conf=conf)
    if ao1.get('esil'):
        d = parseao(ao1, conf=conf)
        e = ''
        run_loop = 1
        skip = 0
        dprint('BEFORE: esil in ao1. d.get(esil)={}'.format(d.get('esil')), conf=conf)
        e = parser.parse_esil(d.get('esil'),1)
    else:
        dprint('BEFORE. else . ao1={}'.format(ao1), conf=conf)
        to_continue = 0
        # The fuck is this crap? Why 5?!?!?!?
        for i in range(5):
            dprint('  1. in for loop {} ao1={}'.format(i, ao1), conf=conf)
            ao1 = r2.cmd("aoj")
            ao1 = json.loads(ao1)
            ao1 = ao1[0] if ao1 else None
            dprint(' 2. in for loop {} ao1={}, type()={}'.format(i, ao1, type(ao1)), conf=conf)
            d = parseao(ao1)
            if d.get('esil'):
                dprint('contains esil i={}, d={}'.format(i, d), conf=conf)
                e = parser.parse_esil(d.get('esil'),1) # BEN commented this out
                e = [e] 
                to_continue = 1
                break
            elif d.get('opcode'):
                dprint('contains opcode: i={}, d={}'.format(i, d), conf=conf)
                to_continue = 1
                #print("skipped {}".format(d.get('opcode')))
                e = [e]
                skip = 1
                break
            dprint(' i={}, ao1={}'.format(i, ao1), conf=conf)
        dprint('AFTER for loop else . ao1={}'.format(ao1), conf=conf)

    dprint("AFTER: esil in ao1. d={}, e={}".format(d, e), conf=conf)
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
    dprint('ao1={}, type()={}'.format(ao1, type(ao1)), conf=conf)
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
    addr = addr.strip()
    return hex(int(addr, 16) + offset)


def little_to_big_endian(values):
    """ """
    return list(reversed([v[2:] + v[:2] for v in values]))

def get_mem_value(field_size, addr, r2):
    """Returns the value at the specified memory
    NOTE: Might need to include size or type

    NOTE: radare returns 16 bytes of data per line
    """
    # field size.
    # We always start at 2
    value = r2.cmd("px {} @ {}~:1".format(field_size, addr))
    value = value.strip().split()[1:]
    loops = math.ceil(field_size/2.0)
    values = []
    for i in range(loops):
        values.append(value[i])
    value = little_to_big_endian(values)
    value = "".join(value)
    # Added 0x prepension, might not be correct though.
    value = int("0x" + value, 16)
    return value # Might need to change this if the values are stored in hex

def get_skbuff_data(addr, r2):
    """TODO: Implement this function """
    data_offset = 200
    data_addr = make_addr(addr, data_offset)
    print("data_addr={}".format(data_addr))
    data_field_size = 0
    return None

def get_skbuff_head(addr, r2):
    """ """
    # head_offset = 204
    head_offset = 192
    head_addr = make_addr(addr, head_offset)
    head_addr_field_size = 8 # head is a char * -> 8 bytes on 64 bit OS
    head_value = get_mem_value(head_addr_field_size, head_addr, r2)
    head_value = hex(head_value)
    print('head_value={}'.format(head_value))
    return head_value # Should be a hex value reprensenting the pointer value

def get_ip_hdr(addr, r2):
    """Return the address the ip_hdr is stored at in the sk_buff struct.

    network_header pointer offset is 180 bytes from skb_buff start.
    """
    network_header_offset = 180
    network_header_field_size = 2 # 2 bytes for this field
    skb_head_value = get_skbuff_head(addr, r2)
    network_header_addr = make_addr(addr, network_header_offset)
    network_header_value = get_mem_value(
            network_header_field_size, network_header_addr, r2)
    ip_hdr_addr = make_addr(skb_head_value, network_header_value)
    return ip_hdr_addr

def get_proto(addr, r2):
    """Returns the source address from the addr (sk_buff pointer).

    iph->proto = 9 bytes from start of network header
    """
    proto_offset = 9 # 0x9
    ip_hdr_addr = get_ip_hdr(addr, r2)
    proto_addr = make_addr(ip_hdr_addr, proto_offset)
    proto_field_size = 1 # 1 bytes for this field
    proto = get_mem_value(proto_field_size, proto_addr, r2)
    return proto

def get_saddr(addr, r2):
    """Returns the source address from the addr (sk_buff pointer).

    iph->saddr = 12 bytes from start of network header
    """
    saddr_offset = 12 # 0xC
    ip_hdr_addr = get_ip_hdr(addr, r2)
    saddr_addr = make_addr(ip_hdr_addr, saddr_offset)
    saddr_field_size = 4
    saddr = get_mem_value(saddr_field_size, saddr_addr, r2)
    return saddr

def get_daddr(addr, r2):
    """Returns the destination address from the addr (sk_buff pointer).

    iph->daddr = 16 bytes from start of network header
    """
    daddr_offset = 16 # 0x10
    daddr_addr = make_addr(get_ip_hdr(addr, r2), daddr_offset)
    daddr_field_size = 4
    daddr = get_mem_value(daddr_field_size, daddr_addr, r2)
    return daddr

def get_ip_fields(addr, r2):
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
    proto = get_proto(addr, r2)
    saddr = get_saddr(addr, r2)
    daddr = get_daddr(addr, r2)
    return saddr, daddr, proto


def get_data_len(addr, r2):
    """" """
    data_len_offset = 116 # 0xC
    data_len_addr = make_addr(addr, data_len_offset)
    data_len_field_size = 4
    data_len = get_mem_value(data_len_field_size, data_len_addr, r2)
    return data_len

def get_tcp_hdr(addr, r2):
    transport_header_offset = 178
    transport_header_field_size = 2 # 2 bytes for this field
    skb_head_value = get_skbuff_head(addr, r2)
    transport_header_addr = make_addr(addr, transport_header_offset)
    transport_header_value = get_mem_value(
            transport_header_field_size, transport_header_addr, r2)
    tcp_hdr_addr = make_addr(skb_head_value, transport_header_value)
    return tcp_hdr_addr

def get_tcp_sport(addr, r2):
    """Return the source port for this sk_buff

    source port is 0 bytes from transport header
    """
    sport_offset = 0
    tcp_hdr_addr = get_tcp_hdr(addr, r2)
    sport_addr = make_addr(tcp_hdr_addr, sport_offset)
    sport_field_size = 2
    sport = get_mem_value(sport_field_size, sport_addr, r2)
    return sport

def get_tcp_dport(addr, r2):
    """Return the source port for this sk_buff

    destination port is 2 bytes from start of transport header
    """
    dport_offset = 2
    dport_addr = make_addr(get_tcp_hdr(addr, r2), dport_offset)
    dport_field_size = 2
    dport = get_mem_value(dport_field_size, dport_addr, r2)
    return dport


def get_tcp_fields(addr, r2):
    """

    """
    sport = get_tcp_sport(addr, r2)
    dport = get_tcp_dport(addr, r2)
    return sport, dport

def get_5tuple(addr, r2):
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
    (saddr, daddr, proto) =  get_ip_fields(addr, r2)
    print("saddr={}, daddr={}, proto={}".format(saddr, daddr, proto))
    if proto is not PROTO_TCP:
        # Should do something else if the proto isn't tcp, but assume it is for now
        (sport, dport) = get_tcp_fields(addr, r2)
    else: # Default to TCP
        (sport, dport) = get_tcp_fields(addr, r2)
    return (saddr, daddr, proto, sport, dport)

def get_ip_rcv_skb_addr(r2, conf):
    if conf.get("arch").get("isa") == "x86_64":
        skb_addr = r2.cmd("dr rdi")
    else:
        raise Exception("x86_64 is the only supported architecture, currently.")
    return skb_addr

def taint_source_handler(source, conf):
    """Given a source, return the address pointed to by it's specified parameter(s).
    TODO: Implement this function at some point.
    """
    return None
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
            skb_ptr = get_ip_rcv_skb_addr(r2, conf)
            print("skb_ptr={}".format(skb_ptr))
            five_tuple = get_5tuple(skb_ptr, r2)
            data_len = get_data_len(skb_ptr, r2)
            print("five_tuple={}, data_len={}".format(five_tuple, data_len))
            vdift.DIFT_taint_source_from_5tuple(skb_ptr, r2, five_tuple, "pointer")
            # vdift.DIFT_taint_source_ip_rcv("register")
        elif rip_val in sinks:
            """
            Current sink is:

            int ip_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)

            x86_64 calling convention is (rdi, rsi, rdx)
            """
            rdx = r2.cmd("dr rdx")
            five_tuple = get_5tuple(rdx, r2)
            with open("dift_side_channel_out", "a") as f:
                vdift.DIFT_print_cossim_from_pointer(rdx, length, f)
        ao_output, ddict, esil, run_loop, skip = run_ao_command(r2, parser, conf=conf)
        # Indexing the command in this way assumes all the computation is stored
        # In the tuple, but it currently isn't.
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
