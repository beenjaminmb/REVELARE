#!/bin/bash

# Host-based Routing
## Configure ip forarding
sysctl -w net.ipv4.ip_forward=0
##
# ip route add 192.168.123.0/24 scope link dev tap0

iptables -D FORWARD --protocol all --destination 192.168.123.0/24 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -D FORWARD --protocol all --source 192.168.123.0/24 -j ACCEPT

# Chain FORWARD (policy ACCEPT)
# ACCEPT     all  --  anywhere             192.168.122.0/24     ctstate RELATED,ESTABLISHED
# ACCEPT     all  --  192.168.122.0/24     anywhere            


# Chain OUTPUT (policy ACCEPT)
# target     prot opt source               destination         
# ACCEPT     udp  --  anywhere             anywhere             udp dpt:bootpc

