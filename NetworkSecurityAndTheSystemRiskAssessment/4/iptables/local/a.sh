#!/bin/bash

#localhost can access outer, but outer can not start a new connect to locaohost

iptables -F
iptables -X
iptables -Z
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 
iptables -A INPUT -p icmp --icmp-type 0 -j ACCEPT
iptables -A INPUT -m state --state INVALID,new -j ACCEPT 
