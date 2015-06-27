#!/bin/bash

echo 1 > /proc/sys/net/ipv4/ip_forward

iptables -F

iptables -A INPUT -p tcp -i eth0 --dport 23 -j DROP
