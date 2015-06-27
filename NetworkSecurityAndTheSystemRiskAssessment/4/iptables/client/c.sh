#!/bin/bash

local_ip="192.168.42.45"
remote_ip="192.168.42.100"
dest_port="23"
local_port="2333"

echo 1 > /proc/sys/net/ipv4/ip_forward

iptables -t nat -F

iptables -t nat -A OUTPUT -d $local_ip -p tcp -m tcp --dport $dest_port -j DNAT --to-destination $local_ip:$local_port

