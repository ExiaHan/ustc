#!/bin/bash

#TsingHua
dest_ip="166.111.4.100"
#ustc_ip
#dest_ip="218.22.21.21"
src_ip="192.168.42.100"
proxy_ip="192.168.42.45"
echo 1 > /proc/sys/net/ipv4/ip_forward

#add our rules to set a proxy to www.baidu.com

#flush iptables
iptables -t nat -F

iptables -t nat -A PREROUTING -d $proxy_ip -p tcp -m tcp --dport 6666  -j DNAT --to-destination $dest_ip:80

iptables -t nat -A POSTROUTING -s $src_ip -p tcp -m tcp -j SNAT --to-source $proxy_ip
#below can replace above
#iptables -t nat -A POSTROUTING -d $dest_ip -p tcp -m tcp -j SNAT --to-source $proxy_ip


iptables -t nat -A PREROUTING -d $proxy_ip -p tcp -m tcp --sport 80 -j DNAT --to-destination $src_ip

iptables -t nat -A POSTROUTING -s $dest_ip -p tcp -m tcp -j SNAT --to-source $proxy_ip:6666
#blow can replace above
#iptables -t nat -A POSTROUTING -d $src_ip  -p tcp -m tcp -j SNAT --to-source $proxy_ip:6666
