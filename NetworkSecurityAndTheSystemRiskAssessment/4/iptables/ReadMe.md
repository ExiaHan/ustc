#说明

##一
local里的a.sh和b.sh是iptables问题a和b的脚本，执行时需要root，要看懂需要明白表(filter，nat)和四个chain(input，output，prerouting，postrouting)都是怎么用的

##二
client和host分别是问题3里client和server(host)的配置，问题大意是host有ssh可以访问，但是telent只能本机访问，所以需要在client上通过iptables和ssh转发和创建一个远程绑定，把对方的23端口和本地的某个端口绑定后即可实现telnet通信
