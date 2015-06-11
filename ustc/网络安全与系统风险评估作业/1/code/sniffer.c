/*
 * =====================================================================================
 *
 *       Filename:  sniffer.c
 *
 *    Description:  A Simple NetWork Sniffer, only will deal ICMP, TCP and UDP
 *
 *        Version:  1.0
 *        Created:  2015年06月02日 19时15分14秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ExiaHan
 *   Organization:  USTC
 *
 * =====================================================================================
 */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>
#include <limits.h>
#include <pcap.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#define ETHER_SIZE 14
#define LOOPREAD -1

typedef struct bpf_program BPFP;
typedef bpf_u_int32 bpfu32;
typedef u_char uchar;
typedef struct pcap_pkthdr ppthdr;
typedef pcap_t ppt;
typedef struct ip IP;
typedef struct icmphdr icmpHeader;
typedef struct tcphdr tcpHeader;
typedef struct udphdr udpHeader;
typedef u_int32_t u4;
typedef u_int8_t u1;

void dealPacket(uchar *args, const ppthdr  *header, const uchar *packet);
void dealTCP(IP *pscIp);
void dealUDP(IP *pscIp);
void dealICMP(IP *pscIp);
void dealData(u4 uLength, u1 *cStart);

int main(int argc, char **argv)
{
    char *cDev, cErrBuf[PCAP_ERRBUF_SIZE];//PCAP_ERRBUF_SIZE是预先定义好的
    BPFP scBpfp;
    char cFilterExp[] = "icmp";//只抓udp tcp 或者icmp
    bpfu32 uMask, uNet;//掩码啥的
    ppthdr scPpHeader;
    ppt *pHandle;
    const uchar *packet;
    int iNumOfPackets = 0;

    //cDev = pcap_lookupdev(cErrBuf);//查找网络设备
    cDev = argv[1];
    if (!cDev) {
        //printf("[E]: Error when lookup device, info:[%s]\n", cErrBuf);
        printf("[E]: Usage: %s [interface]\n", argv[0]);
        return -1;
    }

    printf("[I]: The sniff interface is [%s]\n", cDev);

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

    pcap_loop(pHandle, LOOPREAD, dealPacket, NULL);
    
    pcap_freecode(&scBpfp);
    pcap_close(pHandle);

    return 0;
}


void dealPacket(uchar *args, const ppthdr  *header, const uchar *packet)
{
    static uint uCount = 0;
    IP *pscIp = (IP *)(packet + ETHER_SIZE);

    printf("=================================================================================================\n");
    printf("[I]: Packet Number: %d\n", uCount);
    uCount = (uCount + 1) % UINT_MAX;
    printf(" |---IP Header Length: %d\n", pscIp->ip_hl << 2);
    printf(" |---IP Total Length: %d\n", ntohs(pscIp->ip_len));
    printf(" |---IP ID: %d\n", pscIp->ip_id);
    printf(" |---IP Don't Fragment: ");
    if (IP_DF & ntohs(pscIp->ip_off))//ntohs 格式转换，下同，大端小端真恶心
        printf("Yes\n");
    else {
        printf("No\n");
        printf(" |---IP MoreFragment: ");
        if (IP_MF & ntohs(pscIp->ip_off))
            printf("Yes\n");
        else
            printf("No\n");
        printf(" |---IP Fragment Offset: %d\n", (IP_OFFMASK & ntohs(pscIp->ip_off)) << 3);
    }
    printf(" |---IP Time To Live: %d\n", pscIp->ip_ttl);
    printf(" |---From: %s\n", inet_ntoa(pscIp->ip_src));
    printf(" |---To: %s\n", inet_ntoa(pscIp->ip_dst));

    switch(pscIp->ip_p) {
        case IPPROTO_TCP:
            dealTCP(pscIp);
            break;
        case IPPROTO_UDP:
            dealUDP(pscIp);
            break;
        case IPPROTO_ICMP:
            dealICMP(pscIp);
            break;
        default:
            printf("[I]: Yo!Yo!Fnial! Not TCP, UDP, ICMP\n");
    }

    printf("=================================================================================================\n");

    return;
}

void dealTCP(IP *pscIp)
{
    u4 uDataLength;
    u1 *cStr;
    tcpHeader *pscHeader = (tcpHeader *)((u1 *)pscIp + pscIp->ip_hl * 4);//计算tcp起始位置
    
    printf("   |---TCP Datagram\n");
    printf("\t|---TCP Source Port: %d ", ntohs(pscHeader->source));
    switch(ntohs(pscHeader->source)) {
        case 21:
            printf("[Ftp]\n");
            break;
        case 22:
            printf("[Ssh]\n");
            break;
        case 23:
            printf("[Telnet]\n");
            break;
        case 53:
            printf("[Dns]\n");
            break;
        case 80:
            printf("[Http]\n");
            break;
        case 443:
            printf("[Https]\n");
            break;
        default:
            printf("\n");
    }
    printf("\t|---TCP Destination Port: %d ", ntohs(pscHeader->dest));
    switch(ntohs(pscHeader->dest)) {
        case 21:
            printf("[Ftp]\n");
            break;
        case 22:
            printf("[Ssh]\n");
            break;
        case 23:
            printf("[Telnet]\n");
            break;
        case 53:
            printf("[Dns]\n");
            break;
        case 80:
            printf("[Http]\n");
            break;
        case 443:
            printf("[Https]\n");
            break;
        default:
            printf("\n");
    }
    printf("\t|---TCP Sequence: %d\n", ntohs(pscHeader->seq));
    printf("\t|---TCP ACK Sequence: %d\n", ntohs(pscHeader->ack_seq));
    printf("\t|---TCP Header Length: %d\n", pscHeader->doff << 2);
    printf("\t|---TCP Reserverd1: %d\n", ntohs(pscHeader->res1));
    printf("\t|---TCP Reserverd2: %d\n", ntohs(pscHeader->res2));
    printf("\t|---TCP URG: %d\n", pscHeader->urg);
    printf("\t|---TCP ACK: %d\n", pscHeader->ack);
    printf("\t|---TCP PSH: %d\n", pscHeader->psh);
    printf("\t|---TCP RST: %d\n", pscHeader->rst);
    printf("\t|---TCP SYN: %d\n", pscHeader->syn);
    printf("\t|---TCP FIN: %d\n", pscHeader->fin);
    printf("\t|---TCP Window Size: %d\n", pscHeader->window);
    printf("\t|---TCP Check: 0x%04x\n", pscHeader->check);
    printf("\t|---TCP Urgent: %d\n", pscHeader->urg_ptr);
    uDataLength = ntohs(pscIp->ip_len) - pscIp->ip_hl * 4 - pscHeader->doff * 4;
    cStr = (u1 *)pscHeader + pscHeader->doff * 4;
    dealData(uDataLength, cStr);

    return;
}

void dealUDP(IP *pscIp)
{
    u4 uDataLength;
    u1 *cStr;
    udpHeader *pscHeader = (udpHeader *)((u1 *)pscIp + pscIp->ip_hl * 4);//计算起始值
    
    printf("   |---UDP Datagram\n");
    printf("\t|---UDP Source Port: %d ", ntohs(pscHeader->source));
    switch(ntohs(pscHeader->source)) {
        case 19:
            printf("[Chargen]\n");
            break;
        case 53:
            printf("[Dns]\n");
            break;
        case 67:
            printf("[Bootps]\n");
            break;
        case 68:
            printf("[Bootpc]\n");
            break;
        case 69:
            printf("[TFTP]\n");
            break;
        case 111:
            printf("[RPC]\n");
            break;
        case 123:
            printf("[NTP]\n");
            break;
        default:
            printf("\n");
    }
    printf("\t|---UDP Destination Port: %d ", ntohs(pscHeader->dest));
    switch(ntohs(pscHeader->dest)) {
        case 19:
            printf("[Chargen]\n");
            break;
        case 53:
            printf("[Dns]\n");
            break;
        case 67:
            printf("[Bootps]\n");
            break;
        case 68:
            printf("[Bootpc]\n");
            break;
        case 69:
            printf("[TFTP]\n");
            break;
        case 111:
            printf("[RPC]\n");
            break;
        case 123:
            printf("[NTP]\n");
            break;
        default:
            printf("\n");
    }
    printf("\t|---UDP Total Length: %d\n", ntohs(pscHeader->len));
    printf("\t|---UDP Check: 0x%04x\n", pscHeader->check);
    uDataLength = ntohs(pscHeader->len) - 8;//udp总长度减去头部固定8字节
    cStr = (u1 *)pscHeader + 8;
    dealData(uDataLength, cStr);

    return;
}

void dealICMP(IP *pscIp)
{
    u1 *ipdot;
    u4 uDataLength;
    u1 *cStr;
    icmpHeader *pscHeader = (icmpHeader *)((u1 *)pscIp + pscIp->ip_hl * 4);//根据IP Header长度算出ICMP报文起始
    switch(pscHeader->type){
        case ICMP_ECHOREPLY:
            printf("   |---ICMP_ECHOREPLY\n");
            printf("\t|---CHECKSUM: 0x%x\n", pscHeader->checksum);
            printf("\t|---ID: 0x%x\n", pscHeader->un.echo.id);
            printf("\t|---Seq: 0x%x\n", pscHeader->un.echo.sequence);
            uDataLength = ntohs(pscIp->ip_len) - pscIp->ip_hl * 4 - 8;//8 是ICMP头
            cStr = (u1 *)pscHeader + 8;//根据icmp报文头长度算出data起始，头大小根据类型变化，不一定是8
            dealData(uDataLength, cStr);
            break;
        case ICMP_ECHO:
            printf("   |---ICMP_ECHO\n");
            printf("\t|---CHECKSUM: 0x%x\n", pscHeader->checksum);
            printf("\t|---ID: 0x%x\n", pscHeader->un.echo.id);
            printf("\t|---Seq: 0x%x\n", pscHeader->un.echo.sequence);
            uDataLength = ntohs(pscIp->ip_len) - pscIp->ip_hl * 4 - 8;//8 是ICMP头
            cStr = (u1 *)pscHeader + 8;
            dealData(uDataLength, cStr);
            break;
        case ICMP_DEST_UNREACH:
            printf("   |---ICMP_DEST_UNREACH\n");
            printf("\t|---CHECKSUM: 0x%x\n", pscHeader->checksum);
            printf("\t|---ID: 0x%x\n", pscHeader->un.echo.id);
            printf("\t|---Seq: 0x%x\n", pscHeader->un.echo.sequence);
            uDataLength = ntohs(pscIp->ip_len) - pscIp->ip_hl * 4 - 8;//8 是ICMP头
            cStr = (u1 *)pscHeader + 8;
            dealData(uDataLength, cStr);
            break;
        case ICMP_REDIRECT:
            printf("   |---ICMP_REDIRECT\n");
            printf("\t|---CHECKSUM: 0x%x\n", pscHeader->checksum);
            ipdot = (u1 *)(&(pscHeader->un.gateway));
            printf("\t|---ICMP GateWay IP Address: %d.%d.%d.%d\n", *ipdot, *(ipdot + 1), *(ipdot + 2), *(ipdot + 3));
            uDataLength = ntohs(pscIp->ip_len) - pscIp->ip_hl * 4 - 8;//8 是ICMP头
            cStr = (u1 *)pscHeader + 8;
            dealData(uDataLength, cStr);
            break;
        default:
            printf("   |---ICMP OTHER TYPE: [%d]\n", pscHeader->type);
            printf("\t|---CHECKSUM: 0x%x\n", pscHeader->checksum);
            uDataLength = ntohs(pscIp->ip_len) - pscIp->ip_hl * 4 - 8;//8 是ICMP头
            cStr = (u1 *)pscHeader + 8;
            dealData(uDataLength, cStr );
    }
    return;
}

//格式化Data打印函数，传入参数为Data长度和起始位置，u1为usigned int 8类型
void dealData(u4 uLength, u1 *cStart)
{
    int iLine= 0, iCount = 0, i = 0;
    char *c = cStart;
    char cStr[16];
    u1 data[16];

    if(!uLength) {//没有数据，退出
        printf("\t|---Data: No DATA\n");
        return;
    }
    printf("\t|---Data:");
    while(uLength) {
        if (iCount == 16) {
            iCount = 0;
            printf(" ");
            for (i = 0; i < 16; i++){
                if (i == 7)
                    printf(" ");
                printf("%02x ", data[i]);
            }
            for (i = 0; i < 16; i++)
                printf("%c", cStr[i]);

        }

        if (!(iLine % 16))
            printf("\n\t  |---%04x: ", iLine);

        data[iCount] = (u1)(*c);
        if (isprint(*c) && *c != ' ')
            cStr[iCount] = *c;
        else
            cStr[iCount] = '.';
        c++, iLine++, uLength--, iCount++;
    }
    if (iCount) {
        printf(" ");
        for (i = 0; i < 16; i++){
            if (i == 7)
                printf(" ");
            if (i < iCount)
                printf("%02x ", data[i]);
            else
                printf("   ");
        }
        for (i = 0; i < iCount; i++)
            printf("%c", cStr[i]);
    }
    printf("\n");
    return;
}
