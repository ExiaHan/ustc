#ifndef _LAB_H_
#define _LAB_H_
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <pcap.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#define ETHER_SIZE 14
#define LOOPREAD -1
#define HEADERLEN 20
#define TOTALLEN 56

typedef struct bpf_program BPFP;
typedef bpf_u_int32 bpfu32;
typedef u_char uchar;
typedef struct pcap_pkthdr ppthdr;
typedef pcap_t ppt;
typedef struct ip IP;
typedef struct icmphdr icmpHeader;
typedef struct icmp ICMP;
typedef struct tcphdr tcpHeader;
typedef struct udphdr udpHeader;
typedef u_int32_t u4;
typedef u_int8_t u1;
typedef struct sockaddr_in SockAddrIn;
typedef struct sockaddr SockAddr;
typedef struct hostent HostEnt;
typedef struct in_addr InAddr;

void attackHost(uchar *args, const ppthdr  *header, const uchar *packet);
unsigned short in_cksum(unsigned short *addr, int len);
void copyByByte(u1 *s, u1 *d, int len);

#endif
