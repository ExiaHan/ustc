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

#endif
