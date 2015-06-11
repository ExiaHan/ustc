#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/ip_icmp.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<sys/types.h>

#define BUFFSIZE 1024

int main(){

	int rawsock;
	char buff[BUFFSIZE];
	int n;
	int count = 0;

//	rawsock = socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
//	rawsock = socket(AF_INET,SOCK_RAW,IPPROTO_UDP);
	rawsock = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
	if(rawsock < 0){
		printf("raw socket error!\n");
		exit(1);
	}
	while(1){	
	n = recvfrom(rawsock,buff,BUFFSIZE,0,NULL,NULL);
	if(n<0){
		printf("receive error!\n");
		exit(1);
	}
		
	count++;
	struct ip *ip = (struct ip*)buff;
	printf("%5d	%20s",count,inet_ntoa(ip->ip_src));
	printf("%20s	%5d	%5d\n",inet_ntoa(ip->ip_dst),ip->ip_p,ntohs(ip->ip_len));	
	printf("\n");
}
}	

