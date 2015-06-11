#include<stdio.h>
#include<pcap.h>
#include<unistd.h>
#include<stdlib.h>
//#include<pcap/bpf.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/ether.h>
#include<arpa/inet.h>
#define ETHER_SIZE 14


void get_packet(u_char*args, const struct pcap_pkthdr *header,const u_char *packet){
	
	static int count = 1;
	const char * payload;

	printf("packet number: %d\n",count++);
	
	struct ip * ip = (struct ip *)(packet + ETHER_SIZE);
	printf("IP header length: %d\n",ip->ip_hl<<2);
	printf("From %s\n",inet_ntoa(ip->ip_src));
	printf("To %s\n",inet_ntoa(ip->ip_dst));
	int ip_hl = ip->ip_hl<<2;

	switch(ip->ip_p){

		case IPPROTO_TCP:
		{
			printf("Protocol TCP\n");
			struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + ip_hl);
			int h_size = tcp->doff*4;
			int payload_size = ntohs(ip->ip_len)-ip_hl-h_size;
			if(payload_size>0){
			payload = (u_char *)(tcp+1);
			printf("payload is: %s\n",payload);}			
		break;}
		case IPPROTO_UDP:printf("Protocol UDP\n");break;
		case IPPROTO_ICMP:printf("Protocol ICMP\n");break;
		case IPPROTO_IP:printf("Protocol IP\n");break;
		default:printf("Protocol unknown\n");
		return;

	}
		

}

int main(int argc,char*argv[]){

	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "port 23";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr header;
	const u_char *packet;	
	int num_packets = 10;
	
	dev = pcap_lookupdev(errbuf);
	if(dev==NULL){
		printf("ERROR:%s\n",errbuf);
		exit(2);
	}
	
	printf("The sniff interface is:%s\n",dev);

	
	if(pcap_lookupnet(dev,&net,&mask,errbuf)==-1){
		printf("ERROR:%s\n",errbuf);
		net = 0;
		mask = 0;
	}	

	pcap_t * handle = pcap_open_live(dev,BUFSIZ,1,0,errbuf);
	if(handle == NULL){
		printf("ERROR:%s\n",errbuf);
		exit(2);
	}

	if(pcap_compile(handle,&fp,filter_exp,0,net)==-1){
		printf("Can't parse filter %s:%s\n",filter_exp,pcap_geterr(handle));
		return(2);
	}
		
	if(pcap_setfilter(handle,&fp)==-1){	
		printf("cant' install filter %s:%s\n",filter_exp,pcap_geterr(handle));		      return(2);	
	}	

	printf("Hello\n");	

//	packet = pcap_next(handle,&header);
//	printf("Get a packet with length %d.\n",header.len);

	pcap_loop(handle,num_packets,get_packet,NULL);

	pcap_freecode(&fp);
	


	pcap_close(handle);
	return(0);
}

