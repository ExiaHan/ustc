/*
 * =====================================================================================
 *
 *       Filename:  addrtoString.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2015年06月28日 02时30分16秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef uint8_t u1;

char *addrToString(unsigned int addr);

int main(int argc, char **argv)
{
    unsigned int addr;
    scanf("%u", &addr);
    printf("%s", addrToString(addr));
}

char *addrToString(unsigned int addr)
{
    int i, j, tmp, s, n;
    char *caddr;
    u1 *pByte = (u1 *)&addr + 3;

    caddr = (char *)malloc(17);
    i = j = 0;
    while (i < 4){
        n = 100;
        tmp = *pByte;
        while(tmp != 0){
            s = tmp / n;
            if (s != 0){
                caddr[j] = s + '0';
                j++;
            }
            tmp = tmp % n;
            n /= 10;
        }
        caddr[j++] = '.';
        pByte--;
        i++;
    }
    caddr[--j] = '\0';
    return caddr;
}
