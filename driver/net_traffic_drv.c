#include <net/ip.h>
#include <net/tcp.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/inet.h>
#include <linux/timer.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>



#define CONFIG_NET_TRAFFIC_NETLINK     
//#define CONFIG_NET_TRAFFIC_DEBUG


typedef struct _traffic_entry {
    unsigned int addr;
    unsigned int f_del;
    unsigned long long upload;
    unsigned long long dwload;
    struct list_head list;
} traffic_entry_t;

typedef struct _traffic_entry_s {
    unsigned int addr;
    unsigned long long upload;
    unsigned long long dwload;
} traffic_entry_s;

#ifndef IP_DUMP_FMT
#define IP_DUMP_FMT "%u.%u.%u.%u"
#endif 

#ifndef TCPHDR
#define TCPHDR(skb) ((char*)(skb)->data+iph->ihl*4)
#endif 

#ifndef IP_DUMP
#define IP_DUMP(addr) \
    ((unsigned char *)&addr)[0],\
    ((unsigned char *)&addr)[1],\
    ((unsigned char *)&addr)[2],\
    ((unsigned char *)&addr)[3]
#endif

#ifndef MAX_LOAD
#define MAX_LOAD    0xffffffffffffff00
#endif

#define MSG_NL_TFC_LIST 0x2000  
#define MAX_PAYLOAD_LEN 1024

#define NT_F_DEL    10

#define NT_TIME_VAL     10*1000
#define NT_TIME_INT     5*1000

#define NETLINK_NET_TRAFFIC 29

#define NET_TRAFFIC_PROCFILE    "net_traffic"

static int traffic_netlink_pid = 0;

static struct timer_list traffic_timer;

static struct nf_hook_ops traffic_nf_post_route;

static struct sock *traffic_netlink_sock = NULL;

static struct kmem_cache *traffic_entry_cache = NULL;

static LIST_HEAD(traffic_entry_head);

static int traffic_netlink_send(int type, char *data, int len);



static void _traffic_entry_dump(void)
{
    unsigned long long ul, dl;
    traffic_entry_t *entry;

    printk("addr\t\t\t\tupload\t\tdwload\t\t\n");
    printk("---------------------------------------------------------------\n");

    if (!list_empty(&traffic_entry_head)) {
        list_for_each_entry(entry, &traffic_entry_head, list) {
            ul = (entry->upload > MAX_LOAD) ? 0 : entry->upload;
            dl = (entry->dwload > MAX_LOAD) ? 0 : entry->dwload;
            printk(IP_DUMP_FMT"\t\t\t""%llu\t\t%llu\t\t\t", IP_DUMP(entry->addr), ul, dl);
        }
    }

    printk("\n\n\n");
}

static void traffic_entry_send(void)
{
    traffic_entry_t *entry;
     
    if (!traffic_entry_cache || list_empty(&traffic_entry_head))
        return;
    
    list_for_each_entry(entry, &traffic_entry_head, list) {
        if (!entry->f_del || entry->upload || entry->dwload)
            traffic_netlink_send(MSG_NL_TFC_LIST, (char *)entry, sizeof(traffic_entry_s));
    }
}

static int traffic_entry_need_del(traffic_entry_t *entry)
{
    if (!entry)
        return 0;

    if (entry->f_del == NT_F_DEL)
        return 1;

    if (entry->upload == 0 && entry->dwload == 0) {
        entry->f_del++;
    }   

    return 0;
}

static void traffic_entry_clean(void)
{
    traffic_entry_t *entry;
    traffic_entry_t *tmp;
    
    if (!traffic_entry_cache || list_empty(&traffic_entry_head))
        return;   

    list_for_each_entry_safe(entry, tmp, &traffic_entry_head, list) {

        if(traffic_entry_need_del(entry)) { // for entry has no data traffic, delete it
            list_del(&entry->list);
            kmem_cache_free(traffic_entry_cache, entry);
        } else {         
            entry->upload = 0;
            entry->dwload = 0;
        }
    }
}

static void traffic_timer_proc(void)
{
    int ret = 0;


#ifdef CONFIG_NET_TRAFFIC_DEBUG
    _traffic_entry_dump(); // only for debug
#endif


#ifdef CONFIG_NET_TRAFFIC_NETLINK
    traffic_entry_send();
#endif


    traffic_entry_clean();

    ret = mod_timer(&traffic_timer, jiffies + msecs_to_jiffies(NT_TIME_INT));
    if (ret) printk("traffic mod_timer error\n");
}

static traffic_entry_t *traffic_entry_create(const unsigned int addr)
{
    traffic_entry_t *entry;

    if (!traffic_entry_cache)
        return NULL;

    entry = (traffic_entry_t *)kmem_cache_alloc(traffic_entry_cache, GFP_KERNEL);
    if (!entry) {
        printk("traffic entry create error\n");
        return NULL;
    }

    memset(entry, 0x0, sizeof(traffic_entry_t));
    entry->addr = addr;
    INIT_LIST_HEAD(&entry->list);
    list_add(&entry->list, &traffic_entry_head);

    return entry;
}

static traffic_entry_t *traffic_entry_search(const unsigned int addr)
{
    traffic_entry_t *entry;

    if (!traffic_entry_cache)
        return NULL;

    list_for_each_entry(entry, &traffic_entry_head, list) {
        if (entry->addr == addr)
            return entry;
    }

    return NULL;
}

static void traffic_entry_update(const struct sk_buff *skb, 
                        const struct iphdr *iph,
                        const struct tcphdr *tcph)
{
    int update = 0;
    traffic_entry_t *entry;

    //if (!skb || !iph || !tcph)
	if (!skb || !iph)
        return;

    int tot_len = ntohs(iph->tot_len);
    int iph_len = ip_hdrlen(skb);
    int tcph_len = tcph->doff*4;
    int tcp_load = tot_len - (iph_len + tcph_len);    // use ip totlen, not tcp load

    entry = traffic_entry_search(iph->daddr);
    if (entry) {
        entry->dwload += tot_len;
        if (entry->f_del)
            entry->f_del = 0;
        update++;
    } 
    
    entry = traffic_entry_search(iph->saddr);
    if (entry) {
        entry->upload += tot_len;
        if (entry->f_del)
            entry->f_del = 0;
        update++;
    }

    if (update)
        return;

    entry = traffic_entry_create(iph->saddr);
    if (!entry) {
        printk("traffic entry create error\n");
        return;
    }

    return;
}

static void net_traffic_entry_destory(void)
{
    traffic_entry_t *entry;
    traffic_entry_t *tmp;

    list_for_each_entry_safe(entry, tmp, &traffic_entry_head, list) {
        list_del(&entry->list);
        kmem_cache_free(traffic_entry_cache, entry);
    }

    if (traffic_entry_cache)
        kmem_cache_destroy(traffic_entry_cache);
    return;
}

unsigned int traffic_post_route(unsigned int hooknum,
                            struct sk_buff *__skb,
                            const struct net_device *in,
                            const struct net_device *out,
                            int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph;
    struct sk_buff *skb;
    struct tcphdr *tcph;
    
    skb = __skb;

    if (!skb || !(iph = ip_hdr(skb)))
        return NF_ACCEPT;

    if (iph->protocol == IPPROTO_TCP) {
	//if (iph->protocol) {
        //tcph = (struct tcphdr *)TCPHDR(skb);
        traffic_netlink_send(MSG_NL_TFC_LIST, (char *)skb, sizeof(struct sk_buff));
        //traffic_entry_update(skb, iph, NULL);
    }
    
    return NF_ACCEPT;    
}


#ifdef CONFIG_NET_TRAFFIC_NETLINK
static int group_mask(int group)
{
    return (1 << group);
}

static int traffic_netlink_send(int type, char *data, int len)
{    
    int pid = traffic_netlink_pid;
    unsigned int load = NLMSG_SPACE(len);
    struct sk_buff *skb =  NULL;
    struct nlmsghdr *msgh = NULL;
    struct sock *sock = traffic_netlink_sock;
    
    if(!pid || !sock || !data) {
        return -1;
    } 

    if(data && (len > MAX_PAYLOAD_LEN)) {
        return -1;
    } 
    
    skb = alloc_skb(load, GFP_ATOMIC);
    if(!skb) {
        return -1;
    }
    
    memset((void*)skb, 0, load);
    msgh = nlmsg_put(skb, 0, 0, type, len, 0);
    memcpy(NLMSG_DATA(msgh), data, len);
    
    //NETLINK_CB(skb).pid = 0; /*from kernel */
    NETLINK_CB(skb).dst_group = group_mask(0); 
    
    netlink_unicast(traffic_netlink_sock, skb, 
        traffic_netlink_pid, MSG_DONTWAIT);
    
    return 0;
}

static void traffic_netlink_recv(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = nlmsg_hdr(skb);
    traffic_netlink_pid = nlh->nlmsg_pid;
    printk("traffic_netlink_pid %d\n", traffic_netlink_pid);
}

static void net_traffic_netlink_exit(void)
{
	if (traffic_netlink_sock){
		sock_release(traffic_netlink_sock->sk_socket);
		printk("net traffic netlink exit...\n");
	}
}

static int net_traffic_netlink_init(void)
{
    struct net init_net;

    memset(&init_net, 0x0, sizeof(init_net));

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24))  
    traffic_netlink_sock = netlink_kernel_create(NETLINK_NET_TRAFFIC, 
                                                 0, 
                                                 traffic_netlink_recv, 
                                                 THIS_MODULE); 

#elif (LINUX_VERSION_CODE < KERNEL_VERSION(3, 6, 0))
    traffic_netlink_sock = netlink_kernel_create(&init_net, 
                                        NETLINK_NET_TRAFFIC, 
                                        0, 
                                        traffic_netlink_recv);
#else
    struct netlink_kernel_cfg traffic_netlink_cfg = {
        .input  = traffic_netlink_recv,
    };
    traffic_netlink_sock = netlink_kernel_create(&init_net, 
                                                 NETLINK_NET_TRAFFIC, 
                                                 &traffic_netlink_cfg); 
#endif
    

    if(!traffic_netlink_sock) {
        printk("net traffic netlink init error\n");
        return -1;
    }
	return 0;
}
#endif

static int net_traffic_entry_init(void)
{
    traffic_entry_cache = kmem_cache_create("traffic_entry_cache",
        sizeof(struct _traffic_entry), 0, 0, NULL);
    if (!traffic_entry_cache) {
        printk("net traffic cache create error\n");
        return -1;
    }

    return 0;
}

static int net_traffic_hook_init(void)
{
    int ret;

    //hook at netfilter IP protocol post routing   
    
    traffic_nf_post_route.pf = AF_INET;
    traffic_nf_post_route.hook = traffic_post_route;
    traffic_nf_post_route.priority = NF_IP_PRI_FIRST;
    traffic_nf_post_route.hooknum = NF_INET_POST_ROUTING;   
    ret = nf_register_hook(&traffic_nf_post_route);
    if (ret < 0) {
        printk("net fraffic register post route hook error, ret %d\n", ret);
        return ret;
    } 
    return ret;
}

static int net_traffic_timer_init(void)
{
    int ret;
    
    setup_timer(&traffic_timer, traffic_timer_proc, 0);

    ret = mod_timer(&traffic_timer, jiffies + msecs_to_jiffies(NT_TIME_VAL));
    if (ret < 0) {
        printk("net traffic timer mod_timer error, ret %d\n", ret);
        return ret;
    }   
    return ret;
}


static int __init net_traffic_init(void)
{
    int ret = 0;

    ret = net_traffic_entry_init();
    if (ret < 0) {
        printk("net traffic entry init error, ret %d\n", ret);
        return ret;
    }

    ret = net_traffic_hook_init();
    if (ret < 0) {
        printk("net traffic hook init error, ret %d\n", ret);
        goto out3;       
    }

#ifdef CONFIG_NET_TRAFFIC_NETLINK
    ret = net_traffic_netlink_init();
    if (ret < 0) {
        printk("net fraffic netlink init error, ret %d\n", ret);
        goto out2;  
    }
#endif

    ret = net_traffic_timer_init();
    if (ret < 0) {
        printk("net fraffic timer init error, ret %d\n", ret);
        goto out1;        
    }


    return 0;

out1:
#ifdef CONFIG_NET_TRAFFIC_NETLINK
    net_traffic_netlink_exit();
#endif

out2:
    nf_unregister_hook(&traffic_nf_post_route);
    
out3:
    net_traffic_entry_destory();

    return -1;
}

static void __exit net_traffic_exit(void)
{
    int ret = 0;

    ret = del_timer(&traffic_timer);
    if (ret)
        printk("net traffic timer is still use...\n");

    net_traffic_entry_destory();

    nf_unregister_hook(&traffic_nf_post_route);


#ifdef CONFIG_NET_TRAFFIC_NETLINK
    net_traffic_netlink_exit();
#endif

}

module_init(net_traffic_init);
module_exit(net_traffic_exit);

