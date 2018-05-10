
#include "net_traffic_drv.h"
#include "nt_netlink.h"
#include "nt_fifo.h"

#define CONFIG_PROC
//#define CONFIG_NETLINK     
//#define CONFIG_DEBUG


#ifdef CONFIG_PROC
#define NET_TRAFFIC_PROCFILE    "net_traffic"
static char *mmap_mem = NULL;
#define MMAP_MEM_SIZE (PAGE_SIZE * 8)  
#endif

extern net_fifo_ctl *fifo_ctl;
extern int fifo_clean;

static struct timer_list traffic_timer;

static struct nf_hook_ops traffic_nf_post_route;

static struct nf_hook_ops traffic_nf_pre_route;

static struct kmem_cache *traffic_entry_cache = NULL;

static LIST_HEAD(traffic_entry_head);


int nt_skb_receive(const struct sk_buff *skb, 
                         const struct iphdr *iph,
                         const struct tcphdr *tcph,
                         net_pkt_f flag);




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

        if (!entry->f_del || entry->upload || entry->dwload) {
            
#ifdef CONFIG_NETLINK
            traffic_netlink_send(MSG_NL_TFC_LIST, (char *)entry, sizeof(traffic_entry_s));
#endif
        }
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

#ifdef CONFIG_DEBUG
    _traffic_entry_dump(); // only for debug
#endif

    printk("TIMER : fifo pull %d\n", fifo_ctl->fifo_pull);

#ifdef CONFIG_NETLINK
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
        tcph = (struct tcphdr *)TCPHDR(skb);
        nt_skb_receive(skb, iph, tcph, c_to_s);
        //traffic_netlink_send(MSG_NL_TFC_LIST, (char *)skb, sizeof(struct sk_buff));
        //traffic_entry_update(skb, iph, NULL);
    }
    
    return NF_ACCEPT;    
}

int skb_is_segm(const struct sk_buff *skb)
{
    if (skb->data[46] == 0)
        return 0;
    else 
        return 1;
}

int nt_skb_receive(const struct sk_buff *skb, 
                         const struct iphdr *iph,
                         const struct tcphdr *tcph,
                         net_pkt_f flag)
{
    net_pkt_t *pkt;

    if (!skb || !iph)
        return -1;

    if (fifo_clean) {
        fifo_clean = 0;
        nt_fifo_refresh();
    }

    pkt = nt_fifo_get_pkt();
    if (!pkt)
        return 0;

    if (flag == s_to_c) {
        pkt->f_cs = 0;
        pkt->port = ntohs(tcph->source);
    } else if (flag = c_to_s) {
        pkt->f_cs = 1;
        pkt->port = ntohs(tcph->dest);
    }

    pkt->window = ntohs(tcph->window);

    pkt->f_psh = tcph->psh;
    pkt->f_segm = skb_is_segm(skb);
    pkt->f_syn = tcph->syn;
    pkt->f_ack = tcph->ack;

    if (pkt->f_segm) {
        pkt->segm_len = skb->data[46];
    }

    pkt->eth_len = skb->len;

    pkt->ip_len = ntohs(iph->tot_len);

    /*
    printk("port %d\n", pkt->port);
    printk("ip_len %d\n", pkt->ip_len);
    printk("eth_len %d\n", pkt->eth_len);
    printk("window %d\n", pkt->window);
    printk("\n", pkt->port);
    */
}

unsigned int traffic_pre_route(unsigned int hooknum,
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
        tcph = (struct tcphdr *)tcp_hdr(skb);
        nt_skb_receive(skb, iph, tcph, s_to_c);
    }

    return NF_ACCEPT;    
}

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
    traffic_nf_pre_route.pf = AF_INET;
    traffic_nf_pre_route.hook = traffic_pre_route;
    traffic_nf_pre_route.priority = NF_IP_PRI_FIRST;
    traffic_nf_pre_route.hooknum = NF_INET_PRE_ROUTING;
    ret = nf_register_hook(&traffic_nf_pre_route);
    if (ret < 0) {
        printk("net fraffic register pre route hook error, ret %d\n", ret);
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

#ifdef CONFIG_PROC

static int proc_mmap(struct file *filp, struct vm_area_struct *vma)  
{
    int ret;
    struct page *page = NULL;
    unsigned long size = (unsigned long)(vma->vm_end - vma->vm_start); 

    if (size > MMAP_MEM_SIZE)  
    {  
        ret = -EINVAL;  
        goto err;  
    } 

    page = virt_to_page((unsigned long)mmap_mem + (vma->vm_pgoff << PAGE_SHIFT));
    ret = remap_pfn_range(vma, 
                          vma->vm_start, 
                          page_to_pfn(page), 
                          size, 
                          vma->vm_page_prot);
    //nt_fifo_refresh();
    fifo_clean = 1;
    if (ret)
        goto err;
    
    return 0;
    
err:
    return ret;
}

static struct file_operations proc_fops =  
{  
    .owner = THIS_MODULE,  
    .mmap = proc_mmap,  
};  

static int net_traffic_proc_init(void)
{
    int i;
    uint32_t fifo_size;
    uint32_t fifo_control_size;

    mmap_mem = kmalloc(MMAP_MEM_SIZE, GFP_KERNEL);
     if (!mmap_mem) {
        printk("kmalloc error\n");
        return -1;
    }

    fifo_control_size = sizeof(net_fifo_ctl);
    fifo_size = sizeof(net_pkt_t)*FIFO_SIZE;

    printk("fifo_control_size %d, fifo_size %d\n", fifo_control_size, fifo_size);
    printk("mem size %d\n", MMAP_MEM_SIZE);

    nt_fifo_init(mmap_mem);

    struct proc_dir_entry *proc_file = 
        proc_create(NET_TRAFFIC_PROCFILE, 0x0644, NULL, &proc_fops);

    
    return 0;  
}

static void net_traffic_proc_exit(void)
{
    int i;

    if (mmap_mem) {
        kfree(mmap_mem);
    }

    remove_proc_entry(NET_TRAFFIC_PROCFILE, NULL);  
}
#endif

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
        goto out4;       
    }

#ifdef CONFIG_NETLINK
    ret = net_traffic_netlink_init();
    if (ret < 0) {
        printk("net fraffic netlink init error, ret %d\n", ret);
        goto out3;  
    }
#endif

#ifdef CONFIG_PROC
    ret = net_traffic_proc_init();
    if (ret < 0) {
        printk("net traffic proc init error, ret %d\n", ret);
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
#ifdef CONFIG_PROC
    net_traffic_proc_exit();
#endif
  

out2:
#ifdef CONFIG_NETLINK
    net_traffic_netlink_exit();
#endif


out3:
    nf_unregister_hook(&traffic_nf_post_route);
    nf_unregister_hook(&traffic_nf_pre_route);
    
out4:
    net_traffic_entry_destory();


    return -1;
}

static void __exit net_traffic_exit(void)
{
    int ret = 0;

    ret = del_timer(&traffic_timer);
    if (ret)
        printk("net traffic timer is still use...\n");


#ifdef CONFIG_PROC
    net_traffic_proc_exit();
#endif

#ifdef CONFIG_NETLINK
    net_traffic_netlink_exit();
#endif   

    net_traffic_entry_destory();

    nf_unregister_hook(&traffic_nf_post_route);
    nf_unregister_hook(&traffic_nf_pre_route);
}

module_init(net_traffic_init);
module_exit(net_traffic_exit);

 