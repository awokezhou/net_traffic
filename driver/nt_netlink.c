#include "net_traffic_drv.h"


#ifdef CONFIG_NETLINK
#define NETLINK_NET_TRAFFIC 29
static int traffic_netlink_pid = 0;
static struct sock *traffic_netlink_sock = NULL;
#endif



#ifdef CONFIG_NETLINK
static int group_mask(int group)
{
    return (1 << group);
}

int nt_netlink_send(int type, char *data, int len)
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

void nt_netlink_recv(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = nlmsg_hdr(skb);
    traffic_netlink_pid = nlh->nlmsg_pid;
    printk("traffic_netlink_pid %d\n", traffic_netlink_pid);
}

void nt_traffic_netlink_exit(void)
{
	if (traffic_netlink_sock){
		sock_release(traffic_netlink_sock->sk_socket);
		printk("net traffic netlink exit...\n");
	}
}

int nt_traffic_netlink_init(void)
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

