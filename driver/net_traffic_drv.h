#ifndef __NET_TRAFFIC_DRV_H__
#define __NET_TRAFFIC_DRV_H__


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
#include <linux/proc_fs.h> 
#include <linux/fs.h>

#include <linux/string.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/in.h>
#include <linux/tty.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>
#include <linux/if_slip.h>
#include <linux/init.h>

#include <linux/proc_fs.h>
#include <linux/fs.h>

typedef struct _net_flow_ctl_knl_t{

    int port;           /* server port number */

    int init_win_byte_cs;    /* number of bytes in initial window client->server */
    int init_win_byte_sc;    /* number of bytes in initial window server->client */

    int rtt_cs;         /* total number of Round-Trip Time(RTT) samples client->server */
    int rtt_sc;         /* total number of Round-Trip Time(RTT) samples server->client */

    int min_segm_cs;    /* minimum segment size client->server */
    int min_segm_sc;    /* minimum segment size server->client */

    int max_segm_cs;    /* maximum segment size client->server */
    int max_segm_sc;    /* maximum segment size server->client */

    int mean_segm_cs;   /* mean number size client->server */
    int mean_segm_sc;   /* mean number size server->client */

    int total_data_pkts;    /* total number of data packets */

    int psh_data_pkts_cs;   /* number of data packet with PUSH bit in TCP header client->server */
    int psh_data_pkts_sc;   /* number of data packet with PUSH bit in TCP header server->client */

    int segm_ack_cum_cs;    /* number of segments cumulatively acknowledged client->server */
    int segm_ack_cum_sc;    /* number of segments cumulatively acknowledged server->client */

    int median_in_ip_pkt_cs;    /* median of total bytes in each ip packet client->server */
    int median_in_ip_pkt_sc;    /* median of total bytes in each ip packet server->client */

    int control_bytes_cs;       /* control bytes number in each packet client->server */
    int control_bytes_sc;       /* control bytes number in each packet client->server */

    int max_bytes_in_ip_cs;     /* maximum number of bytes in IP package client->server */
    int max_bytes_in_ip_sc;     /* maximum number of bytes in IP package server->client */

    int median_ctl_in_pkt_cs;   /* median number of control bytes in each packet client->server */
    int median_ctl_in_pkt_sc;   /* median number of control bytes in each packet server->client */
} net_flow_ctl_knl_t;


#endif /* __NET_TRAFFIC_DRV_H__ */
