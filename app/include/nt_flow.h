#ifndef __NT_FLOW_H__
#define __NT_FLOW_H__

#define FIFO_SIZE   1024


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

    nt_list _head;
} net_flow_t;

typedef enum {
    def = 0,
    c_to_s,
    s_to_c,
} net_pkt_f;

typedef struct _net_pkt_t {

    uint16_t f_cs:1,
             f_psh:1,
             f_segm:1,
             f_syn:1,
             f_ack;

    uint16_t port;
    uint16_t window;
    uint8_t ip_pkt_median;

    int segm_len;
    int ip_len;
    int eth_len;
    
} net_pkt_t;




typedef struct {

    uint32_t fifo_size;
    uint32_t fifo_pull;

    net_pkt_t *fifo_base;
    net_pkt_t *fifo_curr;
    
} net_fifo_ctl;

#endif /* __NT_FLOW_H__ */
