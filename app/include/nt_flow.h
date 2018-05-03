#include "nt_flow.h"

typedef struct _net_flow_ctl_usr_t{

    int port;           /* server port number A*/

    int init_window_byte_cs;    /* number of bytes in initial window client->server A*/
    int init_window_byte_sc;    /* number of bytes in initial window server->client A*/

    int total_data_pkts_cs;     /* total number of data packets client->server A*/
    int rtt;

    int psh_data_pkts_cs;   /* number of data packet with PUSH bit in TCP header client->server A*/
    int psh_data_pkts_sc;   /* number of data packet with PUSH bit in TCP header server->client A*/

    int min_segm_size_cs;   /* minimum segment size client->server A*/
    int min_segm_size_sc;   /* minimum segment size server->client A*/

    int max_segm_size_sc;   /* maximum segment size server->client A*/

    int max_ip_byte_sc;     /* maximum number of bytes in IP package server->client A*/

    int max_eth_byte_sc;    /* maximum number of bytes in Ethernet package server->client A*/

    uint8_t median_in_ip_cs;    /* median of total bytes in each ip packet client->server A*/

    uint8_t median_in_ctl_cs;   /* median number of control bytes in each packet client->server A*/
    uint8_t median_in_ctl_sc;   /* median number of control bytes in each packet server->client A*/
} net_flow_ctl_usr;

typedef enum {
    def = 0,
    c_to_s,
    s_to_c,
} net_pkt_f;

typedef struct _net_pkt_t {

    net_pkt_f flag;

    uint16_t port;

    int window;

    bool if_psh;

    bool if_segm;

    uint8_t ip_pkt_median;

    int ip_len;

    int eth_len;
    
} net_pkt_t;
