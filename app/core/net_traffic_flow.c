#include "nt_core.h"
#include "nt_flow.h"
#include "nt_mgr.h"

nt_ret nt_flow_init(nt_run_mgr *mgr)
{
    FILE *fp = NULL;
    char line[128] = {'\0'};

    mgr->save_file = nt_string_dup("data/flow_save.dat");

    fp = fopen(mgr->save_file, "a+");
    if (!fp) {
        nt_err("fopen %s error", mgr->save_file);
        return nt_err_file_open;
    }

    fgets(line, 128, fp);
    if (strstr(line, "flow save file")) {
        nt_debug("find head");
        goto file_close;
    }

    fseek(fp, 0, SEEK_SET);

    sprintf(line, "flow save file\n");
    fputs(line, fp);
    memset(line, 0x0, 128);

    sprintf(line, "[Characteristics]:\n");
    fputs(line, fp);
    memset(line, 0x0, 128);

    sprintf(line, "[Character 1] <port> : server port\n");
    fputs(line, fp);
    memset(line, 0x0, 128);    

    sprintf(line, "[Character 2] <tlt_pkts> : total number of data packets\n");
    fputs(line, fp);
    memset(line, 0x0, 128); 

    sprintf(line, "[Character 3] <init_win_cs> : number of bytes in initial window client->server\n");
    fputs(line, fp);
    memset(line, 0x0, 128); 

    sprintf(line, "[Character 4] <init_win_sc> : number of bytes in initial window server->client\n");
    fputs(line, fp);
    memset(line, 0x0, 128); 

    sprintf(line, "[Character 5] <min_sgm_cs> : minimum segment size client->server\n");
    fputs(line, fp);
    memset(line, 0x0, 128); 

    sprintf(line, "[Character 6] <min_sgm_sc> : minimum segment size server->client\n");
    fputs(line, fp);
    memset(line, 0x0, 128);    

    sprintf(line, "[Character 7] <max_sgm_cs> : maximum segment size client->server\n");
    fputs(line, fp);
    memset(line, 0x0, 128);    

    sprintf(line, "[Character 8] <max_sgm_sc> : maximum segment size server->client\n");
    fputs(line, fp);
    memset(line, 0x0, 128);

    sprintf(line, "[Character 9] <max_ip_cs> : maximum number of bytes in IP package client->server\n");
    fputs(line, fp);
    memset(line, 0x0, 128);    

    sprintf(line, "[Character 10] <max_ip_sc> : maximum number of bytes in IP package server->client\n");
    fputs(line, fp);
    memset(line, 0x0, 128); 

    sprintf(line, "[Character 11] <psh_ack_cs> : number of data packet with PUSH bit in TCP header client->server\n");
    fputs(line, fp);
    memset(line, 0x0, 128);     

    sprintf(line, "[Character 12] <psh_ack_sc> : number of data packet with PUSH bit in TCP header server->client\n");
    fputs(line, fp);
    memset(line, 0x0, 128);

    sprintf(line, "[Character 13] <sgm_ack_cs> : number of segments cumulatively acknowledged client->server\n");
    fputs(line, fp);
    memset(line, 0x0, 128);    

    sprintf(line, "[Character 14] <sgm_ack_sc> : number of segments cumulatively acknowledged server->client");
    fputs(line, fp);
    memset(line, 0x0, 128);

    sprintf(line, "\n\n[Data]:\n");
    fputs(line, fp);
    memset(line, 0x0, 128);

file_close:   
    if (fp != NULL) 
        fclose(fp);
    
    NT_LIST_HEAD_IN_STRUCT_INIT(mgr->flow_list);
    
    return nt_ok;
}

void nt_flow_fill_cs(net_flow_t *flow, net_pkt_t *pkt)
{
    // init window
    if (pkt->f_syn && flow->init_win_byte_cs == 0) {
        flow->init_win_byte_cs = pkt->window;
    }

    // max bytes in ip
    flow->max_bytes_in_ip_cs = (pkt->ip_len > flow->max_bytes_in_ip_cs) ? 
                                pkt->ip_len : flow->max_bytes_in_ip_cs;

    // max min segment size
    if (pkt->f_segm) {
        flow->max_segm_cs = (pkt->segm_len > flow->max_segm_cs) ?
                             pkt->segm_len : flow->max_segm_cs;

        if (flow->min_segm_cs == 0) {
            flow->min_segm_cs = pkt->segm_len;
        } else {
            flow->min_segm_cs = (pkt->segm_len < flow->min_segm_cs) ?
                                 pkt->segm_len : flow->min_segm_cs;
        }

    }

    // psh counter
    if (pkt->f_psh) {
        flow->psh_data_pkts_cs++;
    }

    // segm ack counter
    if (pkt->f_ack) {
        flow->segm_ack_cum_cs++;
    }
}

void nt_flow_fill_sc(net_flow_t *flow, net_pkt_t *pkt)
{
    // init window
    if (pkt->f_syn && flow->init_win_byte_sc == 0) {
        flow->init_win_byte_sc = pkt->window;
    }    

    // max bytes in ip
    flow->max_bytes_in_ip_sc = (pkt->ip_len > flow->max_bytes_in_ip_sc) ? 
                                pkt->ip_len : flow->max_bytes_in_ip_sc;    

    // max segment size
    if (pkt->f_segm) {
        flow->max_segm_sc = (pkt->segm_len > flow->max_segm_sc) ?
                             pkt->segm_len : flow->max_segm_sc;
        
        if (flow->min_segm_sc == 0) {
            flow->min_segm_sc = pkt->segm_len;
        } else {
            flow->min_segm_sc = (pkt->segm_len < flow->min_segm_sc) ?
                                 pkt->segm_len : flow->min_segm_sc;
        }

    }

    // psh counter
    if (pkt->f_psh) {
        flow->psh_data_pkts_sc++;
    }    

    // segm ack counter
    if (pkt->f_ack) {
        flow->segm_ack_cum_sc++;
    }    
}

nt_ret nt_flow_add_withpkt(net_pkt_t *pkt, nt_run_mgr *mgr)
{
    net_flow_t *new_flow;

    new_flow = nt_mem_alloc_z(sizeof(net_flow_t));
    if (!new_flow) {
        nt_err("alloc flow error");
        return nt_err_nomem;
    }

    new_flow->port = pkt->port;

    new_flow->total_data_pkts = 1;

    if (pkt->f_cs) {
        nt_flow_fill_cs(new_flow, pkt);
    } else {
        nt_flow_fill_sc(new_flow, pkt);
    }

    nt_list_append(&new_flow->_head, &mgr->flow_list);

    return nt_ok;
}

nt_ret nt_flow_update_withpkt(net_pkt_t *pkt, net_flow_t *flow)
{
    flow->total_data_pkts++;

    if (pkt->f_cs) {
        nt_flow_fill_cs(flow, pkt);
    } else {
        nt_flow_fill_sc(flow, pkt);
    }    

    return nt_ok;
}

nt_ret nt_flow_pull_pkt(net_pkt_t *pkt, nt_run_mgr *mgr)
{
    net_flow_t *flow;
    bool find = FALSE;

    // first find flow
    nt_list_for_each_entry(flow, &mgr->flow_list, _head) {
        if (flow->port == pkt->port) {
            find = TRUE;
            break;
        }
    }

    if (!find) {
        return nt_flow_add_withpkt(pkt, mgr);
    } else {
        return nt_flow_update_withpkt(pkt, flow);
    }
}

bool nt_flow_pkt_invalid(net_pkt_t *pkt)
{
    if (!pkt)
        return TRUE;

    if (pkt->port == 0)
        return TRUE;

    return FALSE;
}

void nt_flow_print(nt_run_mgr *mgr)
{
    net_flow_t *flow;


    nt_debug("*************** flow print **************");
    nt_list_for_each_entry(flow, &mgr->flow_list, _head) {
        nt_info("port : %d", flow->port);
        nt_info("total pkts : %d", flow->total_data_pkts);
        nt_info("init window : %d, %d", flow->init_win_byte_cs, flow->init_win_byte_sc);
        nt_info("max byte in ip : %d, %d", flow->max_bytes_in_ip_cs, flow->max_bytes_in_ip_sc);
        nt_info("max byte in segm : %d, %d", flow->max_segm_cs, flow->max_segm_sc);
        nt_info("min byte in segm : %d, %d", flow->min_segm_cs, flow->min_segm_sc);
        nt_info("psh pkts : %d, %d", flow->psh_data_pkts_cs, flow->psh_data_pkts_sc);
        nt_info("segm ack pkts : %d, %d", flow->segm_ack_cum_cs, flow->psh_data_pkts_sc);
        nt_info("\n");
    }
    nt_debug("*****************************************");
}

nt_ret nt_flow_process(net_fifo_ctl *fifo_ctl, nt_run_mgr *mgr)
{
    int i;
    net_pkt_t *base;
    net_pkt_t *p_pkt;
    uint32_t fifo_size;
    uint32_t fifo_pull;
    nt_ret ret = nt_ok;

    fifo_size = fifo_ctl->fifo_size;
    fifo_pull = fifo_ctl->fifo_pull;

    base = (net_pkt_t *)(fifo_ctl+1);

    for (i=0; i<fifo_pull; i++)
    {
        p_pkt = base + i;

        if (nt_flow_pkt_invalid(p_pkt))
            continue;

        ret = nt_flow_pull_pkt(p_pkt, mgr);
        if (nt_ok != ret)
        {
            nt_err("pull pkt error");
            return nt_err_flow_pull;
        }
    }

    //nt_flow_print(mgr);

    return nt_ok;
}

nt_ret nt_flow_save(nt_run_mgr *mgr)
{
    FILE *fp = NULL;
    net_flow_t *flow;
    char line[512] = {"\0"};

    fp = fopen(mgr->save_file, "a+");
    if (!fp) {
        nt_err("fopen %s error", mgr->save_file);
        return nt_err_file_open;
    }

    nt_list_for_each_entry(flow, &mgr->flow_list, _head) {

        sprintf(line, "%8d, %8d, %8d, %8d, %8d, %8d, %8d, %8d, %8d, %8d, %8d, %8d, %8d, %8d, [%5s]\n", 
                flow->port,
                flow->total_data_pkts,
                flow->init_win_byte_cs,
                flow->init_win_byte_sc,
                flow->min_segm_cs,
                flow->min_segm_sc,
                flow->max_segm_cs,
                flow->max_segm_sc,
                flow->max_bytes_in_ip_cs,
                flow->max_bytes_in_ip_sc,
                flow->psh_data_pkts_cs,
                flow->psh_data_pkts_sc,
                flow->segm_ack_cum_cs,
                flow->segm_ack_cum_sc,
                mgr->param->fcls);
                
        fputs(line, fp);
        memset(line, 0x0, 256);     
    }

    if (fp)
        fclose(fp);

    return nt_ok;
}

void nt_flow_pkt_save(net_fifo_ctl *ctl)
{   
    int i;
    FILE *fp = NULL;
    char line[256] = {"\0"};    
    net_pkt_t *pkt;
    net_pkt_t *base;

    base = (net_pkt_t *)(ctl+1);

    fp = fopen("data/pkt_file", "a+");
    if (!fp) {
        nt_err("fopen data/pkt_file error");
        return nt_err_file_open;
    }   
    
    nt_debug("fifo_pull %d", ctl->fifo_pull);
    sprintf(line, "\n\nfifo_pull %d\n", ctl->fifo_pull);
    fputs(line, fp);
    memset(line, 0x0, 256);  

    for (i=0; i<ctl->fifo_pull; i++)
    {
        pkt = base + i;
        sprintf(line, "%5d, %5d, %5d, %5d, %5d, %5d, %5d, %5d\n",
            pkt->port,
            pkt->f_ack,
            pkt->f_cs,
            pkt->f_psh,
            pkt->f_segm,
            pkt->f_syn,
            pkt->segm_len,
            pkt->window);
        fputs(line, fp);
        memset(line, 0x0, 256);
        nt_debug("%5d, %5d, %5d, %5d, %5d, %5d, %5d, %5d",
            pkt->port,
            pkt->f_ack,
            pkt->f_cs,
            pkt->f_psh,
            pkt->f_segm,
            pkt->f_syn,
            pkt->segm_len,
            pkt->window);
    } 
    
    if (fp)
        fclose(fp);

    return nt_ok;
}