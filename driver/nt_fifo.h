#ifndef __NT_FIFO_H__
#define __NT_FIFO_H__






#define FIFO_SIZE   1024

typedef struct {

    uint32_t fifo_size;
    uint32_t fifo_pull;

    net_pkt_t *fifo_base;
    net_pkt_t *fifo_curr;
    
} net_fifo_ctl;



net_pkt_t *nt_fifo_get_pkt(void);
int nt_fifo_init(const char *mmap_addr);
void nt_fifo_refresh(void);

#endif /* __NT_FIFO_H__ */
