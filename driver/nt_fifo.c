#include "net_traffic_drv.h"
#include "nt_fifo.h"

net_fifo_ctl *fifo_ctl;
int fifo_clean = 0;

void nt_fifo_refresh(void)
{
    net_pkt_t *base;
    net_pkt_t *curr;
    uint32_t fifo_size;
    uint32_t fifo_pull;

    base = fifo_ctl->fifo_base;
    fifo_size = fifo_ctl->fifo_size;
    
    memset(base, 0x0, sizeof(net_pkt_t)*fifo_size);
    fifo_ctl->fifo_curr = base;
    fifo_ctl->fifo_pull = 0;
}

net_pkt_t *nt_fifo_get_pkt(void)
{
    int i;
    net_pkt_t *base;
    net_pkt_t *curr;
    uint32_t fifo_size;
    uint32_t fifo_pull;

    if (!fifo_ctl || !fifo_ctl->fifo_base)
        return NULL;

    base = fifo_ctl->fifo_base;
    curr = fifo_ctl->fifo_curr;
    fifo_size = fifo_ctl->fifo_size;
    fifo_pull = fifo_ctl->fifo_pull;

    
    if (!curr && fifo_pull == 0) {          // first
        fifo_ctl->fifo_curr = base; 
    } else if (curr && fifo_pull < (fifo_size-1)) {
        fifo_ctl->fifo_curr++;
    } else {
        memset(base, 0x0, sizeof(net_pkt_t)*fifo_size);
        fifo_ctl->fifo_curr = base;
        fifo_ctl->fifo_pull = 0;
    }

    fifo_ctl->fifo_pull++;
    return fifo_ctl->fifo_curr;
}

int nt_fifo_init(const char *mmap_addr)
{
    int i;
    net_pkt_t *p_pkt;
    
    if (!mmap_addr)
        return;
    
    fifo_ctl = mmap_addr;
    fifo_ctl->fifo_size = FIFO_SIZE;
    fifo_ctl->fifo_pull = 0;

    p_pkt = mmap_addr + sizeof(net_fifo_ctl);

    memset(p_pkt, 0x0, sizeof(net_fifo_ctl)*FIFO_SIZE);
    
    fifo_ctl->fifo_base = p_pkt;
    fifo_ctl->fifo_curr = NULL;

    return 0;
}

