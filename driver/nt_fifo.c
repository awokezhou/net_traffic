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
    fifo_ctl->fifo_curr = NULL;
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
    } else {                                // fifo full
        //printk("fifo full\n");
        memset(base, 0x0, sizeof(net_pkt_t)*fifo_size);
        fifo_ctl->fifo_curr = base;
        fifo_ctl->fifo_pull = 0;
    }

    fifo_ctl->fifo_pull++;
    return fifo_ctl->fifo_curr;
}

void nt_fifo_print()
{
    int i;
    net_pkt_t *pkt;
    net_pkt_t *base;
    uint32_t fifo_size;
    uint32_t fifo_pull;

    base = fifo_ctl->fifo_base;
    fifo_pull = fifo_ctl->fifo_pull;

    printk("\n\nfifo pull %d\n", fifo_pull);
    for (i=0; i<fifo_pull; i++)
    {
        pkt = base+i;
        printk("%5d, %5d, %5d, %5d, %5d, %5d, %5d, %5d\n",
            pkt->port,
            pkt->f_ack,
            pkt->f_cs,
            pkt->f_psh,
            pkt->f_segm,
            pkt->f_syn,
            pkt->segm_len,
            pkt->window);
    }
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

    fifo_ctl->fifo_base = mmap_addr + sizeof(net_fifo_ctl);

    memset(fifo_ctl->fifo_base, 0x0, sizeof(net_fifo_ctl)*FIFO_SIZE);
    
    fifo_ctl->fifo_curr = NULL;

    return 0;
}

