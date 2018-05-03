#ifndef __NT_MGR_H__
#define __NT_MGR_H__


#include "nt_core.h"


#define FIFO_SIZE 10

#define DEV_NAME "/proc/net_traffic"

#define LINUX_PAGE_SIZE 4096

#define MMAP_MEM_SIZE  (LINUX_PAGE_SIZE * 2)

typedef struct _net_flow {
    int num_buf;
    struct sk_buff *buf[FIFO_SIZE];
} net_flow;
typedef struct _traffic_entry_s {
    unsigned int addr;
    unsigned long long upload;
    unsigned long long dwload;
} traffic_entry_s;

typedef struct {
    traffic_entry_s *entry[FIFO_SIZE];
    int num;
} array_entry;


typedef struct {
    char *intf;             /* interface to bind */
    bool daemon;            /* run as daemon     */    
} nt_run_prm;

typedef struct _nt_run_mgr{
    
    nt_run_prm *param;
} nt_run_mgr;








#endif /* __NT_MGR_H__ */
