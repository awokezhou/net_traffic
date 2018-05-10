#ifndef __NT_MGR_H__
#define __NT_MGR_H__


#include "nt_core.h"

#define DEV_NAME "/proc/net_traffic"

#define LINUX_PAGE_SIZE 4096

#define MMAP_MEM_SIZE  (LINUX_PAGE_SIZE * 8)

typedef struct _traffic_entry_s {
    unsigned int addr;
    unsigned long long upload;
    unsigned long long dwload;
} traffic_entry_s;


typedef struct {
    char *fcls;            /* flow class        */
    char *intf;             /* interface to bind */
    bool daemon;            /* run as daemon     */   
} nt_run_prm;

typedef struct _nt_run_mgr{
    char *save_file;
    nt_list flow_list;
    nt_run_prm *param;
} nt_run_mgr;



#endif /* __NT_MGR_H__ */
