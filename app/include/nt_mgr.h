#ifndef __NT_MGR_H__
#define __NT_MGR_H__


#include "nt_core.h"





typedef struct {
    char *intf;             /* interface to bind */
    bool daemon;            /* run as daemon     */    
} nt_run_prm;

typedef struct _nt_run_mgr{

    nt_list msg_knl_list;
    
    nt_run_prm *param;
} nt_run_mgr;


#endif /* __NT_MGR_H__ */
