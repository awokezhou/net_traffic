#include "nt_mgr.h"
#include "nt_core.h"
#include "nt_flow.h"

#include <getopt.h>







void nt_help(int ex)
{
    printf("usage : net_traffic [option]\n\n");

    printf("    -c,      --flow class\t\t\label traffic type\n");
    printf("    -d,      --daemon\t\t\trun net_traffic as daemon\n");
    printf("    -i ethx, --bind interface\n");

    NT_EXIT(ex);
}







void nt_run_prm_clean(nt_run_prm **param)
{
    nt_run_prm *p;

    if (!*param || !param)
        return;

    p = *param;

    if (p->intf)
        nt_mem_free(p->intf);

    nt_mem_free(p);
    p = NULL;
    return;
}

nt_run_prm *nt_run_prm_create()
{
    nt_run_prm *param = NULL;

    param = nt_mem_alloc_z(sizeof(nt_run_prm));
    if (!param)
        return NULL;

    param->intf = NULL;
    param->daemon = FALSE;
    return param;
}

nt_run_prm *nt_param_parse(int argc, char *argvs[])
{
    int opt;
    nt_run_prm *param;    

    param = nt_run_prm_create();
    if (!param)
    {
        nt_err("param create error");
        return NULL;        
    }

    nt_debug("param create ok");

    static const struct option long_opts[] = {
        {"daemon",      no_argument,        NULL,   'd'},
        {"interface",   required_argument,  NULL,   'i'},
        {"flow calss",  required_argument,  NULL,   'c'},
        {NULL, 0, NULL, 0}
    };    

    while ((opt = getopt_long(argc, argvs, "dic:?h:", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
            case 'd':
                param->daemon = TRUE;
                break;
                
            case 'i':
                param->intf = nt_string_dup(optarg);
                break;

            case 'c':
                param->fcls = nt_string_dup(optarg);
                break;

            case '?':
            case 'h':
            default:
                nt_help(NT_EXIT_SUCCESS);
        }
    }    

    return param;
}

nt_run_mgr *nt_run_mgr_create(nt_run_prm *param)
{
    nt_run_mgr *run_mgr;

    if (!param)
        return nt_err_param;

    run_mgr = nt_mem_alloc_z(sizeof(nt_run_mgr));
    if (!run_mgr)
        return NULL; 

    run_mgr->param = param;

    return run_mgr;
}

void nt_run_mgr_destory(nt_run_mgr **mgr)
{
    nt_run_mgr *p;

    if (!mgr || !*mgr)
        return;

    p = *mgr;

    if (p->param)
        nt_run_prm_clean(&p->param);
    
    nt_mem_free(p);
    return;
}

void nt_run_daemon()
{
    pid_t pid;

    pid = fork();

    switch (pid)
    {
        case -1:                        
            nt_err("fork error!");
            return;

        case 0:                         // child
            break;

        default:                        // father
            NT_EXIT(NT_EXIT_SUCCESS);                
    }

    pid = setsid();
    if (pid < 0)
    {
        nt_err("setsid error");
        return;
    }

    nt_debug("daemon ok");
    return;
}

nt_ret nt_core_init(nt_run_mgr *run_mgr)
{
    nt_signal_init(run_mgr);

    if (run_mgr->param->daemon)
        nt_run_daemon();

    nt_flow_init(run_mgr);

    return nt_ok;
}

nt_ret nt_proc_read(nt_run_mgr *run_mgr)
{
    int kfd; 
    nt_ret ret = nt_ok;
    char *mmap_mem = NULL;
    net_fifo_ctl *fifo_ctl = NULL;
        
    kfd = open(DEV_NAME, O_RDWR|O_NDELAY);
    if (kfd < 0) {
        nt_err("open %s error", DEV_NAME);
        return nt_err_file_open;
    }

    mmap_mem = (char *)mmap(0, 
                            MMAP_MEM_SIZE, 
                            PROT_READ | PROT_WRITE, 
                            MAP_SHARED, 
                            kfd, 
                            0);
    if (!mmap_mem) {
        nt_err("mmap error");
        close(kfd);
        return nt_err_file_mmap;
    }

    fifo_ctl = (net_fifo_ctl *)mmap_mem;

    /*    
    nt_debug("**************** mmap info *****************");
    nt_debug("mmap size : %d Byte\n", MMAP_MEM_SIZE);
    nt_debug("fifo size : %d\n", fifo_ctl->fifo_size);
    nt_debug("fifo pull : %d \n", fifo_ctl->fifo_pull);
    */
    
    
    //nt_flow_pkt_save(fifo_ctl);

    ret = nt_flow_process(fifo_ctl, run_mgr);
    if (nt_ok != ret)
    {
        nt_err("flow process error");
        goto out;
    }

out:
    if (fifo_ctl)
        munmap(fifo_ctl, MMAP_MEM_SIZE);
    if (kfd>0)
        close(kfd);
    return ret;
}

nt_ret nt_run_loop(nt_run_mgr *run_mgr)
{
    int loop = 7;
    nt_ret ret = nt_ok;

    while (loop > 0) 
    {
        sleep(5);

        ret = nt_proc_read(run_mgr);
        if (nt_ok != ret)
        {
            nt_err("proc read error, ret %d", ret);
        }

        loop--;
    }

    nt_debug("break loop, will save flow to file");
    return nt_flow_save(run_mgr);
}

int main(int argc, char *argv[])
{
    nt_ret ret = nt_ok;
    nt_run_mgr *run_mgr;
    nt_run_prm *run_prm;

    run_prm = nt_param_parse(argc, argv);
    if (!run_prm)
    {
        nt_err("param get error");
        NT_EXIT(NT_EXIT_FAILURE);
    }

    run_mgr = nt_run_mgr_create(run_prm);
    if (!run_mgr)
    {
        nt_err("run mgr create error");
        nt_run_prm_clean(&run_prm);
        NT_EXIT(NT_EXIT_FAILURE);
    }
    
    ret = nt_core_init(run_mgr);
    if (nt_ok != ret)
    {
        nt_err("core init error, ret %d", ret);
        goto err;
    }

    nt_run_loop(run_mgr);

err:
    nt_run_mgr_destory(&run_mgr);
    NT_EXIT(NT_EXIT_FAILURE);
}