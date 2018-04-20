#include "nt_core.h"
#include "nt_mgr.h"




void nt_help(int ex)
{
    printf("usage : net_traffic [option]\n\n");

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

    nt_debug("web param create ok");

    static const struct option long_opts[] = {
        {"daemon",      no_argument,        NULL,   'd'},
        {"interface",   required_argument,  NULL,   'i'},
        {""},
        {NULL, 0, NULL, 0}
    };    

    while ((opt = getopt_long(argc, argvs, "di?h:", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
            case 'd':
                param->daemon = TRUE;
                break;
                
            case 'i':
                param->intf = nt_string_dup(optarg);
                break;

            case '?':
            case 'h':
            default:
                nt_help(NT_EXIT_SUCCESS);
        }
    }    
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

    nt_msg_clean(mgr);
    
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

    nt_msg_init(run_mgr);

    return nt_ok;
}


nt_ret nt_run_loop(nt_run_mgr *run_mgr)
{
    nt_msg_knl *msg;
    nt_event *event;
    nt_event_loop *evl;
    nt_ret ret = nt_ok;

    evl = nt_event_loop_create(run_mgr, NT_EVENT_QUEUE_SIZE);
    if (!evl)
    {
        nt_err("server event create error");
        return nt_err_nomem;
    }

    /* Register the listeners */
    nt_list_for_each_entry(msg, &run_mgr->msg_knl_list, _head) {
        nt_event_add(evl, msg->knl_fd, 
                      NT_EVENT_LISTENER, NT_EVENT_READ,
                      msg);
    }

    while (1) 
    {
        nt_event_wait(evl);
        nt_event_foreach(event, evl) {
            
            if (!nt_event_ready(event, evl))
                continue;

            ret = 0;
            if (event->type & NT_EVENT_IDLE) {
                continue;
            }

            if (event->type == NT_EVENT_CONNECTION) {
                nt_debug("type NT_EVENT_CONNECTION");
            } 
            else if (event->type == NT_EVENT_LISTENER) {
                nt_debug("type NT_EVENT_LISTENER");
            }
            else if (event->type == NT_EVENT_CUSTOM) {
                nt_debug("type NT_EVENT_CUSTOM");
            }
            else if (event->type == NT_EVENT_NOTIFICATION) {
                nt_debug("type NT_EVENT_NOTIFICATION");
            }
        }
    }
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
    if (nt_ok != nt_ret)
    {
        nt_err("core init error, ret %d", ret);
        goto err;
    }

    nt_run_loop(run_mgr);

err:
    nt_run_mgr_destory(&run_mgr);
    NT_EXIT(NT_EXIT_FAILURE);
}
