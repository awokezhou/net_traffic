#include "nt_core.h"
#include "nt_print.h"

#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>



static void nt_signal_exit();




static struct _nt_run_mgr *run_mgr_context;

static void nt_signal_handler(int signo, siginfo_t *si, void *context)
{
    switch (signo) 
    {
        case SIGTERM:
        case SIGINT:
            nt_signal_exit();
            break;
            
        case SIGHUP:
            nt_signal_exit();
            break;
            
        case SIGBUS:
        case SIGSEGV:
            nt_err("%s (%d), code=%d, addr=%p",
               strsignal(signo), signo, si->si_code, si->si_addr);
            abort();
            
        default:
            /* let the kernel handle it */
            kill(getpid(), signo);
    }
}

void nt_signal_context(struct _nt_run_mgr *ctx)
{
    run_mgr_context = ctx;
}

static void nt_signal_exit()
{
    /* ignore future signals to properly handle the cleanup */
    signal(SIGTERM, SIG_IGN);
    signal(SIGINT,  SIG_IGN);
    signal(SIGHUP,  SIG_IGN);

    nt_run_mgr_destory(&run_mgr_context);

    nt_info("Exiting... >:(");
    NT_EXIT(NT_EXIT_SUCCESS);
}

void nt_signal_init(void *context)
{
    struct sigaction act;
    memset(&act, 0x0, sizeof(act));

    /* allow signals to be handled concurrently */
    act.sa_flags = SA_SIGINFO | SA_NODEFER;
    act.sa_sigaction = &nt_signal_handler;

    sigaction(SIGSEGV, &act, NULL);
    sigaction(SIGBUS,  &act, NULL);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);

    nt_signal_context(context);
}


