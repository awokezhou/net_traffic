#include <sys/select.h>

#include "nt_event.h"
#include "nt_core.h"

void nt_event_clean(nt_event **event)
{
    nt_event *pevent;
    
    if (!event || !*event)
        return;

    pevent = *event;

    if (pevent->fd)
        close(pevent->fd);

    nt_mem_free(pevent);
    pevent = NULL;
    
    return;
}

static inline void nt_event_loop_ctx_clean(nt_event_ctx **ctx)
{
    nt_event_ctx *pctx;
    
    if (!*ctx || !ctx)
        return;

    pctx = *ctx;

    if (&pctx->events)
        nt_mem_free(&pctx->events);

    if (pctx->fired)
        nt_mem_free(pctx->fired);
    
    nt_mem_free(pctx);
    pctx = NULL;
    return;
}

static inline void nt_event_loop_clean(nt_event_loop **loop)
{
    nt_event_loop *ploop;

    if (!*loop || !loop)
        return;

    ploop = *loop;

    if (ploop->ctx)
        nt_event_loop_ctx_clean(&ploop->ctx);

    if (ploop->events)
        nt_mem_free(ploop->events);

    nt_mem_free(ploop);
    ploop = NULL;
    return;
}

void nt_event_del(nt_event_loop *loop, nt_event *event)
{
    int i;
    int fd;
    nt_event *s_event;
    nt_event_ctx *ctx = loop->ctx;
    
    /* just remove a registered event */
    if ((event->status & NT_EVENT_REGISTERED) == 0) {
        return;
    }

    fd = event->fd;

    if (event->mask & NT_EVENT_READ) {
        FD_CLR(event->fd, &ctx->rfds);
    }

    if (event->mask & NT_EVENT_WRITE) {
        FD_CLR(event->fd, &ctx->wfds);
    }

     /* Update max_fd, lookup */
    if (event->fd == ctx->max_fd) {
        for (i = (ctx->max_fd - 1); i > 0; i--) {
            if (!ctx->events[i]) {
                continue;
            }

            s_event = ctx->events[i];
            if (s_event->mask != NT_EVENT_EMPTY) {
                break;
            }
        }
        ctx->max_fd = i;
    }

    ctx->events[fd] = NULL;

    /* Reset the status and mask */
    NT_EVENT_NEW(event);
        
    return;
}

nt_ret nt_event_add(nt_event_loop *loop, int fd,
                 int type, uint32_t mask, void *data)
{
    nt_event *event;
    nt_event_ctx *ctx = loop->ctx;

    if (!loop || !data)
        return nt_err_param;
        
    if (fd > FD_SETSIZE)
        return nt_err_param;

    if (mask & NT_EVENT_READ) {
        FD_SET(fd, &ctx->rfds);
    }
    
    if (mask & NT_EVENT_WRITE) {
        FD_SET(fd, &ctx->wfds);
    }

    event = (nt_event *) data;
    event->fd   = fd;
    event->type = type;
    event->mask = mask;
    event->status = NT_EVENT_REGISTERED;

    ctx->events[fd] = event;
    if (fd > ctx->max_fd) {
        ctx->max_fd = fd;
    }

    return nt_ok;
}

int nt_event_wait(nt_event_loop *loop)
{
    int i;
    int f = 0;
    uint32_t mask;
    nt_event *fired;
    struct timeval tv;
    nt_event_ctx *ctx = loop->ctx;

    memcpy(&ctx->_rfds, &ctx->rfds, sizeof(fd_set));
    memcpy(&ctx->_wfds, &ctx->wfds, sizeof(fd_set));

    memset(&tv, 0x0, sizeof(tv));
    tv.tv_sec = 5;
    tv.tv_usec = 0;

    loop->n_events = select(ctx->max_fd + 1, &ctx->_rfds, &ctx->_wfds, NULL, NULL);
    if (loop->n_events <= 0) {
        return loop->n_events;
    }

    for (i=0; i<= ctx->max_fd; i++)
    {
        /* skip empty references */
        if (!ctx->events[i]) {
            continue;
        }

        mask = 0;

        if (FD_ISSET(i, &ctx->_rfds)) {
            mask |= NT_EVENT_READ;
        }

        if (FD_ISSET(i, &ctx->_wfds)) {
            mask |= NT_EVENT_READ;
        }

        if (mask) {
            fired = &ctx->fired[f];
            fired->fd   = i;
            fired->mask = mask;
            fired->data = ctx->events[i];
            f++;
        }
    }

    loop->n_events = f;
    return loop->n_events;
}

bool nt_event_ready(nt_event *event, nt_event_loop *evl)
{
    nt_event_ctx *ctx = evl->ctx;       

    if (event->mask & NT_EVENT_WRITE)
        return TRUE;
    
    if (event->mask & NT_EVENT_READ) {
        if(FD_ISSET(event->fd, &ctx->_rfds)) {
            if (nt_socket_fd_read_ready(event->fd)) {
                return TRUE;
            } else {
                nt_event_del(evl, event);
            }
        }
    } 

    return FALSE;
}

inline bool nt_event_read_ready(nt_event *event)
{
    return mask_exst(event->mask, NT_EVENT_READ);
}
inline bool nt_event_write_ready(nt_event *event)
{
    return mask_exst(event->mask, NT_EVENT_WRITE);
}

static inline nt_event_ctx *nt_event_loop_ctx_create(int size)
{
    nt_event_ctx *ctx;

    /* Override caller 'size', we always use FD_SETSIZE */
    size = FD_SETSIZE;

    /* Main event context */
    ctx = nt_mem_alloc_z(sizeof(nt_event_ctx));
    if (!ctx) {
        return NULL;
    }

    FD_ZERO(&ctx->rfds);
    FD_ZERO(&ctx->wfds);

    /* Allocate space for events queue, re-use the struct mk_event */
    ctx->events = nt_mem_alloc_z(sizeof(nt_event *) * size);
    if (!ctx->events) {
        web_mem_free(ctx);
        return NULL;
    }

    /* Fired events (upon select(2) return) */
    ctx->fired = nt_mem_alloc_z(sizeof(nt_event) * size);
    if (!ctx->fired) {
        nt_mem_free(ctx->events);
        nt_mem_free(ctx);
        return NULL;
    }

    ctx->queue_size = size;
    return ctx;
}


nt_event_loop *nt_event_loop_create(int size)
{
    nt_event_ctx *ctx;
    nt_event_loop *loop;

    ctx = nt_event_loop_ctx_create(size);
    if (!ctx) {
        return NULL;
    }

    loop = nt_mem_alloc_z(sizeof(nt_event_loop));
    if (!loop) {
        goto err;
    }

    loop->events = nt_mem_alloc_z(sizeof(nt_event) * size);
    if (!loop->events) {
        goto err;
    }

    loop->size   = size;
    loop->ctx   = ctx;

    return loop;


err:
    if (ctx)
        nt_event_loop_ctx_clean(&ctx);
    
    if (loop)
        nt_event_loop_clean(&loop);
    
    return NULL;
}



