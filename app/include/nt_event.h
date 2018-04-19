#ifndef __NT_EVENT_H__
#define __NT_EVENT_H__

#include "nt_core.h"


#define NT_EVENT_QUEUE_SIZE        128


/* Events type family */
#define NT_EVENT_NOTIFICATION      0    /* notification channel (pipe)      */
#define NT_EVENT_LISTENER          1    /* listener socket                  */
#define NT_EVENT_CONNECTION        2    /* data on active connection        */
#define NT_EVENT_CUSTOM            3    /* custom fd registered             */

/* Event triggered for file descriptors  */
#define NT_EVENT_EMPTY             0x0000
#define NT_EVENT_READ              0x0001
#define NT_EVENT_WRITE             0x0004
#define NT_EVENT_SLEEP             0x0008
#define NT_EVENT_CLOSE             (0x0010 | 0x0008 | 0x2000)
#define NT_EVENT_IDLE              (0x0010 | 0x0008)

/* Event status */
#define NT_EVENT_NONE              1    /* nothing */
#define NT_EVENT_REGISTERED        2    /* event is registered into the ev loop */


#define NT_EP_SOCKET_CLOSED   0
#define NT_EP_SOCKET_ERROR    1
#define NT_EP_SOCKET_TIMEOUT  2
#define NT_EP_SOCKET_DONE     3


/* Event reported by the event loop */
typedef struct _nt_event {
    int      fd;       /* monitored file descriptor */
    int      type;     /* event type  */
    uint32_t mask;     /* events mask */
    uint8_t  status;   /* internal status */
    void    *data;     /* custom data reference */

    /* function handler for custom type */
    int     (*handler)(void *data);
    nt_list _head;
} nt_event;


typedef struct _nt_event_ctx {
    int max_fd;

    /* Original set of file descriptors */
    fd_set rfds;
    fd_set wfds;

    /* Populated before every select(2) */
    fd_set _rfds;
    fd_set _wfds;

    int queue_size;
    nt_event **events;  /* full array to register all events */
    nt_event *fired;    /* used to create iteration array    */
} nt_event_ctx;


typedef struct _nt_event_loop {
    int size;                   /* size of events array */
    int timeout;
    int n_events;               /* number of events reported */
    struct nt_event *events;   /* copy or reference of events triggered */
    nt_event_ctx *ctx;         /* mk_event_ctx_t from backend */
} nt_event_loop;

#define nt_event_foreach(event, evl)                                   \
    int __i;                                                            \
    nt_event_ctx *__ctx = evl->ctx;                                    \
                                                                        \
    if (evl->n_events > 0) {                                            \
        event = __ctx->fired[0].data;                                   \
    }                                                                   \
                                                                        \
    for (__i = 0;                                                       \
         __i < evl->n_events;                                           \
         __i++,                                                         \
             event = __ctx->fired[__i].data                             \
         )

static inline void NT_EVENT_NEW(nt_event *e)
{
    e->mask   = NT_EVENT_EMPTY;
    e->status = NT_EVENT_NONE;
}


int nt_event_wait(nt_event_loop *loop);

#define mask_exst(mask, flag)   ((mask) & (flag))
#define mask_push(mask, flag)   ((mask) |= (flag))
#define mask_only(mask, flag)   (!((mask) & (~(flag))))


#endif /* __NT_EVENT_H__ */

