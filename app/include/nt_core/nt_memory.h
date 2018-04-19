#ifndef __NT_MEMORY_H__
#define __NT_MEMORY_H__

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <nt_core/nt_macros.h>

static inline void *wnt_mem_alloc(const size_t size)
{
    void *aux = malloc(size);

    if (nt_unlikely(!aux && size)) {
        return NULL;
    }

    return aux;
}

static inline void *nt_mem_alloc_z(const size_t size)
{

    void *buf = calloc(1, size);

    if (nt_unlikely(!buf)) {
        return NULL;
    }

    return buf;
}

static inline void *nt_mem_realloc(void *ptr, const size_t size)
{
    void *aux = realloc(ptr, size);

    if (nt_unlikely(!aux && size)) {
        return NULL;
    }

    return aux;
}

static inline void nt_mem_free(void *ptr)
{
    free(ptr);
}

typedef struct
{
    char *data;
    unsigned long len;
} web_ptr_t;

static inline void nt_ptr_reset(web_ptr_t * p)
{
    p->data = NULL;
    p->len = 0;
}


#endif /* __NT_MEMORY_H__ */

