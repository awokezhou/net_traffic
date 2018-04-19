#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "nt_core.h"



/* Lookup char into string, return position */
int nt_string_char_search(const char *string, int c, int len)
{
    char *p;

    if (len < 0) {
        len = strlen(string);
    }

    p = memchr(string, c, len);
    if (p) {
        return (p - string);
    }

    return -1;
}

/* Return a buffer with a new string from string */
char *nt_string_copy_substr(const char *string, int pos_init, int pos_end)
{
    unsigned int size, bytes;
    char *buffer = 0;

    if (pos_init > pos_end) {
        return NULL;
    }

    size = (unsigned int) (pos_end - pos_init) + 1;
    if (size <= 2)
        size = 4;

    buffer = nt_mem_alloc_z(size);

    if (!buffer) {
        return NULL;
    }

    bytes = pos_end - pos_init;
    memcpy(buffer, string + pos_init, bytes);
    buffer[bytes] = '\0';

    return (char *) buffer;
}

char *nt_string_dup(const char *s)
{
    int len;
    char *p;

    if (!s)
        return NULL;

    len = strlen(s);
    p = nt_mem_alloc_z(len + 1);
    memcpy(p, s, len);
    p[len] = '\0';

    return p;
}

char *nt_string_build(char **buffer, int *len,
                      const char *format, ...)
{
    va_list ap;
    int length;
    char *ptr;
    const size_t _mem_alloc = 64;
    size_t alloc = 0;

    /* *buffer *must* be an empty/NULL buffer */
	if (*buffer != NULL)
	{
		return NULL;
	}
	
    *buffer = nt_mem_alloc_z(_mem_alloc);

    if (!*buffer) 
    {
        return NULL;
    }
    alloc = _mem_alloc;

    va_start(ap, format);
    length = vsnprintf(*buffer, alloc, format, ap);
    va_end(ap);
	
    if (length < 0) 
    {
        return NULL;
    }	

    if ((unsigned int) length >= alloc) 
    {
        ptr = nt_mem_realloc(*buffer, length + 1);
        if (!ptr) 
        {
            return NULL;
        }
        *buffer = ptr;
        alloc = length + 1;

        va_start(ap, format);
        length = vsnprintf(*buffer, alloc, format, ap);
        va_end(ap);
    }

    ptr = *buffer;
    ptr[length] = '\0';
    *len = length;
    return *buffer;
}


int web_string_tolower(char *str, int len)
{
    int i;
    int str_len;

    if (!str)
        return -1;

    str_len = (strlen(str) > len) ? len : strlen(str);
    if (str_len <= 0)
        return -1;

    for (i=0; i<str_len; i++) {
        str[i] = tolower(str[i]);
    }

    return i;
}

