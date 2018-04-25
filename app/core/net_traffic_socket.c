#include "nt_core.h"


int web_socket_create(int domain, int type, int protocol)
{
    int fd;

#ifdef SOCK_CLOEXEC
    fd = socket(domain, type | SOCK_CLOEXEC, protocol);
#else
    fd = socket(domain, type, protocol);
    fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif

    if (fd == -1) {
        return -1;
    }

    return fd;
}

bool nt_socket_fd_read_ready(int fd)
{
    uint32_t read_count = 0;
    
    ioctl(fd, FIONREAD, &read_count);

    if (read_count == 0)
        return FALSE;
    else
        return TRUE;
}