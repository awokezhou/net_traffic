#include <fcntl.h>
#include <time.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>




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

