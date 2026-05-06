#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "global.h"
#include "protocol.h"

unsigned short checksum(void *addr, int count) {
    unsigned int sum = 0, value = 0;
    while (count > 1) {
        memcpy(&value, addr, 2);
        sum += value;
        addr  = (char *)addr + 2;
        count -= 2;
    }
    if (count > 0)
        sum += *(unsigned char *)addr;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

int write_all(int fd, const void *buf, size_t n) {
    const char *p = buf;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) return -1;
        p += w;
        n -= w;
    }
    return 0;
}

int read_all(int fd, void *buf, size_t n) {
    char *p = buf;
    while (n > 0) {
        ssize_t r = read(fd, p, n);
        if (r <= 0) return -1;
        p += r;
        n -= r;
    }
    return 0;
}

int send_msg(int fd, uint8_t type, const void *payload, uint32_t len) {
    struct msg_hdr hdr;
    hdr.type = type;
    hdr.len  = htonl(len);
    if (write_all(fd, &hdr, sizeof(hdr)) < 0) return -1;
    if (len > 0 && payload)
        if (write_all(fd, payload, len) < 0) return -1;
    return 0;
}

int resolve_hostname(const char *host, char *ip_out, size_t ip_len) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int r = getaddrinfo(host, NULL, &hints, &res);
    if (r != 0) {
        fprintf(stderr, "resolve: %s: %s\n", host, gai_strerror(r));
        return -1;
    }
    struct sockaddr_in *a = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &a->sin_addr, ip_out, (socklen_t)ip_len);
    freeaddrinfo(res);
    return 0;
}

int recv_msg(int fd, uint8_t *type, void **payload, uint32_t *len) {
    struct msg_hdr hdr;
    if (read_all(fd, &hdr, sizeof(hdr)) < 0) return -1;
    *type = hdr.type;
    *len  = ntohl(hdr.len);
    if (*len == 0) {
        *payload = NULL;
        return 0;
    }
    *payload = malloc(*len);
    if (!*payload) return -1;
    if (read_all(fd, *payload, *len) < 0) {
        free(*payload);
        *payload = NULL;
        return -1;
    }
    return 0;
}
