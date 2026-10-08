#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "global.h"
#include "protocol.h"

const char *proto_name(int proto, int family) {
    switch (proto) {
    case PROTO_ICMP: return family == AF_INET6 ? "ICMPv6" : "ICMP";
    case PROTO_TCP:  return "TCP";
    case PROTO_UDP:  return "UDP";
    }
    return "?";
}

const char *timestamp_utc(char *buf, size_t len) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    gmtime_r(&tv.tv_sec, &tm);
    size_t n = strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
    snprintf(buf + n, len - n, ".%03ldZ", (long)(tv.tv_usec / 1000));
    return buf;
}

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

int resolve_host(const char *host, int family, struct sockaddr_storage *out) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = family;
    hints.ai_socktype = SOCK_STREAM;

    int r = getaddrinfo(host, NULL, &hints, &res);
    if (r != 0) {
        fprintf(stderr, "resolve: %s: %s\n", host, gai_strerror(r));
        return -1;
    }
    memset(out, 0, sizeof(*out));
    memcpy(out, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    sa_set_port(out, 0);
    return 0;
}

socklen_t sa_len(const struct sockaddr_storage *ss) {
    return ss->ss_family == AF_INET6 ? sizeof(struct sockaddr_in6)
                                     : sizeof(struct sockaddr_in);
}

void sa_set_port(struct sockaddr_storage *ss, int port) {
    if (ss->ss_family == AF_INET6)
        ((struct sockaddr_in6 *)ss)->sin6_port = htons(port);
    else
        ((struct sockaddr_in *)ss)->sin_port = htons(port);
}

void sa_unmap(struct sockaddr_storage *ss) {
    if (ss->ss_family != AF_INET6) return;
    struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)ss;
    if (!IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr)) return;

    struct sockaddr_in a4;
    memset(&a4, 0, sizeof(a4));
    a4.sin_family = AF_INET;
    a4.sin_port   = a6->sin6_port;
    memcpy(&a4.sin_addr, &a6->sin6_addr.s6_addr[12], 4);
    memset(ss, 0, sizeof(*ss));
    memcpy(ss, &a4, sizeof(a4));
}

int sa_same_addr(const struct sockaddr_storage *a, const struct sockaddr_storage *b) {
    if (a->ss_family != b->ss_family) return 0;
    if (a->ss_family == AF_INET6)
        return memcmp(&((const struct sockaddr_in6 *)a)->sin6_addr,
                      &((const struct sockaddr_in6 *)b)->sin6_addr,
                      sizeof(struct in6_addr)) == 0;
    return ((const struct sockaddr_in *)a)->sin_addr.s_addr ==
           ((const struct sockaddr_in *)b)->sin_addr.s_addr;
}

const char *sa_ntop(const struct sockaddr_storage *ss, char *buf, size_t len) {
    const void *addr = ss->ss_family == AF_INET6
        ? (const void *)&((const struct sockaddr_in6 *)ss)->sin6_addr
        : (const void *)&((const struct sockaddr_in *)ss)->sin_addr;
    if (!inet_ntop(ss->ss_family, addr, buf, (socklen_t)len))
        snprintf(buf, len, "?");
    return buf;
}

const char *family_name(int family) {
    return family == AF_INET6 ? "IPv6" : "IPv4";
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
