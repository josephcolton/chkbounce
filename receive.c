#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>

#include "global.h"
#include "protocol.h"
#include "receive.h"

/* ----------------------------------------------------------------- socket helpers */

/* Socket of type bound to the wildcard address of family on port. */
static int open_bound(int family, int type, int port) {
    int fd = socket(family, type, 0);
    if (fd < 0) { perror(type == SOCK_STREAM ? "TCP socket" : "UDP socket"); return -1; }

    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    /* Keep v6 sockets v6-only so IPv4-mapped peers can't slip in */
    if (family == AF_INET6)
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));

    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));
    addr.ss_family = family;   /* zeroed address = INADDR_ANY / in6addr_any */
    sa_set_port(&addr, port);

    if (bind(fd, (struct sockaddr *)&addr, sa_len(&addr)) < 0) {
        fprintf(stderr, "bind %s %d: %s\n", type == SOCK_STREAM ? "TCP" : "UDP",
                port, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static int open_tcp_listen(int family, int port) {
    int fd = open_bound(family, SOCK_STREAM, port);
    if (fd >= 0 && listen(fd, 4) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }
    return fd;
}

int open_icmp_raw(int family) {
    int v6 = family == AF_INET6;
    int fd = socket(family, SOCK_RAW, v6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP);
    if (fd < 0) {
        perror(v6 ? "ICMPv6 raw socket (ICMP probes will fail)"
                  : "ICMP raw socket (ICMP probes will fail)");
        return -1;
    }
    if (v6) {
        /* Deliver every ICMPv6 type; don't rely on the kernel default */
        struct icmp6_filter filt;
        ICMP6_FILTER_SETPASSALL(&filt);
        setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, sizeof(filt));
    }
    return fd;
}

int open_probe_socket(int family, int proto, int number, int icmp_fd) {
    int fd = -1;
    if (proto == PROTO_ICMP) {
        fd = icmp_fd;
    } else if (proto == PROTO_TCP) {
        fd = open_tcp_listen(family, number);
        if (fd >= 0)
            printf("Listening TCP %d\n", number);
        else
            fprintf(stderr, "could not open TCP %d\n", number);
    } else if (proto == PROTO_UDP) {
        fd = open_bound(family, SOCK_DGRAM, number);
        if (fd >= 0)
            printf("Listening UDP %d\n", number);
        else
            fprintf(stderr, "could not open UDP %d\n", number);
    }
    return fd;
}

void close_probe_socket(int proto, int fd) {
    if (proto != PROTO_ICMP && fd >= 0)
        close(fd);
}

/*
 * Wait up to *tv for data/connection on fd.
 * Subtracts elapsed time from *tv so repeated calls share a deadline.
 */
static int timed_select(int fd, struct timeval *tv) {
    struct timeval before, after, elapsed;
    gettimeofday(&before, NULL);

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    int r = select(fd + 1, &rfds, NULL, NULL, tv);

    gettimeofday(&after, NULL);
    timersub(&after, &before, &elapsed);
    if (timercmp(&elapsed, tv, <))
        timersub(tv, &elapsed, tv);
    else
        timerclear(tv);
    return r;
}

/* ------------------------------------------------------------------ probe wait */

static int wait_icmp(int icmp_fd, const struct sockaddr_storage *peer,
                     int expected_type, int timeout_sec, int reverse) {
    struct timeval tv = { timeout_sec, 0 };
    char buf[4096];
    char ip[INET6_ADDRSTRLEN];
    uint16_t want_seq = probe_icmp_seq(expected_type, reverse);

    while (1) {
        if (timed_select(icmp_fd, &tv) <= 0) break;

        struct sockaddr_storage src;
        socklen_t slen = sizeof(src);
        int bytes = recvfrom(icmp_fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&src, &slen);
        if (bytes < 0) break;
        if (!sa_same_addr(&src, peer)) continue;

        /* Raw IPv4 sockets include the IP header; raw ICMPv6 sockets don't */
        int off = 0;
        if (src.ss_family == AF_INET)
            off = ((unsigned char)buf[0] & 0x0f) * 4;
        if (bytes < off + 8) continue;

        int got_type = (unsigned char)buf[off];
        uint16_t got_seq;
        memcpy(&got_seq, buf + off + 6, 2);
        got_seq = ntohs(got_seq);

        if (got_type == expected_type && got_seq == want_seq) {
            printf("  ICMP type %d from %s\n", got_type, sa_ntop(&src, ip, sizeof(ip)));
            return 1;
        }
        printf("  ICMP type %d from %s (ignored: not this probe)\n",
               got_type, sa_ntop(&src, ip, sizeof(ip)));
    }
    return 0;
}

static int wait_tcp(int fd, int port, const struct sockaddr_storage *peer,
                    int timeout_sec) {
    struct timeval tv = { timeout_sec, 0 };
    char ip[INET6_ADDRSTRLEN];

    while (1) {
        if (timed_select(fd, &tv) <= 0) return 0;

        struct sockaddr_storage src;
        socklen_t slen = sizeof(src);
        int conn = accept(fd, (struct sockaddr *)&src, &slen);
        if (conn < 0) return 0;
        close(conn);
        if (!sa_same_addr(&src, peer)) continue;
        printf("  TCP port %d from %s\n", port, sa_ntop(&src, ip, sizeof(ip)));
        return 1;
    }
}

static int wait_udp(int fd, int port, const struct sockaddr_storage *peer,
                    int timeout_sec) {
    struct timeval tv = { timeout_sec, 0 };
    char buf[512];
    char ip[INET6_ADDRSTRLEN];

    while (1) {
        if (timed_select(fd, &tv) <= 0) break;

        struct sockaddr_storage src;
        socklen_t slen = sizeof(src);
        int bytes = recvfrom(fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&src, &slen);
        if (bytes < 0) break;
        if (!sa_same_addr(&src, peer)) continue;
        printf("  UDP port %d from %s\n", port, sa_ntop(&src, ip, sizeof(ip)));
        return 1;
    }
    return 0;
}

int wait_probe(int proto, int fd, int number, const struct sockaddr_storage *peer,
               int timeout_sec, int reverse) {
    if (fd < 0) return 0;
    if (proto == PROTO_ICMP)
        return wait_icmp(fd, peer, number, timeout_sec, reverse);
    if (proto == PROTO_TCP)
        return wait_tcp(fd, number, peer, timeout_sec);
    if (proto == PROTO_UDP)
        return wait_udp(fd, number, peer, timeout_sec);
    return 0;
}
