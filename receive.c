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
    if (fd < 0) return -1;     /* e.g. raw socket unavailable without root */

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

/* 1 if buf holds PROBE_MAGIC followed by tag (network order). */
static int has_tag(const unsigned char *buf, size_t len, uint16_t tag) {
    if (len < PROBE_MAGIC_LEN + 2) return 0;
    if (memcmp(buf, PROBE_MAGIC, PROBE_MAGIC_LEN) != 0) return 0;
    uint16_t t;
    memcpy(&t, buf + PROBE_MAGIC_LEN, 2);
    return ntohs(t) == tag;
}

/*
 * Receive the next ICMP message from peer on a raw socket, waiting at most
 * *tv (which is decremented).  Sets *msg and *len to the ICMP message (the IPv4
 * header, which raw IPv4 sockets include and raw ICMPv6 sockets don't, is
 * skipped).  Returns 1 on a message, 0 on timeout or error.
 */
static int next_icmp(int icmp_fd, const struct sockaddr_storage *peer,
                     struct timeval *tv, unsigned char *buf, size_t bufsize,
                     const unsigned char **msg, size_t *len) {
    while (1) {
        if (timed_select(icmp_fd, tv) <= 0) return 0;

        struct sockaddr_storage src;
        socklen_t slen = sizeof(src);
        int bytes = recvfrom(icmp_fd, buf, bufsize, 0,
                             (struct sockaddr *)&src, &slen);
        if (bytes < 0) return 0;
        if (!sa_same_addr(&src, peer)) continue;

        size_t off = 0;
        if (src.ss_family == AF_INET)
            off = (buf[0] & 0x0f) * 4;
        if ((size_t)bytes < off + 8) continue;
        *msg = buf + off;
        *len = bytes - off;
        return 1;
    }
}

static int wait_icmp(int icmp_fd, const struct sockaddr_storage *peer,
                     int expected_type, int timeout_sec, uint16_t tag) {
    struct timeval tv = { timeout_sec, 0 };
    unsigned char buf[4096];
    const unsigned char *m;
    size_t len;
    char ip[INET6_ADDRSTRLEN];

    while (next_icmp(icmp_fd, peer, &tv, buf, sizeof(buf), &m, &len)) {
        uint16_t got_seq;
        memcpy(&got_seq, m + 6, 2);
        if (m[0] == expected_type && ntohs(got_seq) == tag) {
            printf("  ICMP type %d from %s\n", m[0], sa_ntop(peer, ip, sizeof(ip)));
            return 1;
        }
        printf("  ICMP type %d from %s (ignored: not this probe)\n",
               m[0], sa_ntop(peer, ip, sizeof(ip)));
    }
    return 0;
}

/*
 * Source port of the UDP datagram quoted by ICMP message m (header + body),
 * or -1 if it doesn't quote an IPv4/IPv6 UDP datagram.
 */
static int quoted_udp_sport(const unsigned char *m, size_t len) {
    if (len < 8) return -1;
    const unsigned char *q = m + 8;          /* after the 8-byte ICMP header */
    size_t qlen = len - 8, ihl;
    int proto;
    if (qlen >= 20 && (q[0] >> 4) == 4) {
        ihl   = (q[0] & 0x0f) * 4;
        proto = q[9];
    } else if (qlen >= 40 && (q[0] >> 4) == 6) {
        ihl   = 40;                          /* no extension headers expected */
        proto = q[6];
    } else {
        return -1;
    }
    if (proto != IPPROTO_UDP || qlen < ihl + 2) return -1;
    return (q[ihl] << 8) | q[ihl + 1];
}

int wait_icmp_quoted(int icmp_fd, const struct sockaddr_storage *peer,
                     int expected_type, int sport, int timeout_sec) {
    struct timeval tv = { timeout_sec, 0 };
    unsigned char buf[4096];
    const unsigned char *m;
    size_t len;
    char ip[INET6_ADDRSTRLEN];

    while (next_icmp(icmp_fd, peer, &tv, buf, sizeof(buf), &m, &len)) {
        if (m[0] == expected_type && quoted_udp_sport(m, len) == sport) {
            printf("  ICMP type %d (quoting UDP from port %d) from %s\n",
                   m[0], sport, sa_ntop(peer, ip, sizeof(ip)));
            return 1;
        }
        printf("  ICMP type %d from %s (ignored: not this probe)\n",
               m[0], sa_ntop(peer, ip, sizeof(ip)));
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

/* UDP probe or primer: PROBE_MAGIC + tag.  peer NULL = any source. */
static int wait_udp(int fd, const struct sockaddr_storage *peer, int timeout_sec,
                    uint16_t tag, struct sockaddr_storage *from) {
    struct timeval tv = { timeout_sec, 0 };
    unsigned char buf[512];

    while (1) {
        if (timed_select(fd, &tv) <= 0) break;

        struct sockaddr_storage src;
        socklen_t slen = sizeof(src);
        int bytes = recvfrom(fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&src, &slen);
        if (bytes < 0) break;
        sa_unmap(&src);
        if (peer && !sa_same_addr(&src, peer)) continue;
        if (!has_tag(buf, bytes, tag)) continue;
        if (from) *from = src;
        return 1;
    }
    return 0;
}

int recv_primer(int fd, int timeout_sec, uint16_t tag, struct sockaddr_storage *from) {
    return wait_udp(fd, NULL, timeout_sec, tag, from);
}

int wait_probe(int proto, int fd, int number, const struct sockaddr_storage *peer,
               int timeout_sec, uint16_t tag) {
    char ip[INET6_ADDRSTRLEN];
    if (fd < 0) return 0;
    if (proto == PROTO_ICMP)
        return wait_icmp(fd, peer, number, timeout_sec, tag);
    if (proto == PROTO_TCP)
        return wait_tcp(fd, number, peer, timeout_sec);
    if (proto == PROTO_UDP && wait_udp(fd, peer, timeout_sec, tag, NULL)) {
        printf("  UDP port %d from %s\n", number, sa_ntop(peer, ip, sizeof(ip)));
        return 1;
    }
    return 0;
}
