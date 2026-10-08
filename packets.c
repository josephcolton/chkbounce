#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>

#include "global.h"
#include "protocol.h"
#include "packets.h"

/* ICMP/ICMPv6 header plus a short payload; same layout for both families */
struct icmp_send_hdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t cksum;
    uint16_t id;
    uint16_t seq;
    char     data[32];
} packed;

/* Bind fd to src's address (any port) when src is given.  Returns 0 or -1. */
static int bind_source(int fd, const struct sockaddr_storage *src) {
    if (!src) return 0;
    struct sockaddr_storage local = *src;
    sa_set_port(&local, 0);
    if (bind(fd, (struct sockaddr *)&local, sa_len(&local)) < 0) {
        perror("bind probe source address");
        return -1;
    }
    return 0;
}

/*
 * Send a complete ICMP message (header + body) on a raw socket of dst's
 * family.  For IPv4 the checksum is computed here; for ICMPv6 the kernel
 * fills it in (it covers a pseudo-header).  Returns bytes sent or -1.
 */
static int send_raw_icmp(const struct sockaddr_storage *dst,
                         const struct sockaddr_storage *src,
                         unsigned char *msg, size_t len) {
    int v6 = dst->ss_family == AF_INET6;
    int fd = socket(dst->ss_family, SOCK_RAW, v6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP);
    if (fd < 0) {
        perror("ICMP send: socket");
        return -1;
    }
    if (bind_source(fd, src) < 0) { close(fd); return -1; }

    msg[2] = msg[3] = 0;
    if (!v6) {
        uint16_t ck = checksum(msg, (int)len);
        memcpy(msg + 2, &ck, 2);
    }

    struct sockaddr_storage to = *dst;
    sa_set_port(&to, 0);
    int bytes = sendto(fd, msg, len, 0, (struct sockaddr *)&to, sa_len(&to));
    if (bytes < 0)
        perror("ICMP send: sendto");

    close(fd);
    return bytes;
}

int send_icmp_probe(const struct sockaddr_storage *dst,
                    const struct sockaddr_storage *src,
                    int icmp_type, int icmp_code, uint16_t tag) {
    struct icmp_send_hdr pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.type  = (uint8_t)icmp_type;
    pkt.code  = (uint8_t)icmp_code;
    pkt.id    = htons(PROBE_ICMP_ID);
    pkt.seq   = htons(tag);
    memset(pkt.data, 'a', sizeof(pkt.data));
    memcpy(pkt.data, PROBE_MAGIC, PROBE_MAGIC_LEN);
    return send_raw_icmp(dst, src, (unsigned char *)&pkt, sizeof(pkt));
}

/* PROBE_MAGIC followed by the tag in network order; returns the length. */
static size_t tagged_payload(unsigned char *buf, uint16_t tag) {
    memcpy(buf, PROBE_MAGIC, PROBE_MAGIC_LEN);
    uint16_t t = htons(tag);
    memcpy(buf + PROBE_MAGIC_LEN, &t, 2);
    return PROBE_MAGIC_LEN + 2;
}

/*
 * Build the datagram src -> dst (IP header + UDP header + payload) that an
 * ICMP error quotes, with valid IP and UDP checksums.  Returns its length.
 */
static size_t build_quote(unsigned char *buf, const struct sockaddr_storage *src,
                          const struct sockaddr_storage *dst,
                          const unsigned char *payload, size_t plen) {
    int    v6     = src->ss_family == AF_INET6;
    size_t iphlen = v6 ? 40 : 20;
    size_t udplen = 8 + plen;
    unsigned char *ip  = buf;
    unsigned char *udp = buf + iphlen;
    unsigned char  pseudo[40 + 8 + 64];
    size_t         pslen;

    memset(buf, 0, iphlen + udplen);
    if (v6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)src;
        const struct sockaddr_in6 *d6 = (const struct sockaddr_in6 *)dst;
        ip[0] = 0x60;                               /* version 6 */
        ip[4] = (unsigned char)(udplen >> 8);       /* payload length */
        ip[5] = (unsigned char)udplen;
        ip[6] = IPPROTO_UDP;                        /* next header */
        ip[7] = 64;                                 /* hop limit */
        memcpy(ip + 8,  &s6->sin6_addr, 16);
        memcpy(ip + 24, &d6->sin6_addr, 16);
        memcpy(udp,     &s6->sin6_port, 2);
        memcpy(udp + 2, &d6->sin6_port, 2);

        /* pseudo-header: src, dst, upper-layer length (32), zero, next header */
        memset(pseudo, 0, 40);
        memcpy(pseudo, ip + 8, 32);
        pseudo[34] = (unsigned char)(udplen >> 8);
        pseudo[35] = (unsigned char)udplen;
        pseudo[39] = IPPROTO_UDP;
        pslen = 40;
    } else {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)src;
        const struct sockaddr_in *d4 = (const struct sockaddr_in *)dst;
        size_t total = iphlen + udplen;
        ip[0] = 0x45;                               /* version 4, IHL 5 */
        ip[2] = (unsigned char)(total >> 8);
        ip[3] = (unsigned char)total;
        ip[8] = 64;                                 /* TTL */
        ip[9] = IPPROTO_UDP;
        memcpy(ip + 12, &s4->sin_addr, 4);
        memcpy(ip + 16, &d4->sin_addr, 4);
        uint16_t ck = checksum(ip, (int)iphlen);
        memcpy(ip + 10, &ck, 2);
        memcpy(udp,     &s4->sin_port, 2);
        memcpy(udp + 2, &d4->sin_port, 2);

        /* pseudo-header: src, dst, zero, protocol, UDP length */
        memset(pseudo, 0, 12);
        memcpy(pseudo, ip + 12, 8);
        pseudo[9]  = IPPROTO_UDP;
        pseudo[10] = (unsigned char)(udplen >> 8);
        pseudo[11] = (unsigned char)udplen;
        pslen = 12;
    }
    udp[4] = (unsigned char)(udplen >> 8);
    udp[5] = (unsigned char)udplen;
    memcpy(udp + 8, payload, plen);

    memcpy(pseudo + pslen, udp, udplen);
    uint16_t uck = checksum(pseudo, (int)(pslen + udplen));
    if (uck == 0) uck = 0xffff;                     /* 0 means "no checksum" */
    memcpy(udp + 6, &uck, 2);

    return iphlen + udplen;
}

int send_icmp_quoted(const struct sockaddr_storage *dst,
                     const struct sockaddr_storage *src, int icmp_type, int icmp_code,
                     const struct sockaddr_storage *inner_src,
                     const struct sockaddr_storage *inner_dst, uint16_t tag) {
    unsigned char payload[32];
    size_t plen = tagged_payload(payload, tag);

    /* 8-byte ICMP header (type, code, checksum, 4 unused bytes) + quote */
    unsigned char msg[8 + 40 + 8 + sizeof(payload)];
    memset(msg, 0, 8);
    msg[0] = (uint8_t)icmp_type;
    msg[1] = (uint8_t)icmp_code;
    size_t qlen = build_quote(msg + 8, inner_src, inner_dst, payload, plen);
    return send_raw_icmp(dst, src, msg, 8 + qlen);
}

int send_tcp_probe(const struct sockaddr_storage *dst,
                   const struct sockaddr_storage *src,
                   int port, int timeout_sec) {
    int fd = socket(dst->ss_family, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (bind_source(fd, src) < 0) { close(fd); return -1; }

    /* Non-blocking connect so we can apply a timeout */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_storage to = *dst;
    sa_set_port(&to, port);

    int ret = 0;
    if (connect(fd, (struct sockaddr *)&to, sa_len(&to)) < 0) {
        if (errno != EINPROGRESS) {
            close(fd);
            return 0;
        }
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        struct timeval tv = { timeout_sec, 0 };
        int r = select(fd + 1, NULL, &wfds, NULL, &tv);
        if (r <= 0) {
            close(fd);
            return 0;
        }
        int err = 0;
        socklen_t elen = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
        ret = (err == 0) ? 1 : 0;
    } else {
        ret = 1;
    }

    close(fd);
    return ret;
}

int send_udp_probe(const struct sockaddr_storage *dst,
                   const struct sockaddr_storage *src, int port, uint16_t tag) {
    int fd = socket(dst->ss_family, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    if (bind_source(fd, src) < 0) { close(fd); return -1; }

    struct sockaddr_storage to = *dst;
    sa_set_port(&to, port);

    unsigned char payload[32];
    size_t plen = tagged_payload(payload, tag);
    int bytes = sendto(fd, payload, plen, 0,
                       (struct sockaddr *)&to, sa_len(&to));
    if (bytes < 0)
        perror("send_udp_probe: sendto");

    close(fd);
    return bytes;
}

int send_probe(const struct sockaddr_storage *dst,
               const struct sockaddr_storage *src,
               int proto, int number, int code, int timeout_sec, uint16_t tag) {
    if (proto == PROTO_ICMP) return send_icmp_probe(dst, src, number, code, tag);
    if (proto == PROTO_TCP)  return send_tcp_probe(dst, src, number, timeout_sec);
    if (proto == PROTO_UDP)  return send_udp_probe(dst, src, number, tag);
    return -1;
}

int open_udp_local(const struct sockaddr_storage *local, int *port) {
    int fd = socket(local->ss_family, SOCK_DGRAM, 0);
    if (fd < 0) { perror("primer socket"); return -1; }
    if (bind_source(fd, local) < 0) { close(fd); return -1; }

    struct sockaddr_storage bound;
    socklen_t blen = sizeof(bound);
    if (getsockname(fd, (struct sockaddr *)&bound, &blen) < 0) {
        perror("primer socket: getsockname");
        close(fd);
        return -1;
    }
    *port = sa_get_port(&bound);
    return fd;
}

int send_tagged(int fd, const struct sockaddr_storage *dst, int port, uint16_t tag) {
    unsigned char payload[32];
    size_t plen = tagged_payload(payload, tag);
    struct sockaddr_storage to = *dst;
    sa_set_port(&to, port);
    int bytes = sendto(fd, payload, plen, 0, (struct sockaddr *)&to, sa_len(&to));
    if (bytes < 0)
        perror("primer: sendto");
    return bytes;
}
