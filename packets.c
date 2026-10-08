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

int send_icmp_probe(const struct sockaddr_storage *dst,
                    const struct sockaddr_storage *src,
                    int icmp_type, int reverse) {
    int v6 = dst->ss_family == AF_INET6;
    int fd = socket(dst->ss_family, SOCK_RAW, v6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP);
    if (fd < 0) {
        perror("send_icmp_probe: socket");
        return -1;
    }
    if (bind_source(fd, src) < 0) { close(fd); return -1; }

    struct icmp_send_hdr pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.type  = (uint8_t)icmp_type;
    pkt.code  = 0;
    pkt.id    = htons(PROBE_ICMP_ID);
    pkt.seq   = htons(probe_icmp_seq(icmp_type, reverse));
    memset(pkt.data, 'a', sizeof(pkt.data));
    memcpy(pkt.data, PROBE_MAGIC, sizeof(PROBE_MAGIC) - 1);
    /* The kernel fills in the ICMPv6 checksum (it covers a pseudo-header) */
    if (!v6)
        pkt.cksum = checksum(&pkt, sizeof(pkt));

    struct sockaddr_storage to = *dst;
    sa_set_port(&to, 0);
    int bytes = sendto(fd, &pkt, sizeof(pkt), 0,
                       (struct sockaddr *)&to, sa_len(&to));
    if (bytes < 0)
        perror("send_icmp_probe: sendto");

    close(fd);
    return bytes;
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
                   const struct sockaddr_storage *src, int port) {
    int fd = socket(dst->ss_family, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    if (bind_source(fd, src) < 0) { close(fd); return -1; }

    struct sockaddr_storage to = *dst;
    sa_set_port(&to, port);

    const char payload[] = PROBE_MAGIC;
    int bytes = sendto(fd, payload, sizeof(payload), 0,
                       (struct sockaddr *)&to, sa_len(&to));
    if (bytes < 0)
        perror("send_udp_probe: sendto");

    close(fd);
    return bytes;
}

int send_probe(const struct sockaddr_storage *dst,
               const struct sockaddr_storage *src,
               int proto, int number, int timeout_sec, int reverse) {
    if (proto == PROTO_ICMP) return send_icmp_probe(dst, src, number, reverse);
    if (proto == PROTO_TCP)  return send_tcp_probe(dst, src, number, timeout_sec);
    if (proto == PROTO_UDP)  return send_udp_probe(dst, src, number);
    return -1;
}
