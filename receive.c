#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>

#include "protocol.h"
#include "receive.h"

/* ----------------------------------------------------------------- socket helpers */

static int open_tcp_listen(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("TCP socket"); return -1; }

    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "bind TCP %d: %s\n", port, strerror(errno));
        close(fd);
        return -1;
    }
    if (listen(fd, 4) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }
    return fd;
}

static int open_udp_bind(int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("UDP socket"); return -1; }

    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "bind UDP %d: %s\n", port, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

int open_icmp_raw(void) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0)
        perror("ICMP raw socket (ICMP probes will fail)");
    return fd;
}

int open_probe_socket(int proto, int number, int icmp_fd) {
    int fd = -1;
    if (proto == PROTO_ICMP) {
        fd = icmp_fd;
    } else if (proto == PROTO_TCP) {
        fd = open_tcp_listen(number);
        if (fd >= 0)
            printf("Listening TCP %d\n", number);
        else
            fprintf(stderr, "could not open TCP %d\n", number);
    } else if (proto == PROTO_UDP) {
        fd = open_udp_bind(number);
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

static int wait_icmp(int icmp_fd, uint32_t src_ip_net,
                     int expected_type, int timeout_sec) {
    struct timeval tv = { timeout_sec, 0 };
    char buf[4096];

    while (1) {
        if (timed_select(icmp_fd, &tv) <= 0) break;

        struct sockaddr_in src;
        socklen_t slen = sizeof(src);
        int bytes = recvfrom(icmp_fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&src, &slen);
        if (bytes < 0) break;
        if (src.sin_addr.s_addr != src_ip_net) continue;

        int ihl = ((unsigned char)buf[0] & 0x0f) * 4;
        if (bytes < ihl + 1) continue;
        int got_type = (unsigned char)buf[ihl];

        printf("  ICMP type %d from %s\n", got_type, inet_ntoa(src.sin_addr));
        if (got_type == expected_type) return 1;
    }
    return 0;
}

static int wait_tcp(int fd, int port, int timeout_sec) {
    struct timeval tv = { timeout_sec, 0 };
    if (timed_select(fd, &tv) <= 0) return 0;

    struct sockaddr_in src;
    socklen_t slen = sizeof(src);
    int conn = accept(fd, (struct sockaddr *)&src, &slen);
    if (conn < 0) return 0;
    printf("  TCP port %d from %s\n", port, inet_ntoa(src.sin_addr));
    close(conn);
    return 1;
}

static int wait_udp(int fd, int port, uint32_t src_ip_net, int timeout_sec) {
    struct timeval tv = { timeout_sec, 0 };
    char buf[512];

    while (1) {
        if (timed_select(fd, &tv) <= 0) break;

        struct sockaddr_in src;
        socklen_t slen = sizeof(src);
        int bytes = recvfrom(fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&src, &slen);
        if (bytes < 0) break;
        if (src.sin_addr.s_addr != src_ip_net) continue;
        printf("  UDP port %d from %s\n", port, inet_ntoa(src.sin_addr));
        return 1;
    }
    return 0;
}

int wait_probe(int proto, int fd, int number, uint32_t src_ip_net, int timeout_sec) {
    if (fd < 0) return 0;
    if (proto == PROTO_ICMP)
        return wait_icmp(fd, src_ip_net, number, timeout_sec);
    if (proto == PROTO_TCP)
        return wait_tcp(fd, number, timeout_sec);
    if (proto == PROTO_UDP)
        return wait_udp(fd, number, src_ip_net, timeout_sec);
    return 0;
}
