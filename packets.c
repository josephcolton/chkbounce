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
#include "packets.h"

/* ICMP header without the 56-byte data payload used for raw sends */
struct icmp_send_hdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t cksum;
    uint16_t id;
    uint16_t seq;
    char     data[32];
} packed;

int send_icmp_probe(const char *dstip, int icmp_type) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) {
        perror("send_icmp_probe: socket");
        return -1;
    }

    struct icmp_send_hdr pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.type  = (uint8_t)icmp_type;
    pkt.code  = 0;
    pkt.id    = htons(0x1234);
    pkt.seq   = htons(1);
    memset(pkt.data, 'a', sizeof(pkt.data));
    pkt.cksum = checksum(&pkt, sizeof(pkt));

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, dstip, &dst.sin_addr);

    int bytes = sendto(fd, &pkt, sizeof(pkt), 0,
                       (struct sockaddr *)&dst, sizeof(dst));
    if (bytes < 0)
        perror("send_icmp_probe: sendto");

    close(fd);
    return bytes;
}

int send_tcp_probe(const char *dstip, int port, int timeout_sec) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    /* Non-blocking connect so we can apply a timeout */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(port);
    inet_pton(AF_INET, dstip, &dst.sin_addr);

    int ret = 0;
    if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
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

int send_udp_probe(const char *dstip, int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(port);
    inet_pton(AF_INET, dstip, &dst.sin_addr);

    const char payload[] = "chkbounce";
    int bytes = sendto(fd, payload, sizeof(payload), 0,
                       (struct sockaddr *)&dst, sizeof(dst));
    if (bytes < 0)
        perror("send_udp_probe: sendto");

    close(fd);
    return bytes;
}
