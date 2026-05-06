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

#include "global.h"
#include "protocol.h"
#include "server.h"

/* ----------------------------------------------------------------- socket helpers */

static int open_tcp_listen(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("server: TCP socket"); return -1; }

    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "server: bind TCP %d: %s\n", port, strerror(errno));
        close(fd);
        return -1;
    }
    if (listen(fd, 4) < 0) {
        perror("server: listen");
        close(fd);
        return -1;
    }
    return fd;
}

static int open_udp_bind(int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("server: UDP socket"); return -1; }

    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "server: bind UDP %d: %s\n", port, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
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

static int wait_icmp(int icmp_fd, uint32_t client_ip_net,
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
        if (src.sin_addr.s_addr != client_ip_net) continue;

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

static int wait_udp(int fd, int port, uint32_t client_ip_net, int timeout_sec) {
    struct timeval tv = { timeout_sec, 0 };
    char buf[512];

    while (1) {
        if (timed_select(fd, &tv) <= 0) break;

        struct sockaddr_in src;
        socklen_t slen = sizeof(src);
        int bytes = recvfrom(fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&src, &slen);
        if (bytes < 0) break;
        if (src.sin_addr.s_addr != client_ip_net) continue;
        printf("  UDP port %d from %s\n", port, inet_ntoa(src.sin_addr));
        return 1;
    }
    return 0;
}

/* ---------------------------------------------------------------- client session */

static void handle_client(int ctrl_fd, uint32_t client_ip_net, int timeout_sec) {
    uint8_t  msg_type;
    void    *payload;
    uint32_t plen;

    /* Receive negotiate — informational only; no sockets opened yet */
    if (recv_msg(ctrl_fd, &msg_type, &payload, &plen) < 0 ||
        msg_type != MSG_NEGOTIATE) {
        fprintf(stderr, "server: expected MSG_NEGOTIATE\n");
        return;
    }
    uint32_t probe_count;
    memcpy(&probe_count, payload, 4);
    probe_count = ntohl(probe_count);
    free(payload);
    printf("Client negotiated %u probes\n", probe_count);

    /* Signal ready; per-probe sockets will be opened on demand */
    send_msg(ctrl_fd, MSG_READY, NULL, 0);

    /*
     * Keep one raw ICMP socket open for the whole session — it receives
     * all ICMP regardless of type, so there's no need to reopen it per probe.
     */
    int icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_fd < 0)
        perror("server: ICMP raw socket (ICMP probes will fail)");

    /* Probe loop: open socket → signal ready → receive probe → report → close */
    while (1) {
        if (recv_msg(ctrl_fd, &msg_type, &payload, &plen) < 0) break;

        if (msg_type == MSG_DONE) { free(payload); break; }

        if (msg_type != MSG_PROBE_NEXT ||
            plen < sizeof(struct probe_next_payload)) {
            free(payload);
            continue;
        }

        struct probe_next_payload *pnp = payload;
        int proto  = pnp->proto;
        int number = ntohs(pnp->number);
        free(payload);
        payload = NULL;

        /* Open the probe socket for this one probe */
        int probe_fd = -1;
        if (proto == PROTO_ICMP) {
            probe_fd = icmp_fd;          /* reuse session socket */
        } else if (proto == PROTO_TCP) {
            probe_fd = open_tcp_listen(number);
            if (probe_fd >= 0)
                printf("Listening TCP %d\n", number);
            else
                fprintf(stderr, "server: could not open TCP %d\n", number);
        } else if (proto == PROTO_UDP) {
            probe_fd = open_udp_bind(number);
            if (probe_fd >= 0)
                printf("Listening UDP %d\n", number);
            else
                fprintf(stderr, "server: could not open UDP %d\n", number);
        }

        /* Tell client to fire the probe */
        send_msg(ctrl_fd, MSG_PROBE_GO, NULL, 0);

        /* Wait: returns as soon as the probe arrives or timeout expires */
        int received = 0;
        if (probe_fd >= 0) {
            if (proto == PROTO_ICMP)
                received = wait_icmp(icmp_fd, client_ip_net, number, timeout_sec);
            else if (proto == PROTO_TCP)
                received = wait_tcp(probe_fd, number, timeout_sec);
            else if (proto == PROTO_UDP)
                received = wait_udp(probe_fd, number, client_ip_net, timeout_sec);
        }

        /* Close per-probe socket; ICMP fd is kept open for the session */
        if (proto != PROTO_ICMP && probe_fd >= 0)
            close(probe_fd);

        struct probe_result_payload res;
        res.proto    = proto;
        res.number   = htons(number);
        res.received = (uint8_t)received;
        send_msg(ctrl_fd, MSG_PROBE_RESULT, &res, sizeof(res));
    }

    if (icmp_fd >= 0) close(icmp_fd);
}

/* ------------------------------------------------------------------- run_server */

void run_server(int control_port, int timeout_sec) {
    int srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv_fd < 0) { perror("server: socket"); return; }

    int on = 1;
    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(control_port);

    if (bind(srv_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("server: bind control port");
        close(srv_fd);
        return;
    }
    listen(srv_fd, 4);
    printf("Server listening on control port %d  (Ctrl-C to stop)\n\n", control_port);

    /* Accept clients forever; Ctrl-C (SIGINT default) terminates the process */
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t clen = sizeof(client_addr);
        int ctrl_fd = accept(srv_fd, (struct sockaddr *)&client_addr, &clen);
        if (ctrl_fd < 0) {
            perror("server: accept");
            continue;   /* transient error; keep listening */
        }

        printf("Client connected from %s\n", inet_ntoa(client_addr.sin_addr));
        handle_client(ctrl_fd, client_addr.sin_addr.s_addr, timeout_sec);
        close(ctrl_fd);
        printf("Session complete.  Waiting for next client...\n\n");
    }
}
