#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "global.h"
#include "protocol.h"
#include "packets.h"
#include "receive.h"
#include "server.h"

/* ---------------------------------------------------------------- client session */

/*
 * peer  - the client's address as seen on the control connection
 * local - our end of the control connection; probes we send leave from here
 * The session's address family (IPv4 or IPv6) is peer's family.
 */
static void handle_client(int ctrl_fd, const struct sockaddr_storage *peer,
                          const struct sockaddr_storage *local, int timeout_sec) {
    uint8_t  msg_type;
    void    *payload;
    uint32_t plen;
    int      family = peer->ss_family;

    /* Receive negotiate — informational only; no sockets opened yet */
    if (recv_msg(ctrl_fd, &msg_type, &payload, &plen) < 0 ||
        msg_type != MSG_NEGOTIATE || plen < 4) {
        fprintf(stderr, "server: expected MSG_NEGOTIATE\n");
        free(payload);
        return;
    }
    uint32_t probe_count;
    memcpy(&probe_count, payload, 4);
    probe_count = ntohl(probe_count);
    free(payload);
    printf("Client negotiated %u probes (%s)\n", probe_count, family_name(family));

    /* Signal ready; per-probe sockets will be opened on demand */
    send_msg(ctrl_fd, MSG_READY, NULL, 0);

    /*
     * Keep one raw ICMP socket open for the whole session — it receives
     * all ICMP regardless of type, so there's no need to reopen it per probe.
     */
    int icmp_fd = open_icmp_raw(family);

    char client_ip[INET6_ADDRSTRLEN];
    sa_ntop(peer, client_ip, sizeof(client_ip));

    /*
     * Probe loop.  Forward: open socket -> signal go -> receive probe ->
     * report -> close.  Reverse: send the probe to the client -> signal sent.
     */
    while (1) {
        if (recv_msg(ctrl_fd, &msg_type, &payload, &plen) < 0) break;

        if (msg_type == MSG_DONE) { free(payload); break; }

        if ((msg_type != MSG_PROBE_NEXT && msg_type != MSG_RPROBE_REQ) ||
            plen < sizeof(struct probe_next_payload)) {
            free(payload);
            continue;
        }

        struct probe_next_payload *pnp = payload;
        int proto  = pnp->proto;
        int number = ntohs(pnp->number);
        free(payload);
        payload = NULL;

        if (msg_type == MSG_RPROBE_REQ) {
            printf("Sending %s %d to %s\n", proto_name(proto, family), number, client_ip);
            send_probe(peer, local, proto, number, timeout_sec, 1);
            send_msg(ctrl_fd, MSG_RPROBE_SENT, NULL, 0);
            continue;
        }

        /* Open the probe socket for this one probe */
        int probe_fd = open_probe_socket(family, proto, number, icmp_fd);

        /* Tell client to fire the probe */
        send_msg(ctrl_fd, MSG_PROBE_GO, NULL, 0);

        /* Wait: returns as soon as the probe arrives or timeout expires */
        int received = wait_probe(proto, probe_fd, number, peer, timeout_sec, 0);

        /* Close per-probe socket; ICMP fd is kept open for the session */
        close_probe_socket(proto, probe_fd);

        struct probe_result_payload res;
        res.proto    = proto;
        res.number   = htons(number);
        res.received = (uint8_t)received;
        send_msg(ctrl_fd, MSG_PROBE_RESULT, &res, sizeof(res));
    }

    if (icmp_fd >= 0) close(icmp_fd);
}

/* ------------------------------------------------------------------- run_server */

/*
 * Control listener.  AF_UNSPEC: one dual-stack IPv6 socket (IPv4 clients
 * arrive as ::ffff:a.b.c.d), falling back to IPv4 if IPv6 is unavailable.
 * AF_INET / AF_INET6: that family only.
 */
static int open_control_listener(int port, int family) {
    int fd = -1;
    struct sockaddr_storage addr;
    int on = 1, off = 0;

    if (family != AF_INET) {
        fd = socket(AF_INET6, SOCK_STREAM, 0);
        if (fd >= 0) {
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
                       family == AF_INET6 ? &on : &off, sizeof(int));
            memset(&addr, 0, sizeof(addr));
            addr.ss_family = AF_INET6;
        } else if (family == AF_INET6) {
            perror("server: IPv6 socket");
            return -1;
        }
    }
    if (fd < 0) {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) { perror("server: socket"); return -1; }
        memset(&addr, 0, sizeof(addr));
        addr.ss_family = AF_INET;
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    sa_set_port(&addr, port);
    if (bind(fd, (struct sockaddr *)&addr, sa_len(&addr)) < 0) {
        perror("server: bind control port");
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

void run_server(int control_port, int timeout_sec, int family) {
    int srv_fd = open_control_listener(control_port, family);
    if (srv_fd < 0) return;

    printf("Server listening on control port %d (%s)  (Ctrl-C to stop)\n\n",
           control_port,
           family == AF_INET ? "IPv4" : family == AF_INET6 ? "IPv6" : "IPv4+IPv6");

    /* Accept clients forever; Ctrl-C (SIGINT default) terminates the process */
    while (1) {
        struct sockaddr_storage peer, local;
        socklen_t plen = sizeof(peer), llen = sizeof(local);
        int ctrl_fd = accept(srv_fd, (struct sockaddr *)&peer, &plen);
        if (ctrl_fd < 0) {
            perror("server: accept");
            continue;   /* transient error; keep listening */
        }
        if (getsockname(ctrl_fd, (struct sockaddr *)&local, &llen) < 0) {
            perror("server: getsockname");
            close(ctrl_fd);
            continue;
        }
        sa_unmap(&peer);
        sa_unmap(&local);

        char ip[INET6_ADDRSTRLEN], ts[32];
        printf("%s Client connected from %s\n",
               timestamp_utc(ts, sizeof(ts)), sa_ntop(&peer, ip, sizeof(ip)));
        handle_client(ctrl_fd, &peer, &local, timeout_sec);
        close(ctrl_fd);
        printf("%s Session complete.  Waiting for next client...\n\n",
               timestamp_utc(ts, sizeof(ts)));
    }
}
