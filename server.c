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

struct session {
    int ctrl_fd;
    int icmp_fd;               /* raw ICMP/ICMPv6 socket, shared by all probes */
    int quote_fd;              /* UDP socket that receives the client's primers */
    int quote_port;
    int family;
    int timeout_sec;
    const struct sockaddr_storage *peer;   /* client, as seen on control conn */
    const struct sockaddr_storage *local;  /* our end of the control conn */
    char client_ip[INET6_ADDRSTRLEN];
};

/* Forward probe: we are the receiver; the client sends. */
static void serve_forward(struct session *s, const struct probe_next_payload *pnp) {
    int proto   = pnp->proto;
    int number  = ntohs(pnp->number);
    int code    = pnp->code;
    int quoted  = proto == PROTO_ICMP && (pnp->flags & PROBE_FLAG_QUOTE);
    uint16_t tag = probe_tag(number, pnp->attempt, 0);
    int received = RESULT_UNAVAILABLE;   /* until a receiving socket is up */

    if (quoted) {
        /*
         * Prime: send a UDP datagram from a fresh port to the client's quote
         * port so middleboxes see a flow; the client's error will quote it.
         * The client may need up to a timeout to receive our primer first,
         * so wait two timeouts for the error.
         */
        int pr_port = 0;
        int pfd = open_udp_local(s->local, &pr_port);
        if (pfd >= 0)
            send_tagged(pfd, s->peer, ntohs(pnp->port), tag);

        struct port_payload go = { htons((uint16_t)(pfd >= 0 ? pr_port : 0)) };
        send_msg(s->ctrl_fd, MSG_PROBE_GO, &go, sizeof(go));

        if (pfd >= 0 && s->icmp_fd >= 0)
            received = wait_icmp_quoted(s->icmp_fd, s->peer, number, code, pr_port,
                                        2 * s->timeout_sec);
        if (pfd >= 0)
            close(pfd);
    } else {
        /* Open the probe socket for this one probe */
        int probe_fd = open_probe_socket(s->family, proto, number, s->icmp_fd);

        /* Tell client to fire the probe */
        struct port_payload go = { 0 };
        send_msg(s->ctrl_fd, MSG_PROBE_GO, &go, sizeof(go));

        /* Wait: returns as soon as the probe arrives or timeout expires */
        if (probe_fd >= 0)
            received = wait_probe(proto, probe_fd, number, code, s->peer,
                                  s->timeout_sec, tag);

        /* Close per-probe socket; ICMP fd is kept open for the session */
        close_probe_socket(proto, probe_fd);
    }

    struct probe_result_payload res;
    res.proto    = proto;
    res.number   = htons(number);
    res.received = (uint8_t)received;
    send_msg(s->ctrl_fd, MSG_PROBE_RESULT, &res, sizeof(res));
}

/* Reverse probe: we send; the client is already listening. */
static void serve_reverse(struct session *s, const struct probe_next_payload *pnp) {
    int proto   = pnp->proto;
    int number  = ntohs(pnp->number);
    int code    = pnp->code;
    int quoted  = proto == PROTO_ICMP && (pnp->flags & PROBE_FLAG_QUOTE);
    uint16_t tag = probe_tag(number, pnp->attempt, 1);
    struct rprobe_sent_payload sent = { 0 };

    if (quoted) {
        /*
         * Quote the primer the client sent to our quote port.  Use its
         * observed source (correct through NAT) if it arrived; otherwise
         * fall back to the client's address and the port it reported.
         */
        struct sockaddr_storage inner_src, inner_dst = *s->local;
        sent.primed = s->quote_fd >= 0 &&
                      recv_primer(s->quote_fd, s->timeout_sec, tag, &inner_src);
        if (!sent.primed) {
            inner_src = *s->peer;
            sa_set_port(&inner_src, ntohs(pnp->port));
        }
        sa_set_port(&inner_dst, s->quote_port);

        printf("Sending %s %d code %d (quoted, %s) to %s\n", proto_name(proto, s->family),
               number, code, sent.primed ? "primed" : "primer not received", s->client_ip);
        sent.sent = send_icmp_quoted(s->peer, s->local, number, code,
                                     &inner_src, &inner_dst, tag) >= 0;
    } else {
        if (proto == PROTO_ICMP)
            printf("Sending %s %d code %d to %s\n", proto_name(proto, s->family),
                   number, code, s->client_ip);
        else
            printf("Sending %s %d to %s\n", proto_name(proto, s->family), number,
                   s->client_ip);
        sent.sent = send_probe(s->peer, s->local, proto, number, code,
                               s->timeout_sec, tag) >= 0;
    }
    send_msg(s->ctrl_fd, MSG_RPROBE_SENT, &sent, sizeof(sent));
}

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

    struct session s;
    memset(&s, 0, sizeof(s));
    s.ctrl_fd     = ctrl_fd;
    s.family      = peer->ss_family;
    s.timeout_sec = timeout_sec;
    s.peer        = peer;
    s.local       = local;
    sa_ntop(peer, s.client_ip, sizeof(s.client_ip));

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
    printf("Client negotiated %u probes (%s)\n", probe_count, family_name(s.family));

    /*
     * Session sockets: one raw ICMP socket receives all ICMP regardless of
     * type, and one UDP socket receives quote primers for reverse probes.
     */
    s.icmp_fd  = open_icmp_raw(s.family);
    s.quote_fd = open_udp_local(local, &s.quote_port);

    /* Signal ready; per-probe sockets will be opened on demand */
    struct ready_payload ready;
    memset(&ready, 0, sizeof(ready));
    ready.port = htons((uint16_t)(s.quote_fd >= 0 ? s.quote_port : 0));
    snprintf(ready.observed_addr, sizeof(ready.observed_addr), "%s", s.client_ip);
    send_msg(ctrl_fd, MSG_READY, &ready, sizeof(ready));

    while (1) {
        if (recv_msg(ctrl_fd, &msg_type, &payload, &plen) < 0) break;

        if (msg_type == MSG_DONE) { free(payload); break; }

        if ((msg_type != MSG_PROBE_NEXT && msg_type != MSG_RPROBE_REQ) ||
            plen < sizeof(struct probe_next_payload)) {
            free(payload);
            continue;
        }

        if (msg_type == MSG_PROBE_NEXT)
            serve_forward(&s, payload);
        else
            serve_reverse(&s, payload);
        free(payload);
    }

    if (s.icmp_fd >= 0)  close(s.icmp_fd);
    if (s.quote_fd >= 0) close(s.quote_fd);
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
        set_nodelay(ctrl_fd);
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
