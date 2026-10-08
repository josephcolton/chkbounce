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
    int icmp_fd = open_icmp_raw();

    char client_ip[INET_ADDRSTRLEN];
    struct in_addr cia = { client_ip_net };
    inet_ntop(AF_INET, &cia, client_ip, sizeof(client_ip));

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
            printf("Sending %s %d to %s\n", proto_name(proto), number, client_ip);
            send_probe(client_ip, proto, number, timeout_sec);
            send_msg(ctrl_fd, MSG_RPROBE_SENT, NULL, 0);
            continue;
        }

        /* Open the probe socket for this one probe */
        int probe_fd = open_probe_socket(proto, number, icmp_fd);

        /* Tell client to fire the probe */
        send_msg(ctrl_fd, MSG_PROBE_GO, NULL, 0);

        /* Wait: returns as soon as the probe arrives or timeout expires */
        int received = wait_probe(proto, probe_fd, number, client_ip_net, timeout_sec);

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
