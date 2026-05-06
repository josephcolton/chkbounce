#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "global.h"
#include "protocol.h"
#include "packets.h"
#include "client.h"

struct result {
    int proto;
    int number;
    int received;
};

/* ------------------------------------------------------------------ helpers */

static int ctrl_connect(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("client: socket"); return -1; }

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port   = htons(port);
    if (inet_pton(AF_INET, ip, &srv.sin_addr) != 1) {
        fprintf(stderr, "client: invalid resolved IP: %s\n", ip);
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        perror("client: connect to server");
        close(fd);
        return -1;
    }
    return fd;
}

static int send_negotiate(int fd,
                          int *icmp_types, int icmp_count,
                          int *tcp_ports,  int tcp_count,
                          int *udp_ports,  int udp_count) {
    uint32_t total = (uint32_t)(icmp_count + tcp_count + udp_count);
    size_t   plen  = 4 + total * sizeof(struct probe_entry);
    char    *buf   = malloc(plen);
    if (!buf) return -1;

    uint32_t net_total = htonl(total);
    memcpy(buf, &net_total, 4);

    struct probe_entry *pe = (struct probe_entry *)(buf + 4);
    int idx = 0;

    for (int i = 0; i < icmp_count; i++, idx++) {
        pe[idx].proto  = PROTO_ICMP;
        pe[idx].number = htons((uint16_t)icmp_types[i]);
    }
    for (int i = 0; i < tcp_count; i++, idx++) {
        pe[idx].proto  = PROTO_TCP;
        pe[idx].number = htons((uint16_t)tcp_ports[i]);
    }
    for (int i = 0; i < udp_count; i++, idx++) {
        pe[idx].proto  = PROTO_UDP;
        pe[idx].number = htons((uint16_t)udp_ports[i]);
    }

    int r = send_msg(fd, MSG_NEGOTIATE, buf, (uint32_t)plen);
    free(buf);
    return r;
}

/* Write a formatted line to stdout and, if outfile is non-NULL, to outfile too. */
static void rprintf(FILE *outfile, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    if (outfile) {
        va_start(ap, fmt);
        vfprintf(outfile, fmt, ap);
        va_end(ap);
    }
}

static void print_report(struct result *results, int count, FILE *outfile) {
    int received = 0;
    for (int i = 0; i < count; i++)
        if (results[i].received) received++;

    rprintf(outfile, "\n=== chkbounce Report ===\n");

    int has_icmp = 0;
    for (int i = 0; i < count; i++) if (results[i].proto == PROTO_ICMP) { has_icmp = 1; break; }
    if (has_icmp) {
        rprintf(outfile, "\nICMP Probes:\n");
        for (int i = 0; i < count; i++) {
            if (results[i].proto != PROTO_ICMP) continue;
            rprintf(outfile, "  Type %3d: %s\n", results[i].number,
                    results[i].received ? "RECEIVED" : "not received");
        }
    }

    int has_tcp = 0;
    for (int i = 0; i < count; i++) if (results[i].proto == PROTO_TCP) { has_tcp = 1; break; }
    if (has_tcp) {
        rprintf(outfile, "\nTCP Probes:\n");
        for (int i = 0; i < count; i++) {
            if (results[i].proto != PROTO_TCP) continue;
            rprintf(outfile, "  Port %5d: %s\n", results[i].number,
                    results[i].received ? "RECEIVED" : "not received");
        }
    }

    int has_udp = 0;
    for (int i = 0; i < count; i++) if (results[i].proto == PROTO_UDP) { has_udp = 1; break; }
    if (has_udp) {
        rprintf(outfile, "\nUDP Probes:\n");
        for (int i = 0; i < count; i++) {
            if (results[i].proto != PROTO_UDP) continue;
            rprintf(outfile, "  Port %5d: %s\n", results[i].number,
                    results[i].received ? "RECEIVED" : "not received");
        }
    }

    rprintf(outfile, "\nSummary: %d of %d probes received\n", received, count);
}

/* ----------------------------------------------------------------- run_client */

void run_client(const char *server_host, int control_port, int timeout_sec,
                int *icmp_types, int icmp_count,
                int *tcp_ports,  int tcp_count,
                int *udp_ports,  int udp_count,
                const char *output_file) {
    int total = icmp_count + tcp_count + udp_count;
    if (total == 0) {
        fprintf(stderr, "client: no probes specified (use -i, -t, or -u)\n");
        return;
    }

    /* Resolve hostname once; all probe functions receive the dotted-decimal IP */
    char server_ip[INET_ADDRSTRLEN];
    if (resolve_hostname(server_host, server_ip, sizeof(server_ip)) < 0)
        return;
    if (strcmp(server_host, server_ip) != 0)
        printf("Resolved %s -> %s\n", server_host, server_ip);

    printf("Connecting to %s:%d\n", server_ip, control_port);
    int ctrl_fd = ctrl_connect(server_ip, control_port);
    if (ctrl_fd < 0) return;

    if (send_negotiate(ctrl_fd, icmp_types, icmp_count,
                       tcp_ports, tcp_count, udp_ports, udp_count) < 0) {
        fprintf(stderr, "client: send_negotiate failed\n");
        close(ctrl_fd);
        return;
    }

    uint8_t  msg_type;
    void    *payload;
    uint32_t plen;

    if (recv_msg(ctrl_fd, &msg_type, &payload, &plen) < 0 ||
        msg_type != MSG_READY) {
        fprintf(stderr, "client: expected MSG_READY\n");
        close(ctrl_fd);
        return;
    }
    free(payload);
    printf("Server ready. Sending %d probes...\n\n", total);

    struct result *results = calloc(total, sizeof(*results));
    if (!results) { close(ctrl_fd); return; }
    int ridx = 0;

    /* ---- ICMP probes ---- */
    for (int i = 0; i < icmp_count; i++) {
        int t = icmp_types[i];
        struct probe_next_payload pnp = { PROTO_ICMP, htons((uint16_t)t) };
        send_msg(ctrl_fd, MSG_PROBE_NEXT, &pnp, sizeof(pnp));

        if (recv_msg(ctrl_fd, &msg_type, &payload, &plen) < 0 ||
            msg_type != MSG_PROBE_GO) {
            fprintf(stderr, "client: expected MSG_PROBE_GO for ICMP %d\n", t);
            free(payload);
            break;
        }
        free(payload);

        send_icmp_probe(server_ip, t);

        if (recv_msg(ctrl_fd, &msg_type, &payload, &plen) < 0 ||
            msg_type != MSG_PROBE_RESULT) {
            fprintf(stderr, "client: expected MSG_PROBE_RESULT for ICMP %d\n", t);
            free(payload);
            break;
        }
        struct probe_result_payload *rp = payload;
        results[ridx].proto    = PROTO_ICMP;
        results[ridx].number   = t;
        results[ridx].received = rp->received;
        ridx++;
        free(payload);
    }

    /* ---- TCP probes ---- */
    for (int i = 0; i < tcp_count; i++) {
        int port = tcp_ports[i];
        struct probe_next_payload pnp = { PROTO_TCP, htons((uint16_t)port) };
        send_msg(ctrl_fd, MSG_PROBE_NEXT, &pnp, sizeof(pnp));

        if (recv_msg(ctrl_fd, &msg_type, &payload, &plen) < 0 ||
            msg_type != MSG_PROBE_GO) {
            fprintf(stderr, "client: expected MSG_PROBE_GO for TCP %d\n", port);
            free(payload);
            break;
        }
        free(payload);

        send_tcp_probe(server_ip, port, timeout_sec);

        if (recv_msg(ctrl_fd, &msg_type, &payload, &plen) < 0 ||
            msg_type != MSG_PROBE_RESULT) {
            fprintf(stderr, "client: expected MSG_PROBE_RESULT for TCP %d\n", port);
            free(payload);
            break;
        }
        struct probe_result_payload *rp = payload;
        results[ridx].proto    = PROTO_TCP;
        results[ridx].number   = port;
        results[ridx].received = rp->received;
        ridx++;
        free(payload);
    }

    /* ---- UDP probes ---- */
    for (int i = 0; i < udp_count; i++) {
        int port = udp_ports[i];
        struct probe_next_payload pnp = { PROTO_UDP, htons((uint16_t)port) };
        send_msg(ctrl_fd, MSG_PROBE_NEXT, &pnp, sizeof(pnp));

        if (recv_msg(ctrl_fd, &msg_type, &payload, &plen) < 0 ||
            msg_type != MSG_PROBE_GO) {
            fprintf(stderr, "client: expected MSG_PROBE_GO for UDP %d\n", port);
            free(payload);
            break;
        }
        free(payload);

        send_udp_probe(server_ip, port);

        if (recv_msg(ctrl_fd, &msg_type, &payload, &plen) < 0 ||
            msg_type != MSG_PROBE_RESULT) {
            fprintf(stderr, "client: expected MSG_PROBE_RESULT for UDP %d\n", port);
            free(payload);
            break;
        }
        struct probe_result_payload *rp = payload;
        results[ridx].proto    = PROTO_UDP;
        results[ridx].number   = port;
        results[ridx].received = rp->received;
        ridx++;
        free(payload);
    }

    send_msg(ctrl_fd, MSG_DONE, NULL, 0);
    close(ctrl_fd);

    FILE *outfile = NULL;
    if (output_file) {
        outfile = fopen(output_file, "w");
        if (!outfile)
            perror(output_file);
        else
            printf("Writing report to %s\n", output_file);
    }

    print_report(results, ridx, outfile);

    if (outfile)
        fclose(outfile);
    free(results);
}
