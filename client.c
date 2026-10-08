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
#include "receive.h"
#include "client.h"

/* fwd/rev: 1 = received, 0 = not received, -1 = not tested */
struct result {
    int proto;
    int number;
    int fwd;
    int rev;
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

static const char *status(int r) {
    return r < 0 ? "-" : r ? "RECEIVED" : "not received";
}

static void print_section(struct result *results, int count, int proto,
                          int directions, FILE *outfile) {
    int any = 0;
    for (int i = 0; i < count; i++) if (results[i].proto == proto) { any = 1; break; }
    if (!any) return;

    const char *label = proto == PROTO_ICMP ? "Type" : "Port";
    int width = proto == PROTO_ICMP ? 3 : 5;

    rprintf(outfile, "\n%s Probes:\n", proto_name(proto));
    if (directions == DIR_BOTH)
        rprintf(outfile, "  %*s  %-14s %-14s\n", (int)strlen(label) + width + 2, "",
                "client->server", "server->client");

    for (int i = 0; i < count; i++) {
        struct result *r = &results[i];
        if (r->proto != proto) continue;
        if (directions == DIR_BOTH)
            rprintf(outfile, "  %s %*d:  %-14s %-14s%s\n", label, width, r->number,
                    status(r->fwd), status(r->rev),
                    (r->fwd >= 0 && r->rev >= 0 && r->fwd != r->rev) ? " ASYMMETRIC" : "");
        else
            rprintf(outfile, "  %s %*d: %s\n", label, width, r->number,
                    status(directions == DIR_FORWARD ? r->fwd : r->rev));
    }
}

static void print_report(struct result *results, int count, int directions,
                         FILE *outfile) {
    rprintf(outfile, "\n=== chkbounce Report ===\n");
    if (directions == DIR_FORWARD)
        rprintf(outfile, "Direction: client -> server\n");
    else if (directions == DIR_REVERSE)
        rprintf(outfile, "Direction: server -> client\n");
    else
        rprintf(outfile, "Direction: both\n");

    print_section(results, count, PROTO_ICMP, directions, outfile);
    print_section(results, count, PROTO_TCP,  directions, outfile);
    print_section(results, count, PROTO_UDP,  directions, outfile);

    int fwd = 0, rev = 0, fwd_n = 0, rev_n = 0, asym = 0;
    for (int i = 0; i < count; i++) {
        if (results[i].fwd >= 0) { fwd_n++; fwd += results[i].fwd; }
        if (results[i].rev >= 0) { rev_n++; rev += results[i].rev; }
        if (results[i].fwd >= 0 && results[i].rev >= 0 &&
            results[i].fwd != results[i].rev)
            asym++;
    }

    rprintf(outfile, "\nSummary:");
    if (directions & DIR_FORWARD)
        rprintf(outfile, " client->server %d of %d received", fwd, fwd_n);
    if (directions == DIR_BOTH)
        rprintf(outfile, ";");
    if (directions & DIR_REVERSE)
        rprintf(outfile, " server->client %d of %d received", rev, rev_n);
    if (directions == DIR_BOTH)
        rprintf(outfile, "; %d asymmetric", asym);
    rprintf(outfile, "\n");
}

/* ------------------------------------------------------------- probe exchanges */

/* Expect a message of type want; frees any payload unless out is non-NULL. */
static int expect_msg(int fd, uint8_t want, void **out) {
    uint8_t  msg_type;
    void    *payload;
    uint32_t plen;
    if (recv_msg(fd, &msg_type, &payload, &plen) < 0) return -1;
    if (msg_type != want) { free(payload); return -1; }
    if (out) *out = payload; else free(payload);
    return 0;
}

/* Client sends the probe; the server reports whether it arrived. */
static int run_forward(int ctrl_fd, const char *server_ip, int proto, int number,
                       int timeout_sec) {
    struct probe_next_payload pnp = { (uint8_t)proto, htons((uint16_t)number) };
    send_msg(ctrl_fd, MSG_PROBE_NEXT, &pnp, sizeof(pnp));

    if (expect_msg(ctrl_fd, MSG_PROBE_GO, NULL) < 0) {
        fprintf(stderr, "client: expected MSG_PROBE_GO for %s %d\n",
                proto_name(proto), number);
        return -1;
    }

    send_probe(server_ip, proto, number, timeout_sec);

    void *payload = NULL;
    if (expect_msg(ctrl_fd, MSG_PROBE_RESULT, &payload) < 0 || !payload) {
        fprintf(stderr, "client: expected MSG_PROBE_RESULT for %s %d\n",
                proto_name(proto), number);
        free(payload);
        return -1;
    }
    int received = ((struct probe_result_payload *)payload)->received;
    free(payload);
    return received;
}

/* Client listens; the server sends the probe and says when it has done so. */
static int run_reverse(int ctrl_fd, uint32_t server_ip_net, int icmp_fd,
                       int proto, int number, int timeout_sec) {
    int fd = open_probe_socket(proto, number, icmp_fd);

    struct probe_next_payload pnp = { (uint8_t)proto, htons((uint16_t)number) };
    send_msg(ctrl_fd, MSG_RPROBE_REQ, &pnp, sizeof(pnp));

    int received = wait_probe(proto, fd, number, server_ip_net, timeout_sec);
    close_probe_socket(proto, fd);

    if (expect_msg(ctrl_fd, MSG_RPROBE_SENT, NULL) < 0) {
        fprintf(stderr, "client: expected MSG_RPROBE_SENT for %s %d\n",
                proto_name(proto), number);
        return -1;
    }
    return received;
}

/* ----------------------------------------------------------------- run_client */

void run_client(const char *server_host, int control_port, int timeout_sec,
                int *icmp_types, int icmp_count,
                int *tcp_ports,  int tcp_count,
                int *udp_ports,  int udp_count,
                int directions, const char *output_file) {
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

    struct in_addr server_addr;
    inet_pton(AF_INET, server_ip, &server_addr);

    printf("Connecting to %s:%d\n", server_ip, control_port);
    int ctrl_fd = ctrl_connect(server_ip, control_port);
    if (ctrl_fd < 0) return;

    if (send_negotiate(ctrl_fd, icmp_types, icmp_count,
                       tcp_ports, tcp_count, udp_ports, udp_count) < 0) {
        fprintf(stderr, "client: send_negotiate failed\n");
        close(ctrl_fd);
        return;
    }

    if (expect_msg(ctrl_fd, MSG_READY, NULL) < 0) {
        fprintf(stderr, "client: expected MSG_READY\n");
        close(ctrl_fd);
        return;
    }
    printf("Server ready. Sending %d probes...\n\n", total);

    struct result *results = calloc(total, sizeof(*results));
    if (!results) { close(ctrl_fd); return; }

    int ridx = 0;
    for (int i = 0; i < icmp_count; i++, ridx++)
        results[ridx] = (struct result){ PROTO_ICMP, icmp_types[i], -1, -1 };
    for (int i = 0; i < tcp_count; i++, ridx++)
        results[ridx] = (struct result){ PROTO_TCP, tcp_ports[i], -1, -1 };
    for (int i = 0; i < udp_count; i++, ridx++)
        results[ridx] = (struct result){ PROTO_UDP, udp_ports[i], -1, -1 };

    /* Reverse ICMP probes are received on one raw socket for the session */
    int icmp_fd = -1;
    if ((directions & DIR_REVERSE) && icmp_count > 0)
        icmp_fd = open_icmp_raw();

    int done = 0;
    for (; done < total; done++) {
        struct result *r = &results[done];
        if (directions & DIR_FORWARD) {
            r->fwd = run_forward(ctrl_fd, server_ip, r->proto, r->number, timeout_sec);
            if (r->fwd < 0) break;
        }
        if (directions & DIR_REVERSE) {
            r->rev = run_reverse(ctrl_fd, server_addr.s_addr, icmp_fd,
                                 r->proto, r->number, timeout_sec);
            if (r->rev < 0) break;
        }
    }

    if (icmp_fd >= 0) close(icmp_fd);
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

    /* On a control-channel error, report only the probes that completed */
    print_report(results, done, directions, outfile);

    if (outfile)
        fclose(outfile);
    free(results);
}
