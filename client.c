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
#include "report.h"
#include "client.h"

/* ------------------------------------------------------------------ helpers */

static int ctrl_connect(const struct sockaddr_storage *server, int port) {
    int fd = socket(server->ss_family, SOCK_STREAM, 0);
    if (fd < 0) { perror("client: socket"); return -1; }

    struct sockaddr_storage srv = *server;
    sa_set_port(&srv, port);
    if (connect(fd, (struct sockaddr *)&srv, sa_len(&srv)) < 0) {
        perror("client: connect to server");
        close(fd);
        return -1;
    }
    return fd;
}

static int send_negotiate(int fd, const struct result *results, int count) {
    if (count <= 0) return -1;
    size_t plen = 4 + (size_t)count * sizeof(struct probe_entry);
    char  *buf  = malloc(plen);
    if (!buf) return -1;

    uint32_t net_total = htonl((uint32_t)count);
    memcpy(buf, &net_total, 4);

    struct probe_entry *pe = (struct probe_entry *)(buf + 4);
    for (int i = 0; i < count; i++) {
        pe[i].proto  = (uint8_t)results[i].proto;
        pe[i].number = htons((uint16_t)results[i].number);
    }

    int r = send_msg(fd, MSG_NEGOTIATE, buf, (uint32_t)plen);
    free(buf);
    return r;
}

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

/* ------------------------------------------------------------- probe exchanges */

/*
 * Per-session addressing: server is the probe destination, local is our end
 * of the control connection (probes leave from and are received on it).
 */
struct session {
    int ctrl_fd;
    int icmp_fd;
    int family;
    int timeout_sec;
    struct sockaddr_storage server;
    struct sockaddr_storage local;
};

/* Client sends the probe; the server reports whether it arrived. */
static int run_forward(const struct session *s, int proto, int number) {
    struct probe_next_payload pnp = { (uint8_t)proto, htons((uint16_t)number) };
    send_msg(s->ctrl_fd, MSG_PROBE_NEXT, &pnp, sizeof(pnp));

    if (expect_msg(s->ctrl_fd, MSG_PROBE_GO, NULL) < 0) {
        fprintf(stderr, "client: expected MSG_PROBE_GO for %s %d\n",
                proto_name(proto, s->family), number);
        return -1;
    }

    send_probe(&s->server, &s->local, proto, number, s->timeout_sec, 0);

    void *payload = NULL;
    if (expect_msg(s->ctrl_fd, MSG_PROBE_RESULT, &payload) < 0 || !payload) {
        fprintf(stderr, "client: expected MSG_PROBE_RESULT for %s %d\n",
                proto_name(proto, s->family), number);
        free(payload);
        return -1;
    }
    int received = ((struct probe_result_payload *)payload)->received;
    free(payload);
    return received;
}

/* Client listens; the server sends the probe and says when it has done so. */
static int run_reverse(const struct session *s, int proto, int number) {
    int fd = open_probe_socket(s->family, proto, number, s->icmp_fd);

    struct probe_next_payload pnp = { (uint8_t)proto, htons((uint16_t)number) };
    send_msg(s->ctrl_fd, MSG_RPROBE_REQ, &pnp, sizeof(pnp));

    int received = wait_probe(proto, fd, number, &s->server, s->timeout_sec, 1);
    close_probe_socket(proto, fd);

    if (expect_msg(s->ctrl_fd, MSG_RPROBE_SENT, NULL) < 0) {
        fprintf(stderr, "client: expected MSG_RPROBE_SENT for %s %d\n",
                proto_name(proto, s->family), number);
        return -1;
    }
    return received;
}

/* ----------------------------------------------------------------- run_client */

void run_client(const struct client_opts *o) {
    int total = o->icmp_count + o->tcp_count + o->udp_count;
    if (total == 0) {
        fprintf(stderr, "client: no probes specified (use -i, -t, or -u)\n");
        return;
    }

    struct session s;
    memset(&s, 0, sizeof(s));
    s.icmp_fd     = -1;
    s.timeout_sec = o->timeout_sec;

    struct run_info info;
    memset(&info, 0, sizeof(info));
    info.server_host  = o->server_host;
    info.control_port = o->control_port;
    info.timeout_sec  = o->timeout_sec;
    info.directions   = o->directions;

    /* Resolve once; -4/-6 restrict the family, otherwise the resolver picks */
    if (resolve_host(o->server_host, o->family, &s.server) < 0)
        return;
    s.family    = s.server.ss_family;
    info.family = s.family;
    sa_ntop(&s.server, info.server_addr, sizeof(info.server_addr));
    if (strcmp(o->server_host, info.server_addr) != 0)
        printf("Resolved %s -> %s\n", o->server_host, info.server_addr);

    printf("Connecting to %s port %d (%s)\n", info.server_addr, o->control_port,
           family_name(s.family));
    s.ctrl_fd = ctrl_connect(&s.server, o->control_port);
    if (s.ctrl_fd < 0) return;

    socklen_t llen = sizeof(s.local);
    if (getsockname(s.ctrl_fd, (struct sockaddr *)&s.local, &llen) < 0) {
        perror("client: getsockname");
        close(s.ctrl_fd);
        return;
    }
    sa_unmap(&s.local);
    sa_ntop(&s.local, info.client_addr, sizeof(info.client_addr));

    struct result *results = calloc(total, sizeof(*results));
    if (!results) { close(s.ctrl_fd); return; }

    int ridx = 0;
    for (int i = 0; i < o->icmp_count; i++, ridx++)
        results[ridx] = (struct result){ .proto = PROTO_ICMP, .number = o->icmp_types[i] };
    for (int i = 0; i < o->tcp_count; i++, ridx++)
        results[ridx] = (struct result){ .proto = PROTO_TCP, .number = o->tcp_ports[i] };
    for (int i = 0; i < o->udp_count; i++, ridx++)
        results[ridx] = (struct result){ .proto = PROTO_UDP, .number = o->udp_ports[i] };
    for (int i = 0; i < total; i++)
        results[i].fwd = results[i].rev = -1;

    if (send_negotiate(s.ctrl_fd, results, total) < 0) {
        fprintf(stderr, "client: send_negotiate failed\n");
        close(s.ctrl_fd);
        free(results);
        return;
    }

    if (expect_msg(s.ctrl_fd, MSG_READY, NULL) < 0) {
        fprintf(stderr, "client: expected MSG_READY\n");
        close(s.ctrl_fd);
        free(results);
        return;
    }
    printf("Server ready. Sending %d probes...\n\n", total);
    timestamp_utc(info.start, sizeof(info.start));

    /* Reverse ICMP probes are received on one raw socket for the session */
    if ((o->directions & DIR_REVERSE) && o->icmp_count > 0)
        s.icmp_fd = open_icmp_raw(s.family);

    int done = 0;
    for (; done < total; done++) {
        struct result *r = &results[done];
        if (o->directions & DIR_FORWARD) {
            r->fwd = run_forward(&s, r->proto, r->number);
            if (r->fwd < 0) break;
            timestamp_utc(r->fwd_time, sizeof(r->fwd_time));
        }
        if (o->directions & DIR_REVERSE) {
            r->rev = run_reverse(&s, r->proto, r->number);
            if (r->rev < 0) break;
            timestamp_utc(r->rev_time, sizeof(r->rev_time));
        }
    }
    timestamp_utc(info.end, sizeof(info.end));

    if (s.icmp_fd >= 0) close(s.icmp_fd);
    send_msg(s.ctrl_fd, MSG_DONE, NULL, 0);
    close(s.ctrl_fd);

    FILE *outfile = NULL;
    if (o->output_file) {
        outfile = fopen(o->output_file, "w");
        if (!outfile)
            perror(o->output_file);
        else
            printf("Writing report to %s\n", o->output_file);
    }

    /* On a control-channel error, report only the probes that completed */
    print_report(&info, results, done, outfile);
    if (outfile)
        fclose(outfile);

    if (o->csv_file && write_csv(o->csv_file, &info, results, done) == 0)
        printf("Appended CSV results to %s\n", o->csv_file);
    if (o->json_file && write_json(o->json_file, &info, results, done) == 0)
        printf("Wrote JSON results to %s\n", o->json_file);

    free(results);
}
