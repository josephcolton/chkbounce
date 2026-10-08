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
    int server_quote_port;     /* where reverse-probe primers go (MSG_READY) */
    struct sockaddr_storage server;
    struct sockaddr_storage local;
};

static void send_next(const struct session *s, uint8_t type, const struct result *r,
                      int port) {
    struct probe_next_payload pnp;
    pnp.proto   = (uint8_t)r->proto;
    pnp.number  = htons((uint16_t)r->number);
    pnp.attempt = (uint8_t)r->attempt;
    pnp.flags   = r->quoted ? PROBE_FLAG_QUOTE : 0;
    pnp.port    = htons((uint16_t)port);
    pnp.code    = (uint8_t)r->code;
    send_msg(s->ctrl_fd, type, &pnp, sizeof(pnp));
}

/*
 * Client sends the probe; the server reports whether it arrived.
 * Returns a RESULT_* value, or -1 on a control-channel error.
 */
static int run_forward(const struct session *s, struct result *r) {
    uint16_t tag = probe_tag(r->number, r->attempt, 0);
    int qfd = -1, qport = 0, sent;

    /* Quoted: we are the error sender, so open the port the primer comes to */
    if (r->quoted)
        qfd = open_udp_local(&s->local, &qport);
    send_next(s, MSG_PROBE_NEXT, r, qport);

    void *payload = NULL;
    if (expect_msg(s->ctrl_fd, MSG_PROBE_GO, &payload) < 0) {
        fprintf(stderr, "client: expected MSG_PROBE_GO for %s %d\n",
                proto_name(r->proto, s->family), r->number);
        if (qfd >= 0) close(qfd);
        return -1;
    }
    int primer_port = payload ? ntohs(((struct port_payload *)payload)->port) : 0;
    free(payload);

    if (r->quoted) {
        /*
         * Quote the server's primer, using its observed source if it
         * arrived (correct through NAT), else the server's address and the
         * port it reported.
         */
        struct sockaddr_storage inner_src, inner_dst = s->local;
        r->fwd_primed = qfd >= 0 && primer_port &&
                        recv_primer(qfd, s->timeout_sec, tag, &inner_src);
        if (!r->fwd_primed) {
            inner_src = s->server;
            sa_set_port(&inner_src, primer_port);
        }
        sa_set_port(&inner_dst, qport);
        /* Without our quote port there's no flow to quote: don't send */
        sent = qfd >= 0 &&
               send_icmp_quoted(&s->server, &s->local, r->number, r->code,
                                &inner_src, &inner_dst, tag) >= 0;
        if (qfd >= 0) close(qfd);
    } else {
        sent = send_probe(&s->server, &s->local, r->proto, r->number, r->code,
                          s->timeout_sec, tag) >= 0;
    }

    payload = NULL;
    if (expect_msg(s->ctrl_fd, MSG_PROBE_RESULT, &payload) < 0 || !payload) {
        fprintf(stderr, "client: expected MSG_PROBE_RESULT for %s %d\n",
                proto_name(r->proto, s->family), r->number);
        free(payload);
        return -1;
    }
    int received = ((struct probe_result_payload *)payload)->received;
    free(payload);
    return sent ? received : RESULT_UNAVAILABLE;
}

/*
 * Client listens; the server sends the probe and says when it has done so.
 * Returns a RESULT_* value, or -1 on a control-channel error.
 */
static int run_reverse(const struct session *s, struct result *r) {
    uint16_t tag = probe_tag(r->number, r->attempt, 1);
    int received = RESULT_UNAVAILABLE;   /* until a receiving socket is up */

    if (r->quoted) {
        /*
         * We are the error receiver: prime from a fresh port to the server's
         * quote port, then expect an error quoting that port.  The server may
         * wait up to a timeout for the primer, so wait two timeouts.
         */
        int pport = 0;
        int pfd = open_udp_local(&s->local, &pport);
        if (pfd >= 0 && s->server_quote_port)
            send_tagged(pfd, &s->server, s->server_quote_port, tag);
        send_next(s, MSG_RPROBE_REQ, r, pport);
        if (pfd >= 0 && s->icmp_fd >= 0)
            received = wait_icmp_quoted(s->icmp_fd, &s->server, r->number, r->code,
                                        pport, 2 * s->timeout_sec);
        if (pfd >= 0)
            close(pfd);
    } else {
        int fd = open_probe_socket(s->family, r->proto, r->number, s->icmp_fd);
        send_next(s, MSG_RPROBE_REQ, r, 0);
        if (fd >= 0)
            received = wait_probe(r->proto, fd, r->number, r->code, &s->server,
                                  s->timeout_sec, tag);
        close_probe_socket(r->proto, fd);
    }

    void *payload = NULL;
    if (expect_msg(s->ctrl_fd, MSG_RPROBE_SENT, &payload) < 0) {
        fprintf(stderr, "client: expected MSG_RPROBE_SENT for %s %d\n",
                proto_name(r->proto, s->family), r->number);
        return -1;
    }
    struct rprobe_sent_payload *sp = payload;
    if (r->quoted)
        r->rev_primed = sp ? sp->primed : 0;
    int sent = sp ? sp->sent : 0;
    free(payload);
    return sent ? received : RESULT_UNAVAILABLE;
}

/* ------------------------------------------------------------------ shuffling */

/*
 * splitmix64: a small, fully specified PRNG, so a recorded seed reproduces
 * the same probe order on any platform (unlike rand()/random()).
 */
static uint64_t splitmix64(uint64_t *state) {
    uint64_t z = (*state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* Fisher-Yates shuffle of order[0..n-1] (modulo bias is negligible at 64 bits) */
static void shuffle(int *order, int n, uint64_t *state) {
    for (int i = n - 1; i > 0; i--) {
        int j = (int)(splitmix64(state) % (uint64_t)(i + 1));
        int t = order[i]; order[i] = order[j]; order[j] = t;
    }
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
    info.nprobes      = total;
    info.count        = o->count;
    info.quote        = o->quote;
    for (int i = 0; i < o->icmp_count; i++)
        if (o->icmp_codes[i] != 0) info.codes_used = 1;
    info.shuffled     = o->shuffle;
    info.seed         = o->seed;
    info.meta         = o->meta;
    info.nmeta        = o->nmeta;

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
    set_nodelay(s.ctrl_fd);

    socklen_t llen = sizeof(s.local);
    if (getsockname(s.ctrl_fd, (struct sockaddr *)&s.local, &llen) < 0) {
        perror("client: getsockname");
        close(s.ctrl_fd);
        return;
    }
    sa_unmap(&s.local);
    sa_ntop(&s.local, info.client_addr, sizeof(info.client_addr));

    /* Round-major: entry a * total + i is attempt a of probe i */
    int nres = total * o->count;
    struct result *results = calloc(nres, sizeof(*results));
    if (!results) { close(s.ctrl_fd); return; }

    for (int a = 0; a < o->count; a++) {
        struct result *r = &results[a * total];
        for (int i = 0; i < o->icmp_count; i++, r++)
            *r = (struct result){ .proto = PROTO_ICMP, .number = o->icmp_types[i],
                                  .code = o->icmp_codes[i] };
        for (int i = 0; i < o->tcp_count; i++, r++)
            *r = (struct result){ .proto = PROTO_TCP, .number = o->tcp_ports[i] };
        for (int i = 0; i < o->udp_count; i++, r++)
            *r = (struct result){ .proto = PROTO_UDP, .number = o->udp_ports[i] };
    }
    for (int j = 0; j < nres; j++) {
        struct result *r = &results[j];
        r->attempt = j / total;
        r->quoted  = o->quote && r->proto == PROTO_ICMP &&
                     icmp_is_error(s.family, r->number);
        r->fwd = r->rev = r->fwd_primed = r->rev_primed = -1;
    }

    /* The first round lists every probe once */
    if (send_negotiate(s.ctrl_fd, results, total) < 0) {
        fprintf(stderr, "client: send_negotiate failed\n");
        close(s.ctrl_fd);
        free(results);
        return;
    }

    void *payload = NULL;
    if (expect_msg(s.ctrl_fd, MSG_READY, &payload) < 0) {
        fprintf(stderr, "client: expected MSG_READY\n");
        close(s.ctrl_fd);
        free(results);
        return;
    }
    struct ready_payload *rp = payload;
    s.server_quote_port = rp ? ntohs(rp->port) : 0;
    if (rp) {
        rp->observed_addr[sizeof(rp->observed_addr) - 1] = '\0';
        snprintf(info.client_observed_addr, sizeof(info.client_observed_addr),
                 "%s", rp->observed_addr);
    }
    free(payload);

    if (o->count > 1)
        printf("Server ready. Sending %d probes x %d attempts...\n\n", total, o->count);
    else
        printf("Server ready. Sending %d probes...\n\n", total);
    timestamp_utc(info.start, sizeof(info.start));

    /* Reverse ICMP probes are received on one raw socket for the session */
    if ((o->directions & DIR_REVERSE) && o->icmp_count > 0)
        s.icmp_fd = open_icmp_raw(s.family);

    /*
     * Each round runs every probe once, in list order or (with --shuffle) in
     * a fresh seeded permutation; with -b a probe's two directions stay
     * back to back.  On a control-channel error the rest are left untested.
     */
    int *order = malloc(total * sizeof(*order));
    if (!order) { close(s.ctrl_fd); free(results); return; }
    uint64_t rng = o->seed;

    int done = 0, failed = 0;
    for (int a = 0; a < o->count && !failed; a++) {
        for (int i = 0; i < total; i++) order[i] = i;
        if (o->shuffle) shuffle(order, total, &rng);

        for (int k = 0; k < total && !failed; k++) {
            struct result *r = &results[a * total + order[k]];
            r->order = k + 1;
            if (o->directions & DIR_FORWARD) {
                int v = run_forward(&s, r);
                if (v < 0) { failed = 1; break; }
                r->fwd = v;
                timestamp_utc(r->fwd_time, sizeof(r->fwd_time));
            }
            if (o->directions & DIR_REVERSE) {
                int v = run_reverse(&s, r);
                if (v < 0) { failed = 1; break; }
                r->rev = v;
                timestamp_utc(r->rev_time, sizeof(r->rev_time));
            }
            done++;
        }
    }
    free(order);
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
