#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "global.h"
#include "protocol.h"
#include "client.h"
#include "report.h"

#ifndef CHKBOUNCE_VERSION
#define CHKBOUNCE_VERSION "unknown"
#endif

/* Stable lowercase protocol names for machine-readable output */
static const char *proto_key(int proto) {
    switch (proto) {
    case PROTO_ICMP: return "icmp";
    case PROTO_TCP:  return "tcp";
    case PROTO_UDP:  return "udp";
    }
    return "unknown";
}

/* ------------------------------------------------------------------ aggregation */

/* All completed attempts of one probe, per direction */
struct agg {
    int fwd, fwd_n;   /* received / tested, client -> server */
    int rev, rev_n;   /* received / tested, server -> client */
};

/* Aggregate probe i (0 <= i < nprobes) over the first done entries. */
static struct agg aggregate(const struct run_info *info, const struct result *results,
                            int done, int i) {
    struct agg a = { 0, 0, 0, 0 };
    for (int j = i; j < done; j += info->nprobes) {
        const struct result *r = &results[j];
        if (r->fwd >= 0) { a.fwd_n++; a.fwd += r->fwd; }
        if (r->rev >= 0) { a.rev_n++; a.rev += r->rev; }
    }
    return a;
}

/* Received in one direction only (any attempt), i.e. not explained by loss. */
static int asymmetric(const struct agg *a) {
    return a->fwd_n > 0 && a->rev_n > 0 && (a->fwd > 0) != (a->rev > 0);
}

/* Probes that appear in the first done entries (all of them after round 1) */
static int probes_seen(const struct run_info *info, int done) {
    return done < info->nprobes ? done : info->nprobes;
}

/* ------------------------------------------------------------------ text report */

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

/* "RECEIVED" / "not received" for single attempts, "k/n" for repeats */
static const char *status(int received, int tested, char *buf, size_t len) {
    if (tested == 0) return "-";
    if (tested == 1) return received ? "RECEIVED" : "not received";
    snprintf(buf, len, "%d/%d", received, tested);
    return buf;
}

static void print_section(const struct result *results, int done, int proto,
                          const struct run_info *info, FILE *outfile) {
    int nseen = probes_seen(info, done);
    int any = 0;
    for (int i = 0; i < nseen; i++) if (results[i].proto == proto) { any = 1; break; }
    if (!any) return;

    const char *label = proto == PROTO_ICMP ? "Type" : "Port";
    int width = proto == PROTO_ICMP ? 3 : 5;
    int directions = info->directions;
    char b1[16], b2[16];

    rprintf(outfile, "\n%s Probes:\n", proto_name(proto, info->family));
    if (directions == DIR_BOTH)
        rprintf(outfile, "  %*s  %-14s %-14s\n", (int)strlen(label) + width + 2, "",
                "client->server", "server->client");

    for (int i = 0; i < nseen; i++) {
        const struct result *r = &results[i];
        if (r->proto != proto) continue;
        struct agg a = aggregate(info, results, done, i);
        const char *q = r->quoted ? " [quoted]" : "";
        if (directions == DIR_BOTH)
            rprintf(outfile, "  %s %*d:  %-14s %-14s%s%s\n", label, width, r->number,
                    status(a.fwd, a.fwd_n, b1, sizeof(b1)),
                    status(a.rev, a.rev_n, b2, sizeof(b2)),
                    asymmetric(&a) ? " ASYMMETRIC" : "", q);
        else if (directions == DIR_FORWARD)
            rprintf(outfile, "  %s %*d: %s%s\n", label, width, r->number,
                    status(a.fwd, a.fwd_n, b1, sizeof(b1)), q);
        else
            rprintf(outfile, "  %s %*d: %s%s\n", label, width, r->number,
                    status(a.rev, a.rev_n, b1, sizeof(b1)), q);
    }
}

void print_report(const struct run_info *info, const struct result *results,
                  int done, FILE *outfile) {
    int directions = info->directions;

    rprintf(outfile, "\n=== chkbounce Report ===\n");
    rprintf(outfile, "Client: %s  Server: %s  (%s)\n",
            info->client_addr, info->server_addr, family_name(info->family));
    if (directions == DIR_FORWARD)
        rprintf(outfile, "Direction: client -> server");
    else if (directions == DIR_REVERSE)
        rprintf(outfile, "Direction: server -> client");
    else
        rprintf(outfile, "Direction: both");
    if (info->count > 1)
        rprintf(outfile, "  Attempts per probe: %d", info->count);
    rprintf(outfile, "\n");
    if (info->quote)
        rprintf(outfile, "ICMP error types marked [quoted] were sent quoting a primer datagram\n");

    print_section(results, done, PROTO_ICMP, info, outfile);
    print_section(results, done, PROTO_TCP,  info, outfile);
    print_section(results, done, PROTO_UDP,  info, outfile);

    struct agg tot = { 0, 0, 0, 0 };
    int asym = 0;
    for (int i = 0; i < probes_seen(info, done); i++) {
        struct agg a = aggregate(info, results, done, i);
        tot.fwd += a.fwd; tot.fwd_n += a.fwd_n;
        tot.rev += a.rev; tot.rev_n += a.rev_n;
        asym += asymmetric(&a);
    }

    rprintf(outfile, "\nSummary:");
    if (directions & DIR_FORWARD)
        rprintf(outfile, " client->server %d of %d received", tot.fwd, tot.fwd_n);
    if (directions == DIR_BOTH)
        rprintf(outfile, ";");
    if (directions & DIR_REVERSE)
        rprintf(outfile, " server->client %d of %d received", tot.rev, tot.rev_n);
    if (directions == DIR_BOTH)
        rprintf(outfile, "; %d asymmetric", asym);
    rprintf(outfile, "\n");
    if (done < info->nprobes * info->count)
        rprintf(outfile, "Incomplete: %d of %d probe attempts ran\n",
                done, info->nprobes * info->count);
}

/* -------------------------------------------------------------------------- CSV */

/* Hostnames and numeric addresses never contain commas or quotes, so no quoting */
static void csv_row(FILE *f, const struct run_info *info, const struct result *r,
                    const char *direction, int received, int primed, const char *time) {
    const char *primed_s = primed < 0 ? "" : primed ? "1" : "0";
    fprintf(f, "%s,%s,%s,%s,%s,%s,%d,%s,%d,%d,%d,%s,%d,%s,%s\n",
            info->start, CHKBOUNCE_VERSION, family_name(info->family),
            info->server_host, info->server_addr, info->client_addr,
            info->timeout_sec, proto_key(r->proto), r->number, r->quoted,
            r->attempt + 1, direction, received, primed_s, time);
}

int write_csv(const char *path, const struct run_info *info,
              const struct result *results, int done) {
    FILE *f = fopen(path, "a");
    if (!f) { perror(path); return -1; }

    fseek(f, 0, SEEK_END);
    if (ftell(f) == 0)
        fprintf(f, "run_start,version,family,server_host,server_addr,client_addr,"
                   "timeout_sec,proto,number,quoted,attempt,direction,received,"
                   "primed,probe_time\n");

    for (int i = 0; i < done; i++) {
        const struct result *r = &results[i];
        if (r->fwd >= 0)
            csv_row(f, info, r, "client_to_server", r->fwd, r->fwd_primed, r->fwd_time);
        if (r->rev >= 0)
            csv_row(f, info, r, "server_to_client", r->rev, r->rev_primed, r->rev_time);
    }
    return fclose(f) == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------------- JSON */

static void json_str(FILE *f, const char *s) {
    fputc('"', f);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') fprintf(f, "\\%c", c);
        else if (c < 0x20)         fprintf(f, "\\u%04x", c);
        else                       fputc(c, f);
    }
    fputc('"', f);
}

/* {"received": k, "attempts": n, "tries": [...]} for one direction, or null */
static void json_dir(FILE *f, const struct run_info *info, const struct result *results,
                     int done, int i, int reverse) {
    struct agg a = aggregate(info, results, done, i);
    int received = reverse ? a.rev : a.fwd;
    int tested   = reverse ? a.rev_n : a.fwd_n;
    if (tested == 0) { fputs("null", f); return; }

    fprintf(f, "{\"received\": %d, \"attempts\": %d, \"tries\": [", received, tested);
    int first = 1;
    for (int j = i; j < done; j += info->nprobes) {
        const struct result *r = &results[j];
        int rec    = reverse ? r->rev : r->fwd;
        int primed = reverse ? r->rev_primed : r->fwd_primed;
        if (rec < 0) continue;
        fprintf(f, "%s{\"received\": %s, \"time\": ", first ? "" : ", ",
                rec ? "true" : "false");
        json_str(f, reverse ? r->rev_time : r->fwd_time);
        if (primed >= 0)
            fprintf(f, ", \"primed\": %s", primed ? "true" : "false");
        fputc('}', f);
        first = 0;
    }
    fputs("]}", f);
}

int write_json(const char *path, const struct run_info *info,
               const struct result *results, int done) {
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); return -1; }

    fputs("{\n  \"tool\": \"chkbounce\",\n  \"version\": ", f);
    json_str(f, CHKBOUNCE_VERSION);
    fputs(",\n  \"start\": ", f);          json_str(f, info->start);
    fputs(",\n  \"end\": ", f);            json_str(f, info->end);
    fputs(",\n  \"family\": ", f);         json_str(f, family_name(info->family));
    fputs(",\n  \"server_host\": ", f);    json_str(f, info->server_host);
    fputs(",\n  \"server_addr\": ", f);    json_str(f, info->server_addr);
    fputs(",\n  \"client_addr\": ", f);    json_str(f, info->client_addr);
    fprintf(f, ",\n  \"control_port\": %d,\n  \"timeout_sec\": %d,\n",
            info->control_port, info->timeout_sec);
    fprintf(f, "  \"count\": %d,\n  \"quote\": %s,\n", info->count,
            info->quote ? "true" : "false");
    fprintf(f, "  \"complete\": %s,\n",
            done == info->nprobes * info->count ? "true" : "false");
    fprintf(f, "  \"directions\": [%s%s%s],\n",
            (info->directions & DIR_FORWARD) ? "\"client_to_server\"" : "",
            info->directions == DIR_BOTH ? ", " : "",
            (info->directions & DIR_REVERSE) ? "\"server_to_client\"" : "");

    struct agg tot = { 0, 0, 0, 0 };
    int asym = 0, nseen = probes_seen(info, done);

    fputs("  \"results\": [", f);
    for (int i = 0; i < nseen; i++) {
        const struct result *r = &results[i];
        struct agg a = aggregate(info, results, done, i);
        tot.fwd += a.fwd; tot.fwd_n += a.fwd_n;
        tot.rev += a.rev; tot.rev_n += a.rev_n;
        asym += asymmetric(&a);

        fprintf(f, "%s\n    {\"proto\": \"%s\", \"number\": %d, \"quoted\": %s, "
                   "\"client_to_server\": ",
                i ? "," : "", proto_key(r->proto), r->number,
                r->quoted ? "true" : "false");
        json_dir(f, info, results, done, i, 0);
        fputs(", \"server_to_client\": ", f);
        json_dir(f, info, results, done, i, 1);
        fprintf(f, ", \"asymmetric\": %s}", asymmetric(&a) ? "true" : "false");
    }
    fputs(nseen ? "\n  ],\n" : "],\n", f);

    fputs("  \"summary\": {", f);
    if (info->directions & DIR_FORWARD)
        fprintf(f, "\"client_to_server\": {\"received\": %d, \"tested\": %d}, ",
                tot.fwd, tot.fwd_n);
    if (info->directions & DIR_REVERSE)
        fprintf(f, "\"server_to_client\": {\"received\": %d, \"tested\": %d}, ",
                tot.rev, tot.rev_n);
    fprintf(f, "\"asymmetric\": %d}\n}\n", asym);

    return fclose(f) == 0 ? 0 : -1;
}
