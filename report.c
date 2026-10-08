#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "global.h"
#include "protocol.h"
#include "client.h"
#include "report.h"
#include "version.h"

/* Stable lowercase protocol names for machine-readable output */
static const char *proto_key(int proto) {
    switch (proto) {
    case PROTO_ICMP: return "icmp";
    case PROTO_TCP:  return "tcp";
    case PROTO_UDP:  return "udp";
    }
    return "unknown";
}

/* Stable outcome names for machine-readable output */
static const char *result_key(int r) {
    switch (r) {
    case RESULT_RECEIVED:    return "received";
    case RESULT_LOST:        return "not_received";
    case RESULT_UNAVAILABLE: return "unavailable";
    }
    return "not_tested";
}

/* The client is behind NAT if the server saw a different address */
static int behind_nat(const struct run_info *info) {
    return info->client_observed_addr[0] &&
           strcmp(info->client_addr, info->client_observed_addr) != 0;
}

/* ------------------------------------------------------------------ aggregation */

/* All attempts of one probe in one direction */
struct dir_agg {
    int received;      /* attempts that arrived */
    int tested;        /* attempts that ran and were available */
    int unavailable;   /* attempts that couldn't be set up */
};

struct agg {
    struct dir_agg fwd, rev;
};

static void add(struct dir_agg *d, int r) {
    if (r == RESULT_UNAVAILABLE) { d->unavailable++; return; }
    if (r < 0) return;
    d->tested++;
    if (r == RESULT_RECEIVED) d->received++;
}

static void add_dir(struct dir_agg *t, const struct dir_agg *d) {
    t->received    += d->received;
    t->tested      += d->tested;
    t->unavailable += d->unavailable;
}

static int nres(const struct run_info *info) {
    return info->nprobes * info->count;
}

/* Aggregate probe i (0 <= i < nprobes) over every round. */
static struct agg aggregate(const struct run_info *info, const struct result *results,
                            int i) {
    struct agg a;
    memset(&a, 0, sizeof(a));
    for (int j = i; j < nres(info); j += info->nprobes) {
        add(&a.fwd, results[j].fwd);
        add(&a.rev, results[j].rev);
    }
    return a;
}

static int ran(const struct dir_agg *d) {
    return d->tested + d->unavailable > 0;
}

/* Received in one direction only (any attempt), i.e. not explained by loss. */
static int asymmetric(const struct agg *a) {
    return a->fwd.tested > 0 && a->rev.tested > 0 &&
           (a->fwd.received > 0) != (a->rev.received > 0);
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

/*
 * "RECEIVED" / "not received" / "unavailable" for single attempts; "k/n"
 * over available attempts for repeats, plus "+u unavail" if some couldn't
 * be set up.
 */
static const char *status(const struct dir_agg *d, int count, char *buf, size_t len) {
    if (!ran(d)) return "-";
    if (d->tested == 0) return "unavailable";
    if (count == 1) return d->received ? "RECEIVED" : "not received";
    if (d->unavailable)
        snprintf(buf, len, "%d/%d +%d unavail", d->received, d->tested, d->unavailable);
    else
        snprintf(buf, len, "%d/%d", d->received, d->tested);
    return buf;
}

static void print_section(const struct result *results, int proto,
                          const struct run_info *info, FILE *outfile) {
    int any = 0;
    for (int i = 0; i < info->nprobes; i++) if (results[i].proto == proto) { any = 1; break; }
    if (!any) return;

    const char *label = proto == PROTO_ICMP ? "Type" : "Port";
    int width = proto == PROTO_ICMP ? 3 : 5;
    int directions = info->directions;
    char b1[48], b2[48];   /* "%d/%d +%d unavail" with any int values */

    rprintf(outfile, "\n%s Probes:\n", proto_name(proto, info->family));
    if (directions == DIR_BOTH)
        rprintf(outfile, "  %*s  %-16s %-16s\n", (int)strlen(label) + width + 2, "",
                "client->server", "server->client");

    for (int i = 0; i < info->nprobes; i++) {
        const struct result *r = &results[i];
        if (r->proto != proto) continue;
        struct agg a = aggregate(info, results, i);
        if (!ran(&a.fwd) && !ran(&a.rev)) continue;     /* never reached */
        const char *q = r->quoted ? " [quoted]" : "";
        if (directions == DIR_BOTH)
            rprintf(outfile, "  %s %*d:  %-16s %-16s%s%s\n", label, width, r->number,
                    status(&a.fwd, info->count, b1, sizeof(b1)),
                    status(&a.rev, info->count, b2, sizeof(b2)),
                    asymmetric(&a) ? " ASYMMETRIC" : "", q);
        else
            rprintf(outfile, "  %s %*d: %s%s\n", label, width, r->number,
                    status(directions == DIR_FORWARD ? &a.fwd : &a.rev,
                           info->count, b1, sizeof(b1)), q);
    }
}

void print_report(const struct run_info *info, const struct result *results,
                  int done, FILE *outfile) {
    int directions = info->directions;

    rprintf(outfile, "\n=== chkbounce Report ===\n");
    rprintf(outfile, "Client: %s  Server: %s  (%s)\n",
            info->client_addr, info->server_addr, family_name(info->family));
    if (behind_nat(info))
        rprintf(outfile, "Client is behind NAT: server saw %s\n", info->client_observed_addr);
    if (directions == DIR_FORWARD)
        rprintf(outfile, "Direction: client -> server");
    else if (directions == DIR_REVERSE)
        rprintf(outfile, "Direction: server -> client");
    else
        rprintf(outfile, "Direction: both");
    if (info->count > 1)
        rprintf(outfile, "  Attempts per probe: %d", info->count);
    if (info->shuffled)
        rprintf(outfile, "  Shuffle seed: %llu", info->seed);
    rprintf(outfile, "\n");
    for (int m = 0; m < info->nmeta; m++)
        rprintf(outfile, "Meta: %s\n", info->meta[m]);
    if (info->quote)
        rprintf(outfile, "ICMP error types marked [quoted] were sent quoting a primer datagram\n");

    print_section(results, PROTO_ICMP, info, outfile);
    print_section(results, PROTO_TCP,  info, outfile);
    print_section(results, PROTO_UDP,  info, outfile);

    struct agg tot;
    memset(&tot, 0, sizeof(tot));
    int asym = 0;
    for (int i = 0; i < info->nprobes; i++) {
        struct agg a = aggregate(info, results, i);
        add_dir(&tot.fwd, &a.fwd);
        add_dir(&tot.rev, &a.rev);
        asym += asymmetric(&a);
    }

    rprintf(outfile, "\nSummary:");
    if (directions & DIR_FORWARD)
        rprintf(outfile, " client->server %d of %d received", tot.fwd.received, tot.fwd.tested);
    if (directions == DIR_BOTH)
        rprintf(outfile, ";");
    if (directions & DIR_REVERSE)
        rprintf(outfile, " server->client %d of %d received", tot.rev.received, tot.rev.tested);
    if (directions == DIR_BOTH)
        rprintf(outfile, "; %d asymmetric", asym);
    rprintf(outfile, "\n");
    if (tot.fwd.unavailable + tot.rev.unavailable)
        rprintf(outfile, "Unavailable (not counted above): %d attempts could not be set up\n",
                tot.fwd.unavailable + tot.rev.unavailable);
    if (done < nres(info))
        rprintf(outfile, "Incomplete: %d of %d probe attempts ran\n", done, nres(info));
}

/* -------------------------------------------------------------------------- CSV */

/* All --meta tags as one RFC 4180 quoted field: "key=value;key=value" */
static void csv_meta(FILE *f, const struct run_info *info) {
    fputc('"', f);
    for (int m = 0; m < info->nmeta; m++) {
        if (m) fputc(';', f);
        for (const char *p = info->meta[m]; *p; p++) {
            if (*p == '"') fputc('"', f);      /* embedded quotes are doubled */
            fputc(*p, f);
        }
    }
    fputc('"', f);
}

/* Hostnames and numeric addresses never contain commas or quotes, so no quoting */
static void csv_row(FILE *f, const struct run_info *info, const struct result *r,
                    const char *direction, int outcome, int primed, const char *time) {
    char seed[24] = "";
    if (info->shuffled) snprintf(seed, sizeof(seed), "%llu", info->seed);
    const char *received = outcome == RESULT_RECEIVED ? "1"
                         : outcome == RESULT_LOST     ? "0" : "";
    const char *primed_s = primed < 0 ? "" : primed ? "1" : "0";

    fprintf(f, "%s,%s,%s,%s,%s,%s,%s,%d,%d,%s,%s,%d,%d,%d,%d,%s,%s,%s,%s,%s,",
            info->start, CHKBOUNCE_VERSION, family_name(info->family),
            info->server_host, info->server_addr, info->client_addr,
            info->client_observed_addr, behind_nat(info), info->timeout_sec, seed,
            proto_key(r->proto), r->number, r->quoted, r->attempt + 1, r->order,
            direction, result_key(outcome), received, primed_s, time);
    csv_meta(f, info);
    fputc('\n', f);
}

int write_csv(const char *path, const struct run_info *info,
              const struct result *results, int done) {
    (void)done;   /* entries that never ran are skipped by their -1 outcome */
    FILE *f = fopen(path, "a");
    if (!f) { perror(path); return -1; }

    fseek(f, 0, SEEK_END);
    if (ftell(f) == 0)
        fprintf(f, "run_start,version,family,server_host,server_addr,client_addr,"
                   "client_observed_addr,nat,timeout_sec,shuffle_seed,proto,number,"
                   "quoted,attempt,order,direction,status,received,primed,"
                   "probe_time,meta\n");

    for (int i = 0; i < nres(info); i++) {
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

/* {"received": k, "attempts": n, "unavailable": u, "tries": [...]}, or null */
static void json_dir(FILE *f, const struct run_info *info, const struct result *results,
                     int i, int reverse) {
    struct agg a = aggregate(info, results, i);
    const struct dir_agg *d = reverse ? &a.rev : &a.fwd;
    if (!ran(d)) { fputs("null", f); return; }

    fprintf(f, "{\"received\": %d, \"attempts\": %d, \"unavailable\": %d, \"tries\": [",
            d->received, d->tested, d->unavailable);
    int first = 1;
    for (int j = i; j < nres(info); j += info->nprobes) {
        const struct result *r = &results[j];
        int outcome = reverse ? r->rev : r->fwd;
        int primed  = reverse ? r->rev_primed : r->fwd_primed;
        if (outcome < 0) continue;
        fprintf(f, "%s{\"status\": \"%s\", \"order\": %d, \"time\": ",
                first ? "" : ", ", result_key(outcome), r->order);
        json_str(f, reverse ? r->rev_time : r->fwd_time);
        if (primed >= 0)
            fprintf(f, ", \"primed\": %s", primed ? "true" : "false");
        fputc('}', f);
        first = 0;
    }
    fputs("]}", f);
}

static void json_dir_total(FILE *f, const char *name, const struct dir_agg *d) {
    fprintf(f, "\"%s\": {\"received\": %d, \"tested\": %d, \"unavailable\": %d}, ",
            name, d->received, d->tested, d->unavailable);
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
    fputs(",\n  \"client_observed_addr\": ", f); json_str(f, info->client_observed_addr);
    fprintf(f, ",\n  \"nat\": %s", behind_nat(info) ? "true" : "false");
    fprintf(f, ",\n  \"control_port\": %d,\n  \"timeout_sec\": %d,\n",
            info->control_port, info->timeout_sec);
    fprintf(f, "  \"count\": %d,\n  \"quote\": %s,\n", info->count,
            info->quote ? "true" : "false");
    /* The seed is a string: 64-bit values don't survive JSON number parsing */
    if (info->shuffled)
        fprintf(f, "  \"shuffle_seed\": \"%llu\",\n", info->seed);
    else
        fputs("  \"shuffle_seed\": null,\n", f);
    fprintf(f, "  \"complete\": %s,\n", done == nres(info) ? "true" : "false");
    fprintf(f, "  \"directions\": [%s%s%s],\n",
            (info->directions & DIR_FORWARD) ? "\"client_to_server\"" : "",
            info->directions == DIR_BOTH ? ", " : "",
            (info->directions & DIR_REVERSE) ? "\"server_to_client\"" : "");

    /* --meta tags were validated as key=value with a short key in main */
    fputs("  \"meta\": {", f);
    for (int m = 0; m < info->nmeta; m++) {
        const char *eq = strchr(info->meta[m], '=');
        fprintf(f, "%s\"%.*s\": ", m ? ", " : "", (int)(eq - info->meta[m]), info->meta[m]);
        json_str(f, eq + 1);
    }
    fputs("},\n", f);

    struct agg tot;
    memset(&tot, 0, sizeof(tot));
    int asym = 0, first = 1;

    fputs("  \"results\": [", f);
    for (int i = 0; i < info->nprobes; i++) {
        const struct result *r = &results[i];
        struct agg a = aggregate(info, results, i);
        if (!ran(&a.fwd) && !ran(&a.rev)) continue;
        add_dir(&tot.fwd, &a.fwd);
        add_dir(&tot.rev, &a.rev);
        asym += asymmetric(&a);

        fprintf(f, "%s\n    {\"proto\": \"%s\", \"number\": %d, \"quoted\": %s, "
                   "\"client_to_server\": ",
                first ? "" : ",", proto_key(r->proto), r->number,
                r->quoted ? "true" : "false");
        json_dir(f, info, results, i, 0);
        fputs(", \"server_to_client\": ", f);
        json_dir(f, info, results, i, 1);
        fprintf(f, ", \"asymmetric\": %s}", asymmetric(&a) ? "true" : "false");
        first = 0;
    }
    fputs(first ? "],\n" : "\n  ],\n", f);

    fputs("  \"summary\": {", f);
    if (info->directions & DIR_FORWARD)
        json_dir_total(f, "client_to_server", &tot.fwd);
    if (info->directions & DIR_REVERSE)
        json_dir_total(f, "server_to_client", &tot.rev);
    fprintf(f, "\"asymmetric\": %d}\n}\n", asym);

    return fclose(f) == 0 ? 0 : -1;
}
