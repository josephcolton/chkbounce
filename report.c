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

/* Received/tested counts per direction, and probes whose directions differ */
struct tally {
    int fwd, fwd_n, rev, rev_n, asym;
};

static struct tally tally(const struct result *results, int count) {
    struct tally t = { 0, 0, 0, 0, 0 };
    for (int i = 0; i < count; i++) {
        const struct result *r = &results[i];
        if (r->fwd >= 0) { t.fwd_n++; t.fwd += r->fwd; }
        if (r->rev >= 0) { t.rev_n++; t.rev += r->rev; }
        if (r->fwd >= 0 && r->rev >= 0 && r->fwd != r->rev) t.asym++;
    }
    return t;
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

static const char *status(int r) {
    return r < 0 ? "-" : r ? "RECEIVED" : "not received";
}

static void print_section(const struct result *results, int count, int proto,
                          const struct run_info *info, FILE *outfile) {
    int any = 0;
    for (int i = 0; i < count; i++) if (results[i].proto == proto) { any = 1; break; }
    if (!any) return;

    const char *label = proto == PROTO_ICMP ? "Type" : "Port";
    int width = proto == PROTO_ICMP ? 3 : 5;
    int directions = info->directions;

    rprintf(outfile, "\n%s Probes:\n", proto_name(proto, info->family));
    if (directions == DIR_BOTH)
        rprintf(outfile, "  %*s  %-14s %-14s\n", (int)strlen(label) + width + 2, "",
                "client->server", "server->client");

    for (int i = 0; i < count; i++) {
        const struct result *r = &results[i];
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

void print_report(const struct run_info *info, const struct result *results,
                  int count, FILE *outfile) {
    int directions = info->directions;

    rprintf(outfile, "\n=== chkbounce Report ===\n");
    rprintf(outfile, "Client: %s  Server: %s  (%s)\n",
            info->client_addr, info->server_addr, family_name(info->family));
    if (directions == DIR_FORWARD)
        rprintf(outfile, "Direction: client -> server\n");
    else if (directions == DIR_REVERSE)
        rprintf(outfile, "Direction: server -> client\n");
    else
        rprintf(outfile, "Direction: both\n");

    print_section(results, count, PROTO_ICMP, info, outfile);
    print_section(results, count, PROTO_TCP,  info, outfile);
    print_section(results, count, PROTO_UDP,  info, outfile);

    struct tally t = tally(results, count);

    rprintf(outfile, "\nSummary:");
    if (directions & DIR_FORWARD)
        rprintf(outfile, " client->server %d of %d received", t.fwd, t.fwd_n);
    if (directions == DIR_BOTH)
        rprintf(outfile, ";");
    if (directions & DIR_REVERSE)
        rprintf(outfile, " server->client %d of %d received", t.rev, t.rev_n);
    if (directions == DIR_BOTH)
        rprintf(outfile, "; %d asymmetric", t.asym);
    rprintf(outfile, "\n");
}

/* -------------------------------------------------------------------------- CSV */

/* Hostnames and numeric addresses never contain commas or quotes, so no quoting */
static void csv_row(FILE *f, const struct run_info *info, const struct result *r,
                    const char *direction, int received, const char *time) {
    fprintf(f, "%s,%s,%s,%s,%s,%s,%d,%s,%d,%s,%d,%s\n",
            info->start, CHKBOUNCE_VERSION, family_name(info->family),
            info->server_host, info->server_addr, info->client_addr,
            info->timeout_sec, proto_key(r->proto), r->number,
            direction, received, time);
}

int write_csv(const char *path, const struct run_info *info,
              const struct result *results, int count) {
    FILE *f = fopen(path, "a");
    if (!f) { perror(path); return -1; }

    fseek(f, 0, SEEK_END);
    if (ftell(f) == 0)
        fprintf(f, "run_start,version,family,server_host,server_addr,client_addr,"
                   "timeout_sec,proto,number,direction,received,probe_time\n");

    for (int i = 0; i < count; i++) {
        const struct result *r = &results[i];
        if (r->fwd >= 0) csv_row(f, info, r, "client_to_server", r->fwd, r->fwd_time);
        if (r->rev >= 0) csv_row(f, info, r, "server_to_client", r->rev, r->rev_time);
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

static void json_dir(FILE *f, int received, const char *time) {
    if (received < 0) { fputs("null", f); return; }
    fprintf(f, "{\"received\": %s, \"time\": ", received ? "true" : "false");
    json_str(f, time);
    fputc('}', f);
}

int write_json(const char *path, const struct run_info *info,
               const struct result *results, int count) {
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); return -1; }

    struct tally t = tally(results, count);

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
    fprintf(f, "  \"directions\": [%s%s%s],\n",
            (info->directions & DIR_FORWARD) ? "\"client_to_server\"" : "",
            info->directions == DIR_BOTH ? ", " : "",
            (info->directions & DIR_REVERSE) ? "\"server_to_client\"" : "");

    fputs("  \"results\": [", f);
    for (int i = 0; i < count; i++) {
        const struct result *r = &results[i];
        fprintf(f, "%s\n    {\"proto\": \"%s\", \"number\": %d, \"client_to_server\": ",
                i ? "," : "", proto_key(r->proto), r->number);
        json_dir(f, r->fwd, r->fwd_time);
        fputs(", \"server_to_client\": ", f);
        json_dir(f, r->rev, r->rev_time);
        fputc('}', f);
    }
    fputs(count ? "\n  ],\n" : "],\n", f);

    fputs("  \"summary\": {", f);
    if (info->directions & DIR_FORWARD)
        fprintf(f, "\"client_to_server\": {\"received\": %d, \"tested\": %d}, ", t.fwd, t.fwd_n);
    if (info->directions & DIR_REVERSE)
        fprintf(f, "\"server_to_client\": {\"received\": %d, \"tested\": %d}, ", t.rev, t.rev_n);
    fprintf(f, "\"asymmetric\": %d}\n}\n", t.asym);

    return fclose(f) == 0 ? 0 : -1;
}
