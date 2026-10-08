#ifndef REPORT_H
#define REPORT_H

#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* One probe; fwd/rev: 1 = received, 0 = not received, -1 = not tested */
struct result {
    int  proto;
    int  number;
    int  fwd;
    int  rev;
    char fwd_time[32];   /* ISO 8601 UTC when the result was known */
    char rev_time[32];
};

/* Session-wide metadata recorded alongside the results */
struct run_info {
    char        start[32];
    char        end[32];
    const char *server_host;
    char        server_addr[INET6_ADDRSTRLEN];
    char        client_addr[INET6_ADDRSTRLEN];  /* local end of control connection */
    int         family;
    int         control_port;
    int         timeout_sec;
    int         directions;                     /* DIR_* bitmask */
};

/* Human-readable report to stdout and, if outfile is non-NULL, to outfile. */
void print_report(const struct run_info *info, const struct result *results,
                  int count, FILE *outfile);

/*
 * Append one row per tested (probe, direction) to path, writing the header
 * first if the file is new or empty, so many runs can share one CSV.
 * Returns 0 on success, -1 on error.
 */
int write_csv(const char *path, const struct run_info *info,
              const struct result *results, int count);

/* Write one JSON document describing the run to path (overwrites). */
int write_json(const char *path, const struct run_info *info,
               const struct result *results, int count);

#endif /* REPORT_H */
