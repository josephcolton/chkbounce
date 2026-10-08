#ifndef REPORT_H
#define REPORT_H

#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
 * One attempt at one probe.  Results are stored round by round: entry
 * attempt * nprobes + i is attempt `attempt` of probe i.
 * fwd/rev: 1 = received, 0 = not received, -1 = not tested.
 * fwd_primed/rev_primed (quoted probes only): 1 if the receiver's primer
 * reached the error sender, 0 if not, -1 if not applicable.
 */
struct result {
    int  proto;
    int  number;
    int  attempt;
    int  quoted;         /* ICMP error type sent with a quoted packet */
    int  fwd;
    int  rev;
    int  fwd_primed;
    int  rev_primed;
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
    int         nprobes;                        /* probes per round */
    int         count;                          /* rounds requested (-n) */
    int         quote;                          /* -q given */
};

/*
 * done is the number of result entries completed (fewer than
 * nprobes * count if the session failed part way).
 */

/* Human-readable report to stdout and, if outfile is non-NULL, to outfile. */
void print_report(const struct run_info *info, const struct result *results,
                  int done, FILE *outfile);

/*
 * Append one row per tested (probe, attempt, direction) to path, writing the
 * header first if the file is new or empty, so many runs can share one CSV.
 * Returns 0 on success, -1 on error.
 */
int write_csv(const char *path, const struct run_info *info,
              const struct result *results, int done);

/* Write one JSON document describing the run to path (overwrites). */
int write_json(const char *path, const struct run_info *info,
               const struct result *results, int done);

#endif /* REPORT_H */
