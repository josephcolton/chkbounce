#ifndef CLIENT_H
#define CLIENT_H

/* Probe directions (bitmask) */
#define DIR_FORWARD 1   /* client -> server */
#define DIR_REVERSE 2   /* server -> client */
#define DIR_BOTH    (DIR_FORWARD | DIR_REVERSE)

struct client_opts {
    const char *server_host;   /* hostname or numeric IPv4/IPv6 address */
    int   control_port;        /* TCP port the server is listening on */
    int   timeout_sec;         /* per-probe timeout */
    int   family;              /* AF_UNSPEC, AF_INET (-4) or AF_INET6 (-6) */
    int   directions;          /* DIR_* bitmask; with DIR_BOTH each probe runs
                                  forward then immediately in reverse */
    int  *icmp_types; int icmp_count;   /* ICMP (or ICMPv6) type numbers */
    int  *tcp_ports;  int tcp_count;
    int  *udp_ports;  int udp_count;
    int   count;               /* attempts per probe (-n), 1..MAX_ATTEMPTS; the
                                  whole probe list is swept count times */
    int   quote;               /* -q: send ICMP error types quoting a primer */
    const char *output_file;   /* text report copy (may be NULL) */
    const char *csv_file;      /* CSV rows appended here (may be NULL) */
    const char *json_file;     /* JSON document written here (may be NULL) */
};

/* Connect to the server, negotiate, run all probes, and report. */
void run_client(const struct client_opts *o);

#endif /* CLIENT_H */
