#ifndef CLIENT_H
#define CLIENT_H

/* Probe directions (bitmask) */
#define DIR_FORWARD 1   /* client -> server */
#define DIR_REVERSE 2   /* server -> client */
#define DIR_BOTH    (DIR_FORWARD | DIR_REVERSE)

/*
 * Connect to the server, negotiate, send all probes, and print the report.
 *
 *   server_host  - hostname or dotted-decimal IPv4 address of the server
 *   control_port - TCP port the server is listening on
 *   timeout_sec  - per-probe timeout
 *   icmp_types / icmp_count - ICMP type numbers to probe
 *   tcp_ports  / tcp_count  - TCP port numbers to probe
 *   udp_ports  / udp_count  - UDP port numbers to probe
 *   directions   - DIR_* bitmask; with DIR_BOTH each probe is run forward
 *                  then immediately in reverse so the pair is close in time
 *   output_file  - also write the report here (may be NULL)
 */
void run_client(const char *server_host, int control_port, int timeout_sec,
                int *icmp_types, int icmp_count,
                int *tcp_ports,  int tcp_count,
                int *udp_ports,  int udp_count,
                int directions, const char *output_file);

#endif /* CLIENT_H */
