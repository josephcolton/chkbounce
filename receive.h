#ifndef RECEIVE_H
#define RECEIVE_H

#include <stdint.h>

/*
 * Receiving side of a probe, shared by the server (forward probes) and the
 * client (reverse probes).
 */

/* Raw ICMP socket used to receive ICMP probes of any type.  Returns fd or -1. */
int open_icmp_raw(void);

/*
 * Open the socket that will receive one probe.  For PROTO_ICMP this returns
 * icmp_fd unchanged (the raw socket is shared across a session); for TCP/UDP
 * it opens a new listening/bound socket on number.  Returns fd or -1.
 */
int open_probe_socket(int proto, int number, int icmp_fd);

/* Close a socket returned by open_probe_socket (no-op for the shared ICMP fd). */
void close_probe_socket(int proto, int fd);

/*
 * Wait up to timeout_sec for the probe to arrive on fd.  ICMP and UDP probes
 * are only counted if they come from src_ip_net (network byte order).
 * Returns 1 if received, 0 otherwise.
 */
int wait_probe(int proto, int fd, int number, uint32_t src_ip_net, int timeout_sec);

#endif /* RECEIVE_H */
