#ifndef RECEIVE_H
#define RECEIVE_H

#include <sys/socket.h>

/*
 * Receiving side of a probe, shared by the server (forward probes) and the
 * client (reverse probes).  family is AF_INET or AF_INET6 and selects ICMP
 * vs. ICMPv6 for PROTO_ICMP.
 */

/* Raw ICMP/ICMPv6 socket used to receive ICMP probes of any type.  Returns fd or -1. */
int open_icmp_raw(int family);

/*
 * Open the socket that will receive one probe.  For PROTO_ICMP this returns
 * icmp_fd unchanged (the raw socket is shared across a session); for TCP/UDP
 * it opens a new listening/bound socket on number.  Returns fd or -1.
 */
int open_probe_socket(int family, int proto, int number, int icmp_fd);

/* Close a socket returned by open_probe_socket (no-op for the shared ICMP fd). */
void close_probe_socket(int proto, int fd);

/*
 * Wait up to timeout_sec for the probe to arrive on fd.  Probes are only
 * counted if they come from peer's address.  reverse must match the sender's
 * value so ICMP sequence tags line up (see probe_icmp_seq).
 * Returns 1 if received, 0 otherwise.
 */
int wait_probe(int proto, int fd, int number, const struct sockaddr_storage *peer,
               int timeout_sec, int reverse);

#endif /* RECEIVE_H */
