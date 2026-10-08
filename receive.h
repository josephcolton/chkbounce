#ifndef RECEIVE_H
#define RECEIVE_H

#include <stdint.h>
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
 * counted if they come from peer's address and carry tag (probe_tag(),
 * computed the same way by the sender).  Returns 1 if received, 0 otherwise.
 */
int wait_probe(int proto, int fd, int number, const struct sockaddr_storage *peer,
               int timeout_sec, uint16_t tag);

/*
 * Wait for a quoted ICMP error of expected_type from peer whose quoted
 * datagram is UDP from our port sport (the primer's fresh source port, which
 * identifies the probe; the destination port is not checked because a NAT
 * in front of the error sender may rewrite it).
 * Returns 1 if received, 0 otherwise.
 */
int wait_icmp_quoted(int icmp_fd, const struct sockaddr_storage *peer,
                     int expected_type, int sport, int timeout_sec);

/*
 * Wait for a quote primer (PROBE_MAGIC + tag) on UDP socket fd from any
 * source; its observed source address/port goes to *from.  Returns 1 if one
 * arrived, 0 otherwise.
 */
int recv_primer(int fd, int timeout_sec, uint16_t tag, struct sockaddr_storage *from);

#endif /* RECEIVE_H */
