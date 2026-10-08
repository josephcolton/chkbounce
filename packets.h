#ifndef PACKETS_H
#define PACKETS_H

#include <sys/socket.h>

/*
 * Probe senders.  dst is the peer; src, when non-NULL, is the local address
 * the probe must leave from (the local end of the control connection), so
 * the receiver's source-address filter matches on multihomed hosts.
 * dst and src must be the same address family.
 */

/*
 * Send a single ICMP (AF_INET) or ICMPv6 (AF_INET6) packet of the given type.
 * reverse selects the sequence-number tag (see probe_icmp_seq in protocol.h).
 * Returns bytes sent or -1.
 */
int send_icmp_probe(const struct sockaddr_storage *dst,
                    const struct sockaddr_storage *src,
                    int icmp_type, int reverse);

/*
 * Attempt a TCP connection to dst:port with the given timeout (seconds).
 * Returns 1 if connected (port reachable), 0 if timed out / refused, -1 on error.
 */
int send_tcp_probe(const struct sockaddr_storage *dst,
                   const struct sockaddr_storage *src,
                   int port, int timeout_sec);

/* Send a single UDP datagram to dst:port. Returns bytes sent or -1. */
int send_udp_probe(const struct sockaddr_storage *dst,
                   const struct sockaddr_storage *src, int port);

/*
 * Send one probe of the given PROTO_* type.  number is the ICMP type or the
 * TCP/UDP port.  Return value is that of the per-protocol function above.
 */
int send_probe(const struct sockaddr_storage *dst,
               const struct sockaddr_storage *src,
               int proto, int number, int timeout_sec, int reverse);

#endif /* PACKETS_H */
