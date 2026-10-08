#ifndef PACKETS_H
#define PACKETS_H

/* Send a single ICMP packet of the given type to dstip. Returns bytes sent or -1. */
int send_icmp_probe(const char *dstip, int icmp_type);

/*
 * Attempt a TCP connection to dstip:port with the given timeout (seconds).
 * Returns 1 if connected (port reachable), 0 if timed out / refused, -1 on error.
 */
int send_tcp_probe(const char *dstip, int port, int timeout_sec);

/* Send a single UDP datagram to dstip:port. Returns bytes sent or -1. */
int send_udp_probe(const char *dstip, int port);

/*
 * Send one probe of the given PROTO_* type.  number is the ICMP type or the
 * TCP/UDP port.  Return value is that of the per-protocol function above.
 */
int send_probe(const char *dstip, int proto, int number, int timeout_sec);

#endif /* PACKETS_H */
