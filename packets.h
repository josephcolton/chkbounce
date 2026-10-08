#ifndef PACKETS_H
#define PACKETS_H

#include <stdint.h>
#include <sys/socket.h>

/*
 * Probe senders.  dst is the peer; src, when non-NULL, is the local address
 * the probe must leave from (the local end of the control connection), so
 * the receiver's source-address filter matches on multihomed hosts.
 * dst and src must be the same address family.  tag is probe_tag(...) from
 * protocol.h.
 */

/*
 * Send a single ICMP (AF_INET) or ICMPv6 (AF_INET6) packet of the given type
 * and code, tagged in the sequence field.  Returns bytes sent or -1.
 */
int send_icmp_probe(const struct sockaddr_storage *dst,
                    const struct sockaddr_storage *src,
                    int icmp_type, int icmp_code, uint16_t tag);

/*
 * Send an ICMP/ICMPv6 error of the given type and code that quotes a UDP
 * datagram inner_src -> inner_dst (addresses and ports) carrying
 * PROBE_MAGIC + tag, i.e. the primer the receiver sent us.
 * Returns bytes sent or -1.
 */
int send_icmp_quoted(const struct sockaddr_storage *dst,
                     const struct sockaddr_storage *src, int icmp_type, int icmp_code,
                     const struct sockaddr_storage *inner_src,
                     const struct sockaddr_storage *inner_dst, uint16_t tag);

/*
 * Attempt a TCP connection to dst:port with the given timeout (seconds).
 * Returns 1 if connected (port reachable), 0 if timed out / refused, -1 on error.
 */
int send_tcp_probe(const struct sockaddr_storage *dst,
                   const struct sockaddr_storage *src,
                   int port, int timeout_sec);

/* Send a single tagged UDP datagram to dst:port. Returns bytes sent or -1. */
int send_udp_probe(const struct sockaddr_storage *dst,
                   const struct sockaddr_storage *src, int port, uint16_t tag);

/*
 * Send one probe of the given PROTO_* type.  number is the ICMP type or the
 * TCP/UDP port; code is the ICMP code (ignored for TCP/UDP).  Return value is
 * that of the per-protocol function above.
 */
int send_probe(const struct sockaddr_storage *dst,
               const struct sockaddr_storage *src,
               int proto, int number, int code, int timeout_sec, uint16_t tag);

/*
 * UDP socket bound to local's address and an ephemeral port, returned in
 * *port.  Used for quote primers.  Returns fd or -1.
 */
int open_udp_local(const struct sockaddr_storage *local, int *port);

/* Send PROBE_MAGIC + tag from fd to dst:port.  Returns bytes sent or -1. */
int send_tagged(int fd, const struct sockaddr_storage *dst, int port, uint16_t tag);

#endif /* PACKETS_H */
