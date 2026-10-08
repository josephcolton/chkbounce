#ifndef GLOBAL_H
#define GLOBAL_H

#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>

#define packed __attribute__((packed))

/* ICMP type constants */
#define ICMP_REPLY   0
#define ICMP_UNREACH 3
#define ICMP_ECHO    8

/* "ICMP"/"ICMPv6", "TCP", "UDP" for a PROTO_* value; "?" otherwise. */
const char *proto_name(int proto, int family);

/* Current time as ISO 8601 UTC with milliseconds (needs >= 25 bytes); returns buf. */
const char *timestamp_utc(char *buf, size_t len);

/* RFC 1071 checksum over count bytes starting at addr */
unsigned short checksum(void *addr, int count);

/*
 * Address helpers.  All addresses are carried as sockaddr_storage holding
 * either AF_INET or AF_INET6; IPv4-mapped IPv6 addresses (::ffff:a.b.c.d)
 * are converted to plain AF_INET by sa_unmap so comparisons work.
 */

/*
 * Resolve a hostname or numeric address.  family is AF_UNSPEC, AF_INET or
 * AF_INET6.  The port in *out is left 0.  Returns 0 on success, -1 on failure.
 */
int resolve_host(const char *host, int family, struct sockaddr_storage *out);

/* sizeof the concrete sockaddr for ss->ss_family. */
socklen_t sa_len(const struct sockaddr_storage *ss);

/* Get/set the port (host order; network order conversion done here). */
int  sa_get_port(const struct sockaddr_storage *ss);
void sa_set_port(struct sockaddr_storage *ss, int port);

/* Convert an IPv4-mapped AF_INET6 address to AF_INET in place. */
void sa_unmap(struct sockaddr_storage *ss);

/* 1 if a and b hold the same IP address (ports ignored), else 0. */
int sa_same_addr(const struct sockaddr_storage *a, const struct sockaddr_storage *b);

/* Numeric address string (no port) into buf; returns buf. */
const char *sa_ntop(const struct sockaddr_storage *ss, char *buf, size_t len);

/* "IPv4" or "IPv6" */
const char *family_name(int family);

/*
 * 1 if this ICMP type is an error message (one that quotes the packet that
 * caused it): ICMPv6 types 0-127; ICMPv4 types 3, 4, 5, 11, 12, 31, 40.
 */
int icmp_is_error(int family, int type);

/* Write/read exactly n bytes, looping over partial I/O. Returns 0 on success. */
int write_all(int fd, const void *buf, size_t n);
int read_all(int fd, void *buf, size_t n);

/* Send a framed control-channel message; payload may be NULL when len==0. */
int send_msg(int fd, uint8_t type, const void *payload, uint32_t len);

/* Disable Nagle on a control connection: the protocol is lock-step and latency-bound. */
void set_nodelay(int fd);

/*
 * Receive a framed control-channel message.
 * *payload is malloc'd by callee; caller must free().
 * *payload is NULL when payload length is 0.
 * Returns 0 on success, -1 on error/EOF.
 */
int recv_msg(int fd, uint8_t *type, void **payload, uint32_t *len);

/* Raw IP header as it appears on the wire */
struct ip {
    unsigned char  version;   /* version(4) + IHL(4): 0x45 = IPv4, 20-byte header */
    unsigned char  qos;
    unsigned short len;
    unsigned short id;
    unsigned short flags;
    unsigned char  ttl;
    unsigned char  proto;
    unsigned short checksum;
    unsigned int   src;
    unsigned int   dst;
} packed;

/* ICMP header + 56 bytes of payload */
struct icmp {
    unsigned char  type;
    unsigned char  code;
    unsigned short checksum;
    unsigned short ident;
    unsigned short seq;
    char           data[56];
} packed;

/* Combined IP + ICMP packet as received from a raw socket */
struct icmp_packet {
    struct ip   ip;
    struct icmp icmp;
} packed;

#endif /* GLOBAL_H */
