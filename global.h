#ifndef GLOBAL_H
#define GLOBAL_H

#include <stdint.h>
#include <stddef.h>

#define packed __attribute__((packed))

/* ICMP type constants */
#define ICMP_REPLY   0
#define ICMP_UNREACH 3
#define ICMP_ECHO    8

/* RFC 1071 checksum over count bytes starting at addr */
unsigned short checksum(void *addr, int count);

/*
 * Resolve a hostname or dotted-decimal IPv4 address to a dotted-decimal
 * string written into ip_out (at least INET_ADDRSTRLEN bytes).
 * Returns 0 on success, -1 on failure.
 */
int resolve_hostname(const char *host, char *ip_out, size_t ip_len);

/* Write/read exactly n bytes, looping over partial I/O. Returns 0 on success. */
int write_all(int fd, const void *buf, size_t n);
int read_all(int fd, void *buf, size_t n);

/* Send a framed control-channel message; payload may be NULL when len==0. */
int send_msg(int fd, uint8_t type, const void *payload, uint32_t len);

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
