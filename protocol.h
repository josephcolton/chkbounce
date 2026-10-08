#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

/* Probe protocol identifiers */
#define PROTO_ICMP 1
#define PROTO_TCP  2
#define PROTO_UDP  3

/* Control-channel message types */
#define MSG_NEGOTIATE    1   /* client->server: list of probes */
#define MSG_READY        2   /* server->client: session set up */
#define MSG_PROBE_NEXT   3   /* client->server: about to send probe */
#define MSG_PROBE_GO     4   /* server->client: ready for this probe */
#define MSG_PROBE_RESULT 5   /* server->client: received or not */
#define MSG_DONE         6   /* client->server: all probes sent */
#define MSG_RPROBE_REQ   7   /* client->server: send me this probe (reverse) */
#define MSG_RPROBE_SENT  8   /* server->client: reverse probe has been sent */

/*
 * Outcome of one probe in one direction (probe_result_payload.received and
 * the client's results).  UNAVAILABLE means the probe could not be set up
 * (the receiver couldn't open its socket, e.g. the port is in use or a raw
 * socket isn't permitted, or the sender couldn't send), so it says nothing
 * about the path and must not be counted as a drop.
 */
#define RESULT_LOST        0
#define RESULT_RECEIVED    1
#define RESULT_UNAVAILABLE 2

/* probe_next_payload.flags */
#define PROBE_FLAG_QUOTE 0x01  /* ICMP error type: send with a quoted packet */

/* Each probe may be repeated; attempt numbers are 0..MAX_ATTEMPTS-1 */
#define MAX_ATTEMPTS 127

/*
 * Probe tags.  Every probe carries a 16-bit tag encoding its number (ICMP
 * type, or port modulo 256), attempt, and direction, so a receiver never
 * counts a stray packet: a late copy of an earlier attempt, or the kernel's
 * automatic reply to an earlier probe (e.g. the Echo Reply, ICMPv6 129, that
 * answers a type 128 probe).
 *
 *   ICMP probes:   identifier = PROBE_ICMP_ID, sequence = tag.  Receivers
 *                  check the sequence only; NATs rewrite the identifier.
 *   UDP probes and quote primers: payload = PROBE_MAGIC (no NUL) + tag.
 *   Quoted ICMP error probes: matched by the quoted UDP ports instead (the
 *                  4 bytes after the checksum are zero, as in a real error).
 */
#define PROBE_MAGIC     "chkbounce"
#define PROBE_MAGIC_LEN (sizeof(PROBE_MAGIC) - 1)
#define PROBE_ICMP_ID   0xCB0C

static inline uint16_t probe_tag(int number, int attempt, int reverse) {
    return (uint16_t)(((attempt & 0x7f) << 9) | ((number & 0xff) << 1) |
                      (reverse ? 1 : 0));
}

#define DEFAULT_CONTROL_PORT 1234
#define DEFAULT_TIMEOUT      2

/*
 * Wire format: all multi-byte fields are big-endian (network byte order).
 *
 * Every message on the control TCP channel:
 *   [1 byte: type][4 bytes: payload_len][payload_len bytes: payload]
 *
 * MSG_NEGOTIATE payload:
 *   [4 bytes: count][count * probe_entry]
 *   probe_entry = [1 byte: proto][2 bytes: number]
 *
 * MSG_READY payload: ready_payload: the server's session UDP port that
 *   receives quote primers (0 if unavailable), and the client's address as
 *   the server sees it (differs from the client's own address behind NAT).
 *
 * MSG_PROBE_NEXT / MSG_RPROBE_REQ payload: probe_next_payload.  port is the
 *   client's UDP port for quoted probes: in PROBE_NEXT the port the primer
 *   must be sent to; in RPROBE_REQ the port the client's primer came from.
 *
 * MSG_PROBE_GO payload: port_payload, the server's primer source port for a
 *   quoted forward probe (0 otherwise).
 *
 * MSG_PROBE_RESULT payload: probe_result_payload.
 *
 * MSG_RPROBE_SENT payload: rprobe_sent_payload.
 *
 * MSG_DONE: zero-length payload.
 *
 * Forward probe (client -> server):
 *   PROBE_NEXT -> PROBE_GO -> client sends probe -> PROBE_RESULT
 *
 * Reverse probe (server -> client), client already listening:
 *   RPROBE_REQ -> server sends probe -> RPROBE_SENT
 *   The client decides received/not itself.
 *
 * Quoted ICMP error probes.  The probe's receiver R first sends a UDP primer
 * (PROBE_MAGIC + tag) from a fresh port to the error sender S, creating
 * state in any stateful middlebox; S then sends the ICMP error quoting that
 * primer as R's address/port -> S's address/port.  S uses the primer's
 * observed source when it arrives (so NAT is handled) and the port R
 * reported otherwise; "primed" records which.
 *   Forward (S = client): client binds port Ps and sends PROBE_NEXT{port=Ps};
 *     server primes from port Pr to client:Ps, replies PROBE_GO{port=Pr}.
 *   Reverse (S = server): client primes from port Pr to the server's session
 *     port (from MSG_READY), then sends RPROBE_REQ{port=Pr}.
 */

#pragma pack(push, 1)

struct msg_hdr {
    uint8_t  type;
    uint32_t len;    /* network byte order */
};

struct probe_entry {
    uint8_t  proto;
    uint16_t number; /* network byte order */
};

struct probe_next_payload {
    uint8_t  proto;
    uint16_t number;  /* network byte order */
    uint8_t  attempt; /* 0-based repeat number */
    uint8_t  flags;   /* PROBE_FLAG_* */
    uint16_t port;    /* network byte order; see above */
};

struct port_payload {
    uint16_t port;    /* network byte order */
};

struct ready_payload {
    uint16_t port;              /* network byte order */
    char     observed_addr[46]; /* numeric, NUL-terminated (INET6_ADDRSTRLEN) */
};

struct probe_result_payload {
    uint8_t  proto;
    uint16_t number;   /* network byte order */
    uint8_t  received; /* RESULT_* */
};

struct rprobe_sent_payload {
    uint8_t  primed;   /* quoted probe: 1 if the client's primer arrived */
    uint8_t  sent;     /* 1 if the server sent the probe, 0 if it couldn't */
};

#pragma pack(pop)

#endif /* PROTOCOL_H */
