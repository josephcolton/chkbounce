#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

/* Probe protocol identifiers */
#define PROTO_ICMP 1
#define PROTO_TCP  2
#define PROTO_UDP  3

/* Control-channel message types */
#define MSG_NEGOTIATE    1   /* client->server: list of probes */
#define MSG_READY        2   /* server->client: sockets set up */
#define MSG_PROBE_NEXT   3   /* client->server: about to send probe */
#define MSG_PROBE_GO     4   /* server->client: ready for this probe */
#define MSG_PROBE_RESULT 5   /* server->client: received or not */
#define MSG_DONE         6   /* client->server: all probes sent */
#define MSG_RPROBE_REQ   7   /* client->server: send me this probe (reverse) */
#define MSG_RPROBE_SENT  8   /* server->client: reverse probe has been sent */

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
 * MSG_PROBE_NEXT payload:
 *   [1 byte: proto][2 bytes: number]
 *
 * MSG_RPROBE_REQ payload: same layout as MSG_PROBE_NEXT.
 *
 * MSG_PROBE_RESULT payload:
 *   [1 byte: proto][2 bytes: number][1 byte: received (0 or 1)]
 *
 * MSG_READY, MSG_PROBE_GO, MSG_DONE, MSG_RPROBE_SENT: zero-length payload.
 *
 * Forward probe (client -> server):
 *   PROBE_NEXT -> PROBE_GO -> client sends probe -> PROBE_RESULT
 *
 * Reverse probe (server -> client), client already listening:
 *   RPROBE_REQ -> server sends probe -> RPROBE_SENT
 *   The client decides received/not itself; no result message is needed.
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
    uint16_t number; /* network byte order */
};

struct probe_result_payload {
    uint8_t  proto;
    uint16_t number;   /* network byte order */
    uint8_t  received; /* 1 = received, 0 = not */
};

#pragma pack(pop)

#endif /* PROTOCOL_H */
