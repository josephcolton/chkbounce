#ifndef PACKETS_H
#define PACKETS_H

/********************
 * Packet Functions *
 ********************/
int send_icmp(char *srcip, char *dstip, unsigned char ttl, unsigned char icmp_type);



#endif
