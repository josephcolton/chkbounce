#ifndef GLOBAL_H
#define GLOBAL_H

/******************************
 * Global Variables/Constants *
 ******************************/
#define packed __attribute__((packed))
#define ICMP_REPLY 0
#define ICMP_UNREACH 3
#define ICMP_ECHO 8

/*************************
 * Function declararions *
 *************************/
unsigned short checksum(void *addr, int count);


/***********
 * Structs *
 ***********/
// The Internet Protocol header
struct ip {
  unsigned char version;
  unsigned char qos;
  unsigned short len;
  unsigned short id;
  unsigned short flags;
  unsigned char ttl;
  unsigned char proto;
  unsigned short checksum;
  unsigned int src;
  unsigned int dst;
} packed;

// ICMP Header/data
struct icmp {
  unsigned char type;
  unsigned char code;
  unsigned short checksum;
  unsigned short ident;
  unsigned short seq;
  char data[56];
} packed;

// Structure for ICMP packets
struct icmp_packet {
  struct ip ip;
  struct icmp icmp;
} packed;


#endif
