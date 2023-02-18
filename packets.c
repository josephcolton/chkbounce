#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <errno.h>

#include "global.h"
#include "packets.h"

#define PACKET_SIZE 4096

/*********************************
 * send_icmp - Send ICMP packets *
 *********************************/
int send_icmp(char *srcip, char *dstip, unsigned char ttl, unsigned char icmp_type) {
  int handle, bytes;
  unsigned int src, dst;

  // Convert source and destination addresses
  src = inet_addr(srcip);
  dst = inet_addr(dstip);

  // Structure to keep track of where the packet is going
  static struct sockaddr_in tostruct;

  // Create the icmp packet
  struct icmp_packet packet;

  // ip portion
  packet.ip.version = 0x45;        // Version 4, header length 20
  packet.ip.qos = 0x00;            // Differentiated Services Field
  packet.ip.len = htons(84);       // Total length of IP packet
  packet.ip.id = htons(54321);     // Packet identification
  packet.ip.flags = htons(0x4000); // Don't fragment, 0 offset.
  packet.ip.ttl = ttl;             // Time to live
  packet.ip.proto = 0x01;          // ICMP packet
  packet.ip.checksum = 0;          // Need to figure out how to calculate
  packet.ip.src = src;             // Get from command line
  packet.ip.dst = dst;             // Get from command line
  
  // icmp portion
  packet.icmp.type = icmp_type;    // ICMP packet type
  packet.icmp.code = 0x00;         // ICMP type code
  packet.icmp.checksum = 0;        // Calculate later
  packet.icmp.ident = 12345;       // ICMP stream identification
  packet.icmp.seq = htons(1);      // Sequence number of 1
  strncpy((char *)&(packet.icmp.data),
          "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1234",
          56);

  // Calculate checksums.  For some reason, the reply does not come if the
  // checksum is not inserted correctly.. not that that is unexpected.
  packet.ip.checksum = checksum(&(packet.ip), sizeof(packet.ip));
  packet.icmp.checksum = checksum(&(packet.icmp), sizeof(packet.icmp));

  // Create a socket handle to send out our ICMP packet on
  handle = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (handle < 0) {
    printf("Could not create socket... got root?\n");
    exit(0);
  }

  // Create tostruct
  tostruct.sin_family = AF_INET; // We are using IPv4
  memcpy(&tostruct.sin_addr.s_addr,&dst,4);

  bytes = sendto(handle,
                 &packet,
                 sizeof(packet),
                 0,
                 (struct sockaddr *)&tostruct,
                 sizeof(struct sockaddr));

  // Return bytes sent
  return bytes;
}

/***************************************
 * recv_icmp - Listen for ICMP Packets *
 ***************************************/
void recv_icmp() {
  int handle, data_size, bytes, addr_len;
  char buffer[PACKET_SIZE];
  struct sockaddr_in addr;
  struct icmp_packet *packet;

  // Create a raw socket with ICMP protocol
  handle = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (handle < 0) {
    printf("Error creating socket.  Got root?\n");
    exit(0);
  }

  // set socket option to receive all incoming packets
  int on = 1;
  if (setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
    printf("Error setting socket option\n");
    exit(0);
  }

  // Listen for incoming ICMP packets
  while (1) {
    addr_len = sizeof(addr);

    // Receive packet
    bytes = recvfrom(handle,
		     buffer,
		     PACKET_SIZE,
		     0,
		     (struct sockaddr *)&addr,
		     &addr_len);

    // Make sure we received something
    if (bytes < 0) {
      printf("Error receiving ICMP packet");
      continue;
    }
    
    // Extract the ICMP packet
    packet = (struct icmp_packet *)&buffer;
    
    // Display information about the ICMP packet we received
    printf("Received %s ", inet_ntoa(addr.sin_addr));
    printf("- IP TTL: %d, Id: %d ",
	   packet->ip.ttl, ntohs(packet->ip.id));
    printf("- ICMP Type: %d, Code: %d, Ident: %d\n",
	   packet->icmp.type, packet->icmp.code, packet->icmp.ident);
  }

  close(handle);
  return;
}
