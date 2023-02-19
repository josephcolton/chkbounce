#include <stdio.h>
#include <stdlib.h>

#include "global.h"
#include "packets.h"

int main(int argc, char** argv) {
  int i, ttl;

  // Set variables
  ttl = 64;
  
  // Check command line
  if (argc == 3) {
    printf("Sending Packets\n");
    // Send ICMP messages
    for (i=0; i < 256; i++) {
      send_icmp(argv[1], argv[2], ttl, i);
    }
  } else {
    printf("Listening for Packets\n");
    // Listen for packets
    recv_icmp();
  }

  return 0;
}
