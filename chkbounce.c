#include <stdio.h>
#include <stdlib.h>

#include "global.h"
#include "packets.h"

int main(int argc, char** argv) {
  // Check command line
  if (argc == 3) {
    printf("Sending Packets\n");
    // Send ICMP message
    send_icmp(argv[1], argv[2], 16, ICMP_ECHO);
    send_icmp(argv[1], argv[2], 16, ICMP_REPLY);
    send_icmp(argv[1], argv[2], 16, ICMP_UNREACH);
  } else {
    printf("Listening for Packets\n");
    // Listen for packets
    recv_icmp();
  }

  return 0;
}
