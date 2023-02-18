#include <stdio.h>
#include <stdlib.h>

#include "global.h"
#include "packets.h"

int main(int argc, char** argv) {
  // Check command line
  if (argc != 3) {
    printf("Usage:\n\t%s src_ip dst_ip\n\n", argv[0]);
    exit(0);
  }

  // Send ICMP message
  send_icmp(argv[1], argv[2], 16, ICMP_ECHO);
  send_icmp(argv[1], argv[2], 16, ICMP_REPLY);
  send_icmp(argv[1], argv[2], 16, ICMP_UNREACH);

  return 0;
}
