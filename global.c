#include <string.h>


// To calculate the checksum.  It is slightly modified from
// the version listed in RFC 1071 because there were problems
// getting the value from the addr when I used that one.
unsigned short checksum(void *addr, int count) {
  // Calculates a checksum from a given address for count bytes
  unsigned short rvalue;

  unsigned int sum = 0;
  unsigned int value = 0;

  while( count > 1 )  {
    memcpy(&value, addr, 2);
    sum += value;
    addr += 2;
    count -= 2;
  }

  // Add left-over byte, if any
  if( count > 0 )
    sum += * (unsigned char *) addr;

  // Fold 32-bit sum to 16 bits
  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);

  rvalue = ~sum;
  return rvalue;
}
