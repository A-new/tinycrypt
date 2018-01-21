

// test unit for crc
// odzhan

#include "crc.h"

int main(int argc, char *argv[])
{
  if (argc!=2) {
    printf ("\nusage: crc <string>\n");
    return 0;
  }
  printf ("\ncrc16  : %04X",  crc16(0, strlen(argv[1]), argv[1]));
  printf ("\ncrc32  : %08X",  crc32(0, strlen(argv[1]), argv[1]));
  printf ("\ncrc32c : %08X", crc32c(0, strlen(argv[1]), argv[1]));
  
  return 0;
}
