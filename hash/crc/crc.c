
#include "crc.h"

uint16_t crc16(
    uint16_t crc, 
    uint32_t inlen, 
    void *in)
{
  uint32_t i;
  uint8_t  *p=(uint8_t*)in;
  
  crc = ~crc;
  
  while (inlen-- != 0)
  {
    crc ^= *p++;
    
    for (i=0; i<8; i++) {
      crc = (crc >> 1) ^ (0x8005 * (crc & 1));
    } 
  }
  return ~crc;
}

// Castagnoli polynomial is 0x1edc6f41
uint32_t crc32c(uint32_t crc, uint32_t inlen, void *in)
{
  uint32_t i, c;
  uint8_t  *p=(uint8_t*)in;
  
  while (inlen-- != 0) {
    crc ^= *p++;
    
    for (i=0; i<8; i++) {
      crc = (crc >> 1) ^ (0x82F63B78 * (crc & 1));
    }
  }
  return crc;
}

uint32_t crc32(uint32_t crc, uint32_t inlen, void *in)
{
  uint32_t i, c;
  uint8_t  *p=(uint8_t*)in;
  
  crc = ~crc;
  
  while (inlen-- != 0) {
    crc ^= *p++;
    
    for (i=0; i<8; i++) {
      crc = (crc >> 1) ^ (0xEDB88320 * (crc & 1));
    }
  }
  return ~crc;
}

