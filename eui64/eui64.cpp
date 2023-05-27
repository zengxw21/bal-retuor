#include "eui64.h"
#include <stdint.h>
#include <stdlib.h>

in6_addr eui64(const ether_addr mac) {
  in6_addr res = {0};
  // TODO
  res.s6_addr[0] = 0xfe;
  res.s6_addr[1] = 0x80;
  for (int i = 2; i <= 7;i++){
    res.s6_addr[i] = 0x00;
  }
  for (int i = 0; i <= 2;i++){
    res.s6_addr[i + 8] = mac.ether_addr_octet[i];
  }
  for (int i = 3; i <= 5;i++){
    res.s6_addr[i + 10] = mac.ether_addr_octet[i];
  }
  res.s6_addr[11] = 0xff;
  res.s6_addr[12] = 0xfe;
  res.s6_addr[8] = res.s6_addr[8] ^ 0x2;
  return res;
}