#include "protocol.h"
#include "common.h"
#include "lookup.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include<iostream>
using namespace std;
RipngErrorCode disassemble(const uint8_t *packet, uint32_t len,
                           RipngPacket *output)
{ 
  
  // TODO
  // 1. len 是否不小于一个 IPv6 header 的长度。
  if(!(len>=40)){
    return ERR_LENGTH;
  }
  
  // 2. IPv6 Header 中的 Payload Length 加上 Header 长度是否等于 len。
  union{
    uint8_t payload_8[2];
    uint16_t payload;
  } Payload;
  Payload.payload_8[0] = packet[4];
  Payload.payload_8[1] = packet[5];
  auto payload_host = ntohs(Payload.payload);//主机序的payload
  if (!(payload_host+40==len))
  {
    return ERR_LENGTH;
  }

  // 3. IPv6 Header 中的 Next header 字段是否为 UDP 协议。
  auto next_header = packet[6];
  if(!(next_header==17)){
    return ERR_IPV6_NEXT_HEADER_NOT_UDP;
  }

//   //  4. IPv6 Header 中的 Payload Length 是否包括一个 UDP header 的长度。
  if(!(payload_host>=8)){
    return ERR_LENGTH;
  }
//   //5. 检查 UDP 源端口和目的端口是否都为 521。
  union {
    uint8_t port_8[2];
    uint16_t port;
  } SourcePort,DestPort;
  SourcePort.port_8[0] = packet[40];
  SourcePort.port_8[1] = packet[41];
  DestPort.port_8[0] = packet[42];
  DestPort.port_8[1] = packet[43];
  auto src_port_host = ntohs(SourcePort.port);
  auto dest_port_host = ntohs(DestPort.port);
  if(!(src_port_host==521&&dest_port_host==521)){
    return ERR_UDP_PORT_NOT_RIPNG;
  }
//   // 6. 检查 UDP header 中 Length 是否等于 UDP header 长度加上 RIPng header
//   // 长度加上 RIPng entry 长度的整数倍。
  union {
    uint8_t len_8[2];
    uint16_t len;
  } Length;
  Length.len_8[0] = packet[44];
  Length.len_8[1] = packet[45];
  auto length_host = ntohs(Length.len);
  if(!((length_host-8-4)%20==0)){
    return ERR_LENGTH;
  }
//   // 7.检查 RIPng header 中的 Command 是否为 1 或 2，
//   //* Version 是否为 1，Zero（Reserved） 是否为 0。
  auto command = packet[48];
  if(!(command==1||command==2)){
    return ERR_RIPNG_BAD_COMMAND;
  }
  auto version = packet[49];
  if(!(version==1)){
    return ERR_RIPNG_BAD_VERSION;
  }
  if(!((int)packet[50]==0&&(int)packet[51]==0)){
    return ERR_RIPNG_BAD_ZERO;
  }
//   //8.对每个 RIPng entry，当 Metric=0xFF 时，检查 Prefix Len
//   //和 Route Tag 是否为 0。
  int EntryNum = (length_host - 8 - 4) / 20;
  for (int i = 1; i <= EntryNum;i++){
    auto metric = packet[51 + 20 * i];
    if(metric==0xff){
      auto prefix_len = packet[50 + 20 * i];
      if(prefix_len!=0){
        return ERR_RIPNG_BAD_PREFIX_LEN;
      }
      if((packet[49+20*i]!=0)||(packet[48+20*i]!=0)){
        return ERR_RIPNG_BAD_ROUTE_TAG;
      }
    }
  }
//   /*9. 对每个 RIPng entry，当 Metric!=0xFF 时，检查 Metric 是否属于
//  * [1,16]，并检查 Prefix Len 是否属于 [0,128]，Prefix Len 是否与 IPv6 prefix
//  * 字段组成合法的 IPv6 前缀。*/


  for (int i = 1; i <= EntryNum;i++){
    auto metric = packet[51 + 20 * i];
    if(metric!=0xff){
      if(!(metric>=1&&metric<=16)){
        return ERR_RIPNG_BAD_METRIC;
      }
      auto prefix_len = packet[50 + 20 * i];
      if(!(prefix_len>=0&&prefix_len<=128)){
        return ERR_RIPNG_BAD_PREFIX_LEN;
      }
      in6_addr ipv6_prefix;
      for (int j = 0; j < 16;j++){
        ipv6_prefix.__in6_u.__u6_addr8[j] = packet[32 + 20 * i + j];
      }
      // 为啥不用转为主机序
      
      if ((len_to_mask(prefix_len) & ipv6_prefix) != ipv6_prefix)
      {
        return ERR_RIPNG_INCONSISTENT_PREFIX_LENGTH;
      }
      
    }
  }

  for (int i = 1; i <= EntryNum; i++)
  {
    output->entries[i - 1].metric = packet[51 + 20 * i];
    output->entries[i - 1].prefix_len = packet[50 + 20 * i];
    union{
      uint8_t tag_8[2];
      uint16_t tag;
    } RouteTag;
    RouteTag.tag_8[0] = packet[48 + 20 * i];
    RouteTag.tag_8[1] = packet[49 + 20 * i];
    output->entries[i - 1].route_tag = RouteTag.tag;//不用转换
    in6_addr ipv6_prefix;
    for (int j = 0; j < 16;j++){
      ipv6_prefix.__in6_u.__u6_addr8[j] = packet[32 + 20 * i + j];
     
    }
    
    output->entries[i - 1].prefix_or_nh = ipv6_prefix;
    
  }
  output->numEntries = EntryNum;
  output->command = packet[48];
  return RipngErrorCode::SUCCESS;
}

uint32_t assemble(const RipngPacket *ripng, uint8_t *buffer) {
  // TODO
  buffer[0] = ripng->command;
  buffer[1] = 0x1;
  buffer[2] = 0x00;
  buffer[3] = 0x0;
  
  for (int i = 0; i < ripng->numEntries;i++){
    for (int j = 0; j < 16;j++){
      buffer[20 * i + 4 + j] = ripng->entries[i].prefix_or_nh.__in6_u.__u6_addr8[j];
      
    }
    
    union
    {
      uint8_t tag_8[2];
      uint16_t tag;
    } RouteTag;
    RouteTag.tag = ripng->entries[i].route_tag;
    buffer[20 * i + 4 + 16] = RouteTag.tag_8[0];
    buffer[20 * i + 4 + 17] = RouteTag.tag_8[1];
    buffer[20 * i + 4 + 18] = ripng->entries[i].prefix_len;
    buffer[20 * i + 4 + 19] = ripng->entries[i].metric;
  }

    return 4 + 20 * ripng->numEntries;
}