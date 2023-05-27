#include "checksum.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include<iostream>
using namespace std;
#define UDP 17
#define ICMPv6 58
struct PseudoHeader
{
  union{
    struct{
      in6_addr src;
      in6_addr dst;
      uint32_t Length;
      uint8_t Tail[4];
    };
    uint16_t pseudo_header_array[20];
  };
};
struct Packet{
  union{//以下随机定义了包的大小上限
    uint8_t packet_8[1000];
    uint16_t packet_16[500];
  };
};
struct Group
{
  union{
    struct{
      PseudoHeader pseudo_header;
      Packet packet;
    };
    uint16_t array[520];
  };
};

uint64_t GetSum(ip6_hdr *ip6,uint16_t length,size_t len,uint8_t * packet,uint8_t type){
  PseudoHeader pseudo_header;
    pseudo_header.src = ip6->ip6_src;
    pseudo_header.dst = ip6->ip6_dst;
    pseudo_header.Length = type==UDP?length: htonl(length);//加htonl能过2，不加能过1
    //2是icmpv6包，1是udp包
    //icmpv6不记载length，本地计算得到的length是本地的字节序，
    for (int i = 0; i < 3;i++){
      pseudo_header.Tail[i] = 0;
    }
    pseudo_header.Tail[3] = type;

    //找到udp/icmpv6 packet
    Packet pkt;
    for (auto i = sizeof(ip6_hdr); i < len; i++){
      pkt.packet_8[i - sizeof(ip6_hdr)] = packet[i];
    }

    Group group;
    group.pseudo_header = pseudo_header;
    group.packet = pkt;
    //确认group长度是否为偶数个字节，并做相应修改
    auto count = 40 + len - sizeof(ip6_hdr);//
    if ((len - sizeof(ip6_hdr)) % 2 != 0){
      count += 1;
      group.packet.packet_8[len - sizeof(ip6_hdr)] = 0;
    }
    count /= 2;//看有多少个16位（双字节）数
    uint64_t sum = 0;
    for (int i = 0; i < count;i++){
      auto each_network = ntohs(group.array[i]);///???
      sum += each_network;
    }
    while((sum>>16)>0){
      auto overflow = sum >> 16;//超出16位的部分
      auto low = sum - (overflow << 16);
      sum = overflow + low;
    }
    return sum;
}

bool validateAndFillChecksum(uint8_t *packet, size_t len)
{
  // TODO
  struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;
  bool flag=false;
  // check next header
  uint8_t nxt_header = ip6->ip6_nxt;
  if (nxt_header == IPPROTO_UDP) {
    // UDP
    struct udphdr *udp = (struct udphdr *)&packet[sizeof(struct ip6_hdr)];
    auto length = udp->uh_ulen;
    auto checksum = ntohs(udp->uh_sum);
    if(checksum==0x0000){//udp校验和不能为0

      flag = false;
    }

    
    // length: udp->uh_ulen
    // checksum: udp->uh_sum

    //生成pseudo header
    PseudoHeader pseudo_header;
    pseudo_header.src = ip6->ip6_src;
    pseudo_header.dst = ip6->ip6_dst;
    pseudo_header.Length = length;
    for (int i = 0; i < 3;i++){
      pseudo_header.Tail[i] = 0;
    }
    pseudo_header.Tail[3] = 17;

    //找到udp/icmpv6 packet
    Packet pkt;
    for (auto i = sizeof(ip6_hdr); i < len; i++){
      pkt.packet_8[i - sizeof(ip6_hdr)] = packet[i];
    }

    Group group;
    group.pseudo_header = pseudo_header;
    group.packet = pkt;
    //确认group长度是否为偶数个字节，并做相应修改
    auto count = 40 + len - sizeof(ip6_hdr);//
    if ((len - sizeof(ip6_hdr)) % 2 != 0){
      count += 1;
      group.packet.packet_8[len - sizeof(ip6_hdr)] = 0;
    }
    count /= 2;//看有多少个16位（双字节）数
    uint64_t sum = 0;
    for (int i = 0; i < count;i++){
      auto each_network = ntohs(group.array[i]);///???
      sum += each_network;
    }
    while((sum>>16)>0){
      auto overflow = sum >> 16;//超出16位的部分
      auto low = sum - (overflow << 16);
      sum = overflow + low;
    }
    if(checksum==0x0000){//udp校验和不能为0
      
      flag = false;
      udp->uh_sum = 0x0;
      auto NewSum = GetSum(ip6, length, len, packet, UDP);
      uint16_t NewCheckSum = NewSum;
      NewCheckSum = ~NewCheckSum;
      if(NewCheckSum==0x0000){
        NewCheckSum = 0xffff;
      }
      
      udp->uh_sum = htons(NewCheckSum);
      return flag;
    }
    if (sum==0xffff){
      flag = true;
      return flag;
    }
    else{
      flag = false;
      udp->uh_sum = 0x0;
      auto NewSum = GetSum(ip6, length, len, packet, UDP);
      // NewSum = ~NewSum;
      uint16_t checksum = NewSum;
      checksum = ~checksum;
      udp->uh_sum = htons(checksum);
      return flag;
    }
  }
  else if (nxt_header == IPPROTO_ICMPV6)
  {
    // ICMPv6
    struct icmp6_hdr *icmp =
        (struct icmp6_hdr *)&packet[sizeof(struct ip6_hdr)];
    // length: len-sizeof(struct ip6_hdr)
    // checksum: icmp->icmp6_cksum
    auto length = len - sizeof(struct ip6_hdr);
    auto checksum = ntohs(icmp->icmp6_cksum);
    PseudoHeader pseudo_header;
    pseudo_header.src = ip6->ip6_src;
    pseudo_header.dst = ip6->ip6_dst;
    pseudo_header.Length = htonl(length);
    for (int i = 0; i < 3;i++){
      pseudo_header.Tail[i] = 0;
    }
    pseudo_header.Tail[3] = 58;

    //找到udp/icmpv6 packet
    Packet pkt;
    for (auto i = sizeof(ip6_hdr); i < len; i++){
      pkt.packet_8[i - sizeof(ip6_hdr)] = packet[i];
    }

    Group group;
    group.pseudo_header = pseudo_header;
    group.packet = pkt;
    //确认group长度是否为偶数个字节，并做相应修改
    auto count = 40 + len - sizeof(ip6_hdr);//
    if ((len - sizeof(ip6_hdr)) % 2 != 0){
      count += 1;
      group.packet.packet_8[len - sizeof(ip6_hdr)] = 0;
    }
    count /= 2;//看有多少个16位（双字节）数
    uint64_t sum = 0;
    for (int i = 0; i < count;i++){
      auto each_network = ntohs(group.array[i]);
      sum += each_network;
    }
    while((sum>>16)>0){
      auto overflow = sum >> 16;//超出16位的部分
      auto low = sum - (overflow << 16);
      sum = overflow + low;
    }
    if(sum==0xffff){
      
      if(checksum==0xffff){
        icmp->icmp6_cksum = 0x0000;//icmpv6校验和检验正确，但是不能
        //通过计算产生（fffff），需要改为同样正确的0
      }
      return true;
    }
    else{
      flag = false;
      icmp->icmp6_cksum = 0;
      auto NewSum = GetSum(ip6, length, len, packet, ICMPv6);
      uint16_t checksum = NewSum;
      checksum = ~checksum;
      icmp->icmp6_cksum = htons(checksum);
      return flag;
    }
  }
  else
  {
    assert(false);
  }
  return false;
}
