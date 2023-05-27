#include "checksum.h"
#include "common.h"
#include "eui64.h"
#include "lookup.h"
#include "protocol.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <list>
#include <math.h>
#define MAX_NUM 25
uint8_t packet[2048];
uint8_t output[2048];
extern std::list<RoutingTableEntry> entry_list;
in6_addr multicast = {0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x09};

// for online experiment, don't change
#ifdef ROUTER_R1
// 0: fd00::1:1/112
// 1: fd00::3:1/112
// 2: fd00::6:1/112
// 3: fd00::7:1/112
in6_addr addrs[N_IFACE_ON_BOARD] = {
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x01, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x03, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x06, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x07, 0x00, 0x01},
};
#elif defined(ROUTER_R2)
// 0: fd00::3:2/112
// 1: fd00::4:1/112
// 2: fd00::8:1/112
// 3: fd00::9:1/112
in6_addr addrs[N_IFACE_ON_BOARD] = {
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x03, 0x00, 0x02},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x04, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x08, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x09, 0x00, 0x01},
};
#elif defined(ROUTER_R3)
// 0: fd00::4:2/112
// 1: fd00::5:2/112
// 2: fd00::a:1/112
// 3: fd00::b:1/112
in6_addr addrs[N_IFACE_ON_BOARD] = {
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x04, 0x00, 0x02},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x05, 0x00, 0x02},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x0a, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x0b, 0x00, 0x01},
};
#else

// 自己调试用，你可以按需进行修改
// 0: fd00::0:1
// 1: fd00::1:1
// 2: fd00::2:1
// 3: fd00::3:1
in6_addr addrs[N_IFACE_ON_BOARD] = {
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x01, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x02, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x03, 0x00, 0x01},
};
#endif

void SendTable(int if_index,in6_addr ip_src,in6_addr ip_dst,ether_addr mac_dst){
  RipngPacket ripng;
  int index = 0;
  bool flag = false;
  for(auto &entry:entry_list){
    flag = true;
    ripng.command = 2;
    ripng.entries[index].prefix_or_nh = entry.addr;
    //ripng.entries[index].route_tag = entry.route_tag;
    ripng.entries[index].metric = (if_index == entry.if_index) ? 16 : entry.metric;
    ripng.entries[index].prefix_len = entry.len;
    index++;
    if(index==MAX_NUM){
      index = 0;
      flag = false;
      ripng.numEntries = MAX_NUM;
      int header_len = sizeof(udphdr) + sizeof(ripng_hdr);
      int entry_len = sizeof(ripng_rte) * MAX_NUM;

      ip6_hdr *ip6 = (ip6_hdr *)&output[0];
      ip6->ip6_flow = 0;
      ip6->ip6_vfc = 6 << 4;
      ip6->ip6_plen = htons(header_len + entry_len);//BUGGY
      ip6->ip6_nxt = IPPROTO_UDP;
      ip6->ip6_hlim = 255;
      ip6->ip6_src = ip_src;
      ip6->ip6_dst = ip_dst;

      udphdr *udp_header = (udphdr *)&output[sizeof(ip6_hdr)];
      udp_header->uh_dport = htons(521);//BUGGY
      udp_header->uh_sport = htons(521);//BUGGY
      udp_header->uh_ulen = ip6->ip6_plen;

      uint8_t *buffer = output + 48;
      assemble((const RipngPacket *)(&ripng), buffer);
      validateAndFillChecksum(output, sizeof(ip6_hdr) + header_len + entry_len);
      HAL_SendIPPacket(if_index, output, header_len + entry_len + sizeof(ip6_hdr), mac_dst);
    }
  }
  //剩下的
  if(flag){
    ripng.numEntries = index;
    int header_len = sizeof(udphdr) + sizeof(ripng_hdr);
    int entry_len = ripng.numEntries * sizeof(ripng_rte);
    ip6_hdr *ip6 = (ip6_hdr *)&output[0];

    ip6->ip6_flow = 0;
    ip6->ip6_vfc = 6 << 4;
    ip6->ip6_plen = htons(header_len + entry_len);
    ip6->ip6_nxt = IPPROTO_UDP;
    ip6->ip6_hlim = 255;
    ip6->ip6_src = ip_src;
    ip6->ip6_dst = ip_dst;

    udphdr *udp = (udphdr *)&output[sizeof(ip6_hdr)];
    udp->uh_dport = htons(521);
    udp->uh_sport = htons(521);
    udp->uh_ulen = ip6->ip6_plen;

    uint8_t *buffer = output + 48;
    assemble((const RipngPacket *)(&ripng), buffer);

    validateAndFillChecksum(output, header_len + entry_len + sizeof(ip6_hdr));
    HAL_SendIPPacket(if_index, output, header_len + entry_len + sizeof(ip6_hdr), mac_dst);
  }
}

int main(int argc, char *argv[]) {
  // 初始化 HAL
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }

  // 插入直连路由
  // 例如 R2：
  // fd00::3:0/112 if 0
  // fd00::4:0/112 if 1
  // fd00::8:0/112 if 2
  // fd00::9:0/112 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
    in6_addr mask = len_to_mask(112);
    // TODO（1 行）
    // 这里需要添加额外的字段来初始化 metric
    RoutingTableEntry entry = {
        .addr = addrs[i] & mask,
        .len = 112,
        .if_index = i,
        .nexthop = in6_addr{0}, // 全 0 表示直连路由
        //.route_tag=0,
        .metric=1
        
    };
    update(true, entry);
  }

#ifdef ROUTER_INTERCONNECT
  // 互联测试
  // 添加路由：
  // fd00::1:0/112 via fd00::3:1 if 0
  // TODO（1 行）
  // 这里需要添加额外的字段来初始化 metric
  RoutingTableEntry entry = {
      .addr = {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
               0x00, 0x00, 0x01, 0x00, 0x00},
      //.metric=1,
      //.route_tag=0,
      .len = 112,
      .if_index = 0,
      .nexthop = {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x03, 0x00, 0x01},
      //.route_tag=0,
      .metric=1
      };
  update(true, entry);
#endif

  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    // RFC 要求每 30s 发送一次
    // 为了提高收敛速度，设为 5s
    if (time > last_time + 5 * 1000) {
      // 提示：你可以打印完整的路由表到 stdout/stderr 来帮助调试。
      //printf("5s Timer\n");

      for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
        ether_addr mac;
        HAL_GetInterfaceMacAddress(i, &mac);
        in6_addr src = eui64(mac);
        ether_addr mac_dst = {0x33, 0x33, 0x00, 0x00, 0x00, 0x09};
        SendTable(i, src, multicast, mac_dst);
        // 下面举一个构造 IPv6 packet
        // 的例子，之后有多处代码需要实现类似的功能，请参考此处的例子进行编写。建议实现单独的函数来简化这个过程。

        // TODO（40 行）
        // 这一步需要向所有 interface 发送当前的完整路由表，设置 Command 为
        // Response，并且注意当路由表表项较多时，需要拆分为多个 IPv6
        // packet。此时 IPv6 packet 的源地址应为使用 eui64 计算得到的 Link Local
        // 地址，目的地址为 ff02::9，以太网帧的源 MAC 地址为当前 interface 的
        // MAC 地址，目的 MAC 地址为 33:33:00:00:00:09，详见 RFC 2080
        // Section 2.5.2 Generating Response Messages。
        //
        // 注意需要实现水平分割以及毒性反转（Split Horizon with Poisoned
        // Reverse） 即，如果某一条路由表项是从 interface A 学习到的，那么发送给
        // interface A 的 RIPng 表项中，该项的 metric 设为 16。详见 RFC 2080
        // Section 2.6 Split Horizon。因此，发往各个 interface 的 RIPng
        // 表项是不同的。
      }
      last_time = time;
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    ether_addr src_mac;
    ether_addr dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), &src_mac, &dst_mac,
                              1000, &if_index);
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }

    // 检查 IPv6 头部长度
    ip6_hdr *ip6 = (ip6_hdr *)packet;
    if (res < sizeof(ip6_hdr)) {
      //printf("Received invalid ipv6 packet (%d < %d)\n", res, sizeof(ip6_hdr));
      continue;
    }
    uint16_t plen = ntohs(ip6->ip6_plen);
    if (res < plen + sizeof(ip6_hdr)) {
      //printf("Received invalid ipv6 packet (%d < %d + %d)\n", res, plen,
      //       sizeof(ip6_hdr));
      continue;
    }

    // 检查 IPv6 头部目的地址是否为我自己
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&ip6->ip6_dst, &addrs[i], sizeof(in6_addr)) == 0) {
        dst_is_me = true;
        break;
      }
    }

    
    // TODO（1 行）
    // 修改这个检查，当目的地址为 RIPng 的组播目的地址（ff02::9）时也设置
    // dst_is_me 为 true。
    if (ip6->ip6_dst==multicast) {
      dst_is_me = true;
    }

    if (dst_is_me) {
      // 目的地址是我，按照类型进行处理

      // 检查 checksum 是否正确
      if (ip6->ip6_nxt == IPPROTO_UDP || ip6->ip6_nxt == IPPROTO_ICMPV6) {
        if (!validateAndFillChecksum(packet, res)) {
          //printf("Received packet with bad checksum\n");
          continue;
        }
      }

      if (ip6->ip6_nxt == IPPROTO_UDP) {
        // 检查是否为 RIPng packet
        RipngPacket ripng;
        RipngErrorCode err = disassemble(packet, res, &ripng);
        if (err == SUCCESS) {
          if (ripng.command == 1) {
            // 可选功能，实现了可以加快路由表收敛速度
            // Command 为 Request
            // 参考 RFC 2080 Section 2.4.1 Request Messages 实现
            // 本次实验中，可以简化为只考虑输出完整路由表的情况

            RipngPacket resp;
            // ether_addr mac;
            // HAL_GetInterfaceMacAddress(if_index, &mac);
            // in6_addr ip_src = eui64(mac);
            // in6_addr ip_dst = ip6->ip6_src;
            // ether_addr mac_dst = src_mac;
            // SendTable(if_index, ip_src, ip_dst, mac_dst);
            // 与 5s Timer 时的处理类似，也需要实现水平分割和毒性反转
            // 可以把两部分代码写到单独的函数中
            // 不同的是，在 5s Timer
            // 中要组播发给所有的路由器；这里则是某一个路由器 Request
            // 本路由器，因此回复 Response 的时候，目的 IPv6 地址和 MAC
            // 地址都应该指向发出请求的路由器

            // 最后把 RIPng 报文发送出去
          } else {
            // TODO（40 行）
            // Command 为 Response
            // 参考 RFC 2080 Section 2.4.2 Request Messages 实现
            // 按照接受到的 RIPng 表项更新自己的路由表
            // 在本实验中，可以忽略 metric=0xFF 的表项，它表示的是 Nexthop
            // 的设置，可以忽略

            // 接下来的处理中，都首先对输入的 RIPng 表项做如下处理：
            // metric = MIN(metric + cost, infinity)
            // 其中 cost 取 1，表示经过了一跳路由器；infinity 用 16 表示

            // 如果出现了一条新的路由表项，并且 metric 不等于 16：
            // 插入到自己的路由表中，设置 nexthop
            // 地址为发送这个 Response 的路由器。

            // 如果收到的路由表项和已知的重复（注意，是精确匹配），
            // 进行以下的判断：如果路由表中的表项是之前从该路由器从学习而来，那么直接更新
            // metric
            // 为新的值；如果路由表中表现是从其他路由器那里学来，就比较已有的表项和
            // RIPng 表项中的 metric 大小，如果 RIPng 表项中的 metric
            // 更小，说明找到了一条更新的路径，那就用新的表项替换原有的，同时更新
            // nexthop 地址。
            for (auto i = 0; i < ripng.numEntries;i++){
              if(ripng.entries[i].metric==0xff){
                continue;
              }
              uint8_t metric = ripng.entries[i].metric + 1 > 16 ? 16 : ripng.entries[i].metric + 1;
              //int index = -1;
              bool found = false;
              for (auto &entry : entry_list){
                if(entry.addr==ripng.entries[i].prefix_or_nh&&entry.len==(uint32_t)ripng.entries[i].prefix_len){
                  found = true;//找到
                  if(entry.nexthop==ip6->ip6_src){
                    entry.metric = metric;
                    entry.if_index = if_index;
                    entry.nexthop = ip6->ip6_src;
                  }
                  else{//其他地方学
                    if(metric<entry.metric){//找到新路径
                      entry.addr = ripng.entries[i].prefix_or_nh;
                      entry.len = ripng.entries[i].prefix_len;
                      entry.if_index = if_index;
                      entry.nexthop = ip6->ip6_src;
                      entry.metric = metric;
                      //entry.route_tag = ripng.entries[i].route_tag;
                    }
                  }
                  break;
                }
              }
              if(found==false){
                if(metric<16){
                  RoutingTableEntry entry;
                  entry.addr = ripng.entries[i].prefix_or_nh;
                  entry.len = ripng.entries[i].prefix_len;
                  entry.if_index = (uint32_t)if_index;
                  entry.nexthop = ip6->ip6_src;
                  //entry.route_tag = ripng.entries[i].route_tag;
                  entry.metric = metric;
                  update(true, entry);
                }
              }
            }
            // 可选功能：实现 Triggered
            // Updates，即在路由表出现更新的时候，向所有 interface
            // 发送出现变化的路由表项，注意此时依然要实现水平分割和毒性反转。详见
            // RFC 2080 Section 2.5.1。
          }
        } else {
          // 接受到一个错误的 RIPng packet >_<
          //printf("Got bad RIPng packet from IP %s with error: %s\n",
                 //inet6_ntoa(ip6->ip6_src), ripng_error_to_string(err));
        }
      } else if (ip6->ip6_nxt == IPPROTO_ICMPV6) {
        // TODO（20 行）
        // 如果是 ICMPv6 packet
        // 检查是否是 Echo Request
        icmp6_hdr *icmp6 = (icmp6_hdr *)&packet[sizeof(ip6_hdr)];
        if (icmp6->icmp6_type==ICMP6_ECHO_REQUEST){
          memcpy(output, packet, res);
          ip6_hdr *ip6_header = (ip6_hdr *)&output[0];
          icmp6_hdr *icmp6_header = (icmp6_hdr *)&output[sizeof(ip6_hdr)];
          icmp6_header->icmp6_type = ICMP6_ECHO_REPLY;
          ip6_header->ip6_src = ip6->ip6_dst;
          ip6_header->ip6_dst = ip6->ip6_src;
          ip6_header->ip6_hlim = 64;
          validateAndFillChecksum(output, res);
          HAL_SendIPPacket(if_index, output, res, src_mac);
          // 如果是 Echo Request，生成一个对应的 Echo Reply：交换源和目的 IPv6
          // 地址，设置 type 为 Echo Reply，设置 TTL（Hop Limit） 为
          // 64，重新计算 Checksum 并发送出去。详见 RFC 4443 Section 4.2 Echo
          // Reply Message
        }
      }
      continue;
    } else {
      // 目标地址不是我，考虑转发给下一跳
      // 检查是否是组播地址（ff00::/8），不需要转发组播分组
      if (ip6->ip6_dst.s6_addr[0] == 0xff) {
        //printf("Don't forward multicast packet to %s\n",
          //     inet6_ntoa(ip6->ip6_dst));
        continue;
      }

      // 检查 TTL（Hop Limit）是否小于或等于 1
      uint8_t ttl = ip6->ip6_hops;
      if (ttl <= 1) {
        auto length = (res > 1232) ? 1232 : res;
        ip6_hdr *ip6_header = (ip6_hdr *)&output[0];
        ip6_header->ip6_flow = 0;
        ip6_header->ip6_vfc = 6 << 4;
        ip6_header->ip6_plen = htons(sizeof(icmp6_hdr) + length);//HTONS BUGGY
        ip6_header->ip6_nxt = IPPROTO_ICMPV6;
        ip6_header->ip6_hlim = 255;
        ip6_header->ip6_src = addrs[if_index];
        ip6_header->ip6_dst = ip6->ip6_src;
        icmp6_hdr *icmp6_header = (icmp6_hdr *)&output[sizeof(ip6_hdr)];
        icmp6_header->icmp6_type = 3;
        icmp6_header->icmp6_code = 0;
        icmp6_header->icmp6_cksum = 0;
        memcpy(output + sizeof(ip6_hdr) + sizeof(icmp6_hdr), packet, length);
        validateAndFillChecksum(output, sizeof(ip6_hdr) + sizeof(icmp6_hdr) + length);
        HAL_SendIPPacket(if_index, output, sizeof(ip6_hdr) + sizeof(icmp6_hdr) + length, src_mac);
        // TODO（40 行）
        // 发送 ICMP Time Exceeded 消息
        // 将接受到的 IPv6 packet 附在 ICMPv6 头部之后。
        // 如果长度大于 1232 字节，则取前 1232 字节：
        // 1232 = IPv6 Minimum MTU(1280) - IPv6 Header(40) - ICMPv6 Header(8)
        // 意味着发送的 ICMP Time Exceeded packet 大小不大于 IPv6 Minimum MTU
        // 不会因为 MTU 问题被丢弃。
        // 详见 RFC 4443 Section 3.3 Time Exceeded Message
        // 计算 Checksum 后由自己的 IPv6 地址发送给源 IPv6 地址。
      } else {
        // 转发给下一跳
        // 按最长前缀匹配查询路由表
        in6_addr nexthop;
        uint32_t dest_if;
        if (prefix_query(ip6->ip6_dst, &nexthop, &dest_if)) {
          // 找到路由
          ether_addr dest_mac;
          // 如果下一跳为全 0，表示的是直连路由，目的机器和本路由器可以直接访问
          if (nexthop == in6_addr{0}) {
            nexthop = ip6->ip6_dst;
          }
          if (HAL_GetNeighborMacAddress(dest_if, nexthop, &dest_mac) == 0) {
            // 在 NDP 表中找到了下一跳的 MAC 地址
            // TTL-1
            ip6->ip6_hops--;

            // 转发出去
            memcpy(output, packet, res);
            HAL_SendIPPacket(dest_if, output, res, dest_mac);
          } else {
            // 没有找到下一跳的 MAC 地址
            // 本实验中可以直接丢掉，等对方回复 NDP 之后，再恢复正常转发。
            //printf("Nexthop ip %s is not found in NDP table\n",
             //      inet6_ntoa(nexthop));
          }
        } else {
          auto length = (res > 1232) ? 1232 : res;
          ip6_hdr *ip6_header = (ip6_hdr *)&output[0];
          ip6_header->ip6_flow = 0;
          ip6_header->ip6_vfc = 6 << 4;
          ip6_header->ip6_plen = htons(sizeof(icmp6_hdr) + length);//BUGGY htons
          ip6_header->ip6_nxt = IPPROTO_ICMPV6;
          ip6_header->ip6_hlim = 255;
          ip6_header->ip6_src = addrs[if_index];
          ip6_header->ip6_dst = ip6->ip6_src;
          icmp6_hdr *icmp6_header = (icmp6_hdr *)&output[sizeof(ip6_hdr)];
          icmp6_header->icmp6_type = 1;
          icmp6_header->icmp6_code = 0;
          icmp6_header->icmp6_cksum = 0;
          memcpy(output + sizeof(ip6_hdr) + sizeof(icmp6_hdr), packet, length);
          validateAndFillChecksum(output, sizeof(ip6_hdr) + sizeof(icmp6_hdr) + length);
          HAL_SendIPPacket(if_index, output, sizeof(ip6_hdr) + sizeof(icmp6_hdr) + length, src_mac);
          // TODO（40 行）
          // 没有找到路由
          // 发送 ICMPv6 Destination Unreachable 消息
          // 要求与上面发送 ICMPv6 Time Exceeded 消息一致
          // Code 取 0，表示 No route to destination
          // 详见 RFC 4443 Section 3.1 Destination Unreachable Message
          // 计算 Checksum 后由自己的 IPv6 地址发送给源 IPv6 地址。

         // printf("Destination IP %s not found in routing table",
          //       inet6_ntoa(ip6->ip6_dst));
          //printf(" and source IP is %s\n", inet6_ntoa(ip6->ip6_src));
        }
      }
    }
  }
  return 0;
}
