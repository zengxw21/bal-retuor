#include "lookup.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <list>
#include<iostream>
std::list<RoutingTableEntry> entry_list;

void update(bool insert, const RoutingTableEntry entry) {
  // TODO
  
  
  if (insert)
  {
    for(auto &i:entry_list){
      if(i.addr==entry.addr&&i.len==entry.len){
        i.if_index = entry.if_index;
        i.nexthop = entry.nexthop;
        return;
      }
    }
    entry_list.push_back(entry);
  }
  else{
    for (auto i = entry_list.begin(); i != entry_list.end();){
      if(i->addr==entry.addr&&i->len==entry.len){
        i = entry_list.erase(i);
      }
      else{
        i++;
      }
    }
  }
}

bool match(RoutingTableEntry entry,const in6_addr addr){
  
  auto prefix_len = entry.len;
  int index = 0;
  bool match = true;
  while (prefix_len >= 8)
  {
    if(entry.addr.__in6_u.__u6_addr8[index] != addr.__in6_u.__u6_addr8[index]){
      match = false;
    }
    prefix_len -= 8;
    index++;
  }
  auto move = 8 - prefix_len;//右移位数
  if((entry.addr.__in6_u.__u6_addr8[index]>>move) != (addr.__in6_u.__u6_addr8[index]>>move))
    match = false;
  return match;
}

bool prefix_query(const in6_addr addr, in6_addr *nexthop, uint32_t *if_index) {
  // TODO
  
  std::list<RoutingTableEntry> match_list;
  RoutingTableEntry *max_entry = nullptr;
  uint32_t max_len = 0;
  for (auto &i : entry_list)
  {

    if(match(i,addr)){
      if(i.len>=max_len){
        max_len = i.len;
        max_entry = &i;
      }
    }
  }
  bool found = false;
  if (max_entry != nullptr)
  {
    found = true;
    *nexthop = max_entry->nexthop;
    *if_index = max_entry->if_index;
  }
  
  return found;
  return false;
}

int mask_to_len(const in6_addr mask) {
  // TODO
 
  
  //TODO: 判断是否合法
  
  int cnt = 0;
  for (int i = 0; i < 16;i++){
    auto tmp = mask.__in6_u.__u6_addr8[i];
    while(tmp){
      if(tmp%2==1){
        cnt++;
      }
      tmp /= 2;
    }
  }
  return cnt;
  return -1;
}

in6_addr len_to_mask(int length) {
  // TODO
  
  in6_addr mask;
  int len = length;
  int index = 0;
  while (len >= 8){
    mask.__in6_u.__u6_addr8[index] = 0xff;
    index++;
    len -= 8;
  }
  int re = 0;
  while (len > 0)
  {
    re <<= 1;
    re += 1;
    len--;
  }//BUG:re===0
  while(re>0&&re<=127){
    
    re <<= 1;
  }
  mask.__in6_u.__u6_addr8[index] = re;
  for (int i = index + 1; i < 16;i++){
    mask.__in6_u.__u6_addr8[i] = 0x0;
  }
    
  return mask;
}
