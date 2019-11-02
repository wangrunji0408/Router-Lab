#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <vector>

/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/
std::vector<RoutingTableEntry> entries;

// 是否 addr, len 相同
bool key_equal(const RoutingTableEntry &a, const RoutingTableEntry &b) {
  return a.addr == b.addr && a.len == b.len;
}

// 找到第一个 addr, len 相同的项，没找到返回 -1
int find_addr(const RoutingTableEntry &e) {
  for (int i = 0; i < entries.size(); ++i) {
    if (key_equal(entries[i], e)) {
      return i;
    }
  }
  return -1;
}

// addr 是否匹配表项 e
bool match(const RoutingTableEntry &e, uint32_t addr) {
  if (e.len == 32)
    return e.addr == addr;
  return e.addr == (addr & ((1u << e.len) - 1));
}

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 *
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len **精确** 匹配。
 */
void update(bool insert, RoutingTableEntry entry) {
  int idx = find_addr(entry);
  if (insert) {
    if (idx == -1) {
      // add
      entries.push_back(entry);
    } else {
      // update
      entries[idx] = entry;
    }
  } else {
    if (idx != -1) {
      // remove
      entries.erase(entries.begin() + idx);
    }
  }
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，网络字节序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool prefix_query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
  int i = 0;
  int max_match_i = -1;
  int max_match_len = -1;
  for (auto const &e : entries) {
    if (match(e, addr) && (int)e.len > max_match_len) {
      max_match_len = e.len;
      max_match_i = i;
    }
    i += 1;
  }
  if (max_match_i == -1) {
    return false;
  }
  *nexthop = entries[max_match_i].nexthop;
  *if_index = entries[max_match_i].if_index;
  return true;
}
