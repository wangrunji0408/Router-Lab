#include "../checksum/checksum.cpp"
#include "rip.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/*
  在头文件 rip.h 中定义了结构体 `RipEntry` 和 `RipPacket` 。
  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的
  IP 包。 由于 RIP 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在
  RipPacket 中额外记录了个数。 需要注意这里的地址都是用 **网络字节序（大端序）**
  存储的，1.2.3.4 在小端序的机器上被解释为整数 0x04030201 。
*/

const uint16_t RIP_PORT = 520;

struct RipRouteEntry {
  uint16_t family;
  uint16_t tag;
  uint32_t addr;
  uint32_t mask;
  uint32_t nexthop;
  uint32_t metric;

  void load_from_info(const RipEntry *e) {
    family = htons(2);
    tag = htons(0);
    addr = e->addr;
    mask = e->mask;
    nexthop = e->nexthop;
    metric = e->metric;
  }

  void write_to_info(RipEntry *e) const {
    e->addr = addr;
    e->mask = mask;
    e->nexthop = nexthop;
    e->metric = metric;
  }
};

struct RipPacketRaw {
  uint8_t command;
  uint8_t version;
  uint16_t zero;
  RipRouteEntry entries[0];

  void load_from_info(const RipPacket *rip) {
    command = rip->command;
    version = 2;
    zero = 0;
    for (int i = 0; i < rip->numEntries; ++i) {
      entries[i].load_from_info(&rip->entries[i]);
    }
  }

  // 将内容写入 `RipPacket`，其中 entry 个数为 `n`
  void write_to_info(int n, RipPacket *rip) const {
    rip->numEntries = n;
    rip->command = command;
    for (int i = 0; i < n; ++i) {
      entries[i].write_to_info(&rip->entries[i]);
    }
  }

  // 检查是否合法
  bool validate() const {
    return (command == 1 || command == 2) && version == 2 && zero == 0;
  }
};

/**
 * @brief 从接受到的 IP 包解析出 RIP 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回
 * true；否则返回 false
 *
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len
 * 时，把传入的 IP 包视为不合法。 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  auto ip = (IPHeader *)packet;
  if (ip->get_total_length() > len) {
    return false;
  }
  if (ip->protocol != IPPROTO_UDP) {
    return false;
  }
  auto udp = (UDPHeader *)ip->get_payload();
  if (!(udp->get_src_port() == RIP_PORT && udp->get_dst_port() == RIP_PORT &&
        udp->calc_checksum(ip->src_addr, ip->dst_addr) == 0xffff)) {
    return false;
  }
  int entry_count = udp->get_length() / sizeof(RipRouteEntry);
  auto rip = (RipPacketRaw *)(udp + 1);
  if (!rip->validate()) {
    return false;
  }
  rip->write_to_info(entry_count, output);
  return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 *
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括
 * Version、Zero、Address Family 和 Route Tag 这四个字段 你写入 buffer
 * 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  auto rip_packet = (RipPacketRaw *)buffer;
  rip_packet->load_from_info(rip);
  int length = sizeof(RipPacketRaw) + rip->numEntries * sizeof(RipRouteEntry);
  return length;
}
