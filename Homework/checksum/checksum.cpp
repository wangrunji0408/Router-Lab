#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>

// 计算校验和
uint16_t calcChecksum(const uint8_t *data, int len) {
  uint32_t s = 0;
  for (int i = 0; i < len; i += 2)
    s += ntohs(*(uint16_t *)&data[i]);
  if (len % 2 == 1)
    s += data[len - 1];
  s = (s & 0xffff) + (s >> 16);
  return s;
}

struct IPHeader {
  uint8_t version_ihl;
  uint8_t tos;
  uint16_t total_length;
  uint8_t padding[4];
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  uint32_t src_addr;
  uint32_t dst_addr;

  uint8_t get_header_length() const { return (version_ihl & 0xf) * 4; }
  uint16_t get_total_length() const { return ntohs(total_length); }
  uint16_t get_payload_length() const {
    return get_total_length() - get_header_length();
  }
  void *get_payload() const { return (uint8_t *)this + get_header_length(); }
  // 计算校验和
  uint16_t calc_checksum() const {
    return calcChecksum((const uint8_t *)this, get_header_length());
  }
};

struct UDPHeader {
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t length;
  uint16_t checksum;

  uint16_t get_src_port() const { return ntohs(src_port); }
  uint16_t get_dst_port() const { return ntohs(dst_port); }
  uint16_t get_length() const { return ntohs(length); }
  // 计算校验和
  uint16_t calc_checksum(uint32_t src_addr, uint32_t dst_addr) const {
    uint32_t s =
        calcChecksum((const uint8_t *)this, sizeof(UDPHeader) + get_length());
    // pseudo IP header
    s += calcChecksum((const uint8_t *)&src_addr, 4);
    s += calcChecksum((const uint8_t *)&dst_addr, 4);
    s += 17; // Protocol: UDP
    s += calcChecksum((const uint8_t *)&length, 2);
    
    s = (s & 0xffff) + (s >> 16);
    s = (s & 0xffff) + (s >> 16);
    return s;
  }
};

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  auto ip = (const IPHeader *)packet;
  return ip->calc_checksum() == 0xffff;
}
