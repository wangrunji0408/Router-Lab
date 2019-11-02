#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>

struct IPHeader {
  uint8_t version_ihl;
  uint8_t tos;
  uint16_t total_length;
  uint8_t padding[4];
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;

  uint8_t get_header_length() const { return (version_ihl & 0xf) * 4; }
  uint16_t get_total_length() const { return ntohs(total_length); }
  uint16_t get_payload_length() const {
    return get_total_length() - get_header_length();
  }
  void *get_payload() const { return (uint8_t *)this + get_header_length(); }
};

// 计算 IP 头校验和
uint16_t calcIPChecksum(uint8_t *packet) {
  auto header = (IPHeader *)packet;
  int header_len = header->get_header_length();
  uint32_t s = 0;
  for (int i = 0; i < header_len; i += 2)
    s += ntohs(*(uint16_t *)&packet[i]);
  s = (s & 0xffff) + (s >> 16);
  return s;
}

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  return calcIPChecksum(packet) == 0xffff;
}
