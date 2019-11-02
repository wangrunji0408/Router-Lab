#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  int header_len = (packet[0] & 0xf) * 4;
  uint32_t s = 0;
  for (int i = 0; i < header_len; i += 2)
    s += ((uint16_t)packet[i] << 8) | packet[i + 1];
  s = (s & 0xffff) + (s >> 16);
  return s == 0xffff;
}
