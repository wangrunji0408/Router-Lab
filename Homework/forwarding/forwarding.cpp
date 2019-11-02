#include <stdint.h>
#include <stdlib.h>
#include "../checksum/checksum.cpp"

// 在 checksum.cpp 中定义
extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern uint16_t calcIPChecksum(uint8_t *packet);

// 更新 IP 头校验和
void updateIPChecksum(uint8_t *packet, size_t len) {
  auto header = (IPHeader *)packet;
  header->checksum = 0;
  uint16_t s = ~calcIPChecksum(packet);
  header->checksum = htons(s);
}

// TTL -= 1
void ttlDecrease(uint8_t *packet) {
  auto header = (IPHeader *)packet;
  header->ttl -= 1;
}

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以调用 checksum 题中的 validateIPChecksum 函数，
 *        编译的时候会链接进来。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
  if (!validateIPChecksum(packet, len)) {
    return false;
  }
  ttlDecrease(packet);
  updateIPChecksum(packet, len);
  return true;
}
