#ifndef PLATFORM_H
#define PLATFORM_H

#include <cstdint>

using namespace std;

namespace PortableNet {

inline uint16_t swapBytes16(uint16_t value) {
  return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8);
}

inline uint32_t swapBytes32(uint32_t value) {
  return ((value & 0xFF000000) >> 24) | ((value & 0x00FF0000) >> 8) |
         ((value & 0x0000FF00) << 8) | ((value & 0x000000FF) << 24);
}

inline bool isLittleEndian() {
  uint16_t test = 0x0001;
  return *reinterpret_cast<uint8_t *>(&test) == 0x01;
}

inline uint16_t netToHost16(uint16_t netValue) {
  if (isLittleEndian()) {
    return swapBytes16(netValue);
  }
  return netValue;
}

inline uint32_t netToHost32(uint32_t netValue) {
  if (isLittleEndian()) {
    return swapBytes32(netValue);
  }
  return netValue;
}

inline uint16_t hostToNet16(uint16_t hostValue) {
  return netToHost16(hostValue); 
}

inline uint32_t hostToNet32(uint32_t hostValue) {
  return netToHost32(hostValue); 
}

} 

#endif 
