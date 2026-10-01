#ifndef PLATFORM_H
#define PLATFORM_H

/**
 * @file platform.h
 * @brief Platform-specific includes and definitions for cross-platform compatibility.
 * 
 * Provides portable byte-order conversion functions.
 */

#include <cstdint>

/**
 * @brief Portable byte order conversion namespace.
 * 
 * Works on any platform without requiring system headers.
 */
namespace PortableNet {

inline uint16_t swapBytes16(uint16_t value) {
  return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8);
}

inline uint32_t swapBytes32(uint32_t value) {
  return ((value & 0xFF000000) >> 24) | ((value & 0x00FF0000) >> 8) |
         ((value & 0x0000FF00) << 8) | ((value & 0x000000FF) << 24);
}

/**
 * @brief Check system endianness at runtime.
 * 
 * @return true if the system is little-endian, false otherwise.
 */
inline bool isLittleEndian() {
  uint16_t test = 0x0001;
  return *reinterpret_cast<uint8_t *>(&test) == 0x01;
}

/**
 * @brief Convert a 16-bit network byte order value to host byte order.
 * 
 * Network byte order is always big-endian.
 * 
 * @param netValue The network byte order value.
 * @return The host byte order value.
 */
inline uint16_t netToHost16(uint16_t netValue) {
  if (isLittleEndian()) {
    return swapBytes16(netValue);
  }
  return netValue;
}

/**
 * @brief Convert a 32-bit network byte order value to host byte order.
 * 
 * @param netValue The network byte order value.
 * @return The host byte order value.
 */
inline uint32_t netToHost32(uint32_t netValue) {
  if (isLittleEndian()) {
    return swapBytes32(netValue);
  }
  return netValue;
}

/**
 * @brief Convert a 16-bit host byte order value to network byte order.
 * 
 * @param hostValue The host byte order value.
 * @return The network byte order value.
 */
inline uint16_t hostToNet16(uint16_t hostValue) {
  return netToHost16(hostValue); // Same operation
}

/**
 * @brief Convert a 32-bit host byte order value to network byte order.
 * 
 * @param hostValue The host byte order value.
 * @return The network byte order value.
 */
inline uint32_t hostToNet32(uint32_t hostValue) {
  return netToHost32(hostValue); // Same operation
}

} // namespace PortableNet

#endif // PLATFORM_H
