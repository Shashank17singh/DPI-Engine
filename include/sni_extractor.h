#ifndef SNI_EXTRACTOR_H
#define SNI_EXTRACTOR_H

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace DPI {

/**
 * @brief SNIExtractor class.
 * 
 * Parses TLS Client Hello packets to extract Server Name Indication (SNI).
 */
class SNIExtractor {
public:
  /**
   * @brief Extract SNI from a TLS Client Hello packet.
   * 
   * @param payload Pointer to the start of the TCP payload.
   * @param length Length of the payload.
   * @return std::optional<std::string> The extracted SNI, if found.
   */
  static std::optional<std::string> extract(const uint8_t *payload,
                                            size_t length);

  /**
   * @brief Check if the payload looks like a TLS Client Hello.
   * 
   * @param payload Pointer to the start of the TCP payload.
   * @param length Length of the payload.
   * @return true if it is a TLS Client Hello, false otherwise.
   */
  static bool isTLSClientHello(const uint8_t *payload, size_t length);

  /**
   * @brief Extract all extensions for debugging or logging.
   * 
   * @param payload Pointer to the start of the TCP payload.
   * @param length Length of the payload.
   * @return std::vector<std::pair<uint16_t, std::string>> List of extension types and their values.
   */
  static std::vector<std::pair<uint16_t, std::string>>
  extractExtensions(const uint8_t *payload, size_t length);

private:
  // TLS Constants
  static constexpr uint8_t CONTENT_TYPE_HANDSHAKE = 0x16;
  static constexpr uint8_t HANDSHAKE_CLIENT_HELLO = 0x01;
  static constexpr uint16_t EXTENSION_SNI = 0x0000;
  static constexpr uint8_t SNI_TYPE_HOSTNAME = 0x00;

  // Helper to read big-endian values
  static uint16_t readUint16BE(const uint8_t *data);
  static uint32_t readUint24BE(const uint8_t *data);
};

/**
 * @brief QUICSNIExtractor class.
 * 
 * Extracts SNI from QUIC/HTTP3 traffic.
 */
class QUICSNIExtractor {
public:
  /**
   * @brief Extract SNI from a QUIC Initial packet.
   * 
   * @param payload Pointer to the start of the UDP payload.
   * @param length Length of the payload.
   * @return std::optional<std::string> The extracted SNI, if found.
   */
  static std::optional<std::string> extract(const uint8_t *payload,
                                            size_t length);

  /**
   * @brief Check if the payload looks like a QUIC Initial packet.
   * 
   * @param payload Pointer to the start of the UDP payload.
   * @param length Length of the payload.
   * @return true if it is a QUIC Initial packet, false otherwise.
   */
  static bool isQUICInitial(const uint8_t *payload, size_t length);
};

/**
 * @brief HTTPHostExtractor class.
 * 
 * Extracts the Host header from unencrypted HTTP traffic.
 */
class HTTPHostExtractor {
public:
  /**
   * @brief Extract Host header from HTTP request.
   * 
   * @param payload Pointer to the start of the TCP payload.
   * @param length Length of the payload.
   * @return std::optional<std::string> The extracted host, if found.
   */
  static std::optional<std::string> extract(const uint8_t *payload,
                                            size_t length);

  /**
   * @brief Check if the payload looks like an HTTP request.
   * 
   * @param payload Pointer to the start of the TCP payload.
   * @param length Length of the payload.
   * @return true if it is an HTTP request, false otherwise.
   */
  static bool isHTTPRequest(const uint8_t *payload, size_t length);
};

/**
 * @brief DNSExtractor class.
 * 
 * Extracts queried domain names from DNS requests.
 */
class DNSExtractor {
public:
  /**
   * @brief Extract queried domain from DNS request.
   * 
   * @param payload Pointer to the start of the UDP payload.
   * @param length Length of the payload.
   * @return std::optional<std::string> The extracted domain, if found.
   */
  static std::optional<std::string> extractQuery(const uint8_t *payload,
                                                 size_t length);

  /**
   * @brief Check if this is a DNS query.
   * 
   * @param payload Pointer to the start of the UDP payload.
   * @param length Length of the payload.
   * @return true if it is a DNS query, false otherwise.
   */
  static bool isDNSQuery(const uint8_t *payload, size_t length);
};

} // namespace DPI

#endif // SNI_EXTRACTOR_H
