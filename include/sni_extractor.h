#ifndef SNI_EXTRACTOR_H
#define SNI_EXTRACTOR_H

#include <cstdint>
#include <string>
#include <vector>

using namespace std;

namespace DPI {

class SNIExtractor {
public:
  static bool extract(const uint8_t *payload, size_t length, string &out_str);

  static bool isTLSClientHello(const uint8_t *payload, size_t length);

  static vector<pair<uint16_t, string>>
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

class QUICSNIExtractor {
public:
  static bool extract(const uint8_t *payload, size_t length, string &out_str);

  static bool isQUICInitial(const uint8_t *payload, size_t length);
};

class HTTPHostExtractor {
public:
  static bool extract(const uint8_t *payload, size_t length, string &out_str);

  static bool isHTTPRequest(const uint8_t *payload, size_t length);
};

class DNSExtractor {
public:
  static bool extractQuery(const uint8_t *payload, size_t length, string &out_str);

  static bool isDNSQuery(const uint8_t *payload, size_t length);
};

} // namespace DPI

#endif // SNI_EXTRACTOR_H
