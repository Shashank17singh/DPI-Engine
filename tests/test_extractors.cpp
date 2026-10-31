// Unit tests for the application-layer extractors. Run with: ctest --output-on-failure
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "sni_extractor.h"

using DPI::HTTPHostExtractor;
using DPI::SNIExtractor;

static int failures = 0;

#define CHECK(condition)                                                        \
    do {                                                                        \
        if (!(condition)) {                                                     \
            std::cout << "FAILED line " << __LINE__ << ": " #condition "\n";     \
            failures++;                                                         \
        }                                                                       \
    } while (0)

static void put16(std::vector<uint8_t> &out, size_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

static void put24(std::vector<uint8_t> &out, size_t value) {
    out.push_back(static_cast<uint8_t>(value >> 16));
    put16(out, value);
}

// Builds a minimal TLS 1.2 ClientHello. An empty host leaves out the SNI extension.
static std::vector<uint8_t> clientHello(const std::string &host) {
    std::vector<uint8_t> extensions;
    if (!host.empty()) {
        put16(extensions, 0x0000);
        put16(extensions, host.size() + 5);
        put16(extensions, host.size() + 3);
        extensions.push_back(0x00);
        put16(extensions, host.size());
        extensions.insert(extensions.end(), host.begin(), host.end());
    }

    std::vector<uint8_t> body = {0x03, 0x03};
    body.insert(body.end(), 32, 0xAB);  // Random.
    body.push_back(0x00);               // Session ID length.
    put16(body, 2);
    body.insert(body.end(), {0x00, 0x2F});  // One cipher suite.
    body.insert(body.end(), {0x01, 0x00});  // One compression method.
    put16(body, extensions.size());
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<uint8_t> handshake = {0x01};
    put24(handshake, body.size());
    handshake.insert(handshake.end(), body.begin(), body.end());

    std::vector<uint8_t> record = {0x16, 0x03, 0x01};
    put16(record, handshake.size());
    record.insert(record.end(), handshake.begin(), handshake.end());
    return record;
}

static std::vector<uint8_t> bytes(const std::string &text) {
    return std::vector<uint8_t>(text.begin(), text.end());
}

static void testSNI() {
    std::vector<uint8_t> hello = clientHello("www.example.com");
    std::string host;

    CHECK(SNIExtractor::isTLSClientHello(hello.data(), hello.size()));
    CHECK(SNIExtractor::extract(hello.data(), hello.size(), host));
    CHECK(host == "www.example.com");
}

static void testClientHelloWithoutSNI() {
    std::vector<uint8_t> hello = clientHello("");
    std::string host;

    CHECK(SNIExtractor::isTLSClientHello(hello.data(), hello.size()));
    CHECK(!SNIExtractor::extract(hello.data(), hello.size(), host));
}

static void testOtherTrafficIsNotClientHello() {
    std::vector<uint8_t> http = bytes("GET / HTTP/1.1\r\n\r\n");
    std::string host;

    CHECK(!SNIExtractor::isTLSClientHello(http.data(), http.size()));
    CHECK(!SNIExtractor::extract(http.data(), http.size(), host));
}

// A truncated capture must never read past the buffer or report a host.
static void testTruncatedPackets() {
    std::vector<uint8_t> hello = clientHello("www.example.com");
    for (size_t length = 0; length < hello.size(); length++) {
        std::string host;
        CHECK(!SNIExtractor::extract(hello.data(), length, host));
    }
}

static void testHTTPHost() {
    std::vector<uint8_t> request = bytes("GET / HTTP/1.1\r\nHost: example.org\r\nAccept: */*\r\n\r\n");
    std::string host;

    CHECK(HTTPHostExtractor::isHTTPRequest(request.data(), request.size()));
    CHECK(HTTPHostExtractor::extract(request.data(), request.size(), host));
    CHECK(host == "example.org");
}

static void testHTTPHostIgnoresPort() {
    std::vector<uint8_t> request = bytes("GET / HTTP/1.1\r\nHost: example.org:8080\r\n\r\n");
    std::string host;

    CHECK(HTTPHostExtractor::extract(request.data(), request.size(), host));
    CHECK(host == "example.org");
}

static void testNonHTTPTraffic() {
    std::vector<uint8_t> payload = bytes("hello there");
    std::string host;

    CHECK(!HTTPHostExtractor::isHTTPRequest(payload.data(), payload.size()));
    CHECK(!HTTPHostExtractor::extract(payload.data(), payload.size(), host));
}

int main() {
    testSNI();
    testClientHelloWithoutSNI();
    testOtherTrafficIsNotClientHello();
    testTruncatedPackets();
    testHTTPHost();
    testHTTPHostIgnoresPort();
    testNonHTTPTraffic();

    if (failures == 0) {
        std::cout << "All extractor tests passed.\n";
    }
    return failures == 0 ? 0 : 1;
}
