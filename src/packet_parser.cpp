/*
 * packet_parser.cpp
 *
 * Implements wire-speed packet decoding for Ethernet, IPv4, TCP, and UDP headers.
 * Extracts critical L2-L4 metadata required for 5-tuple flow hashing and payload offset calculation.
 */
#include "packet_parser.h"
#include "platform.h"
#include <cstring>
#include <iomanip>
#include <sstream>

using namespace std;


using PortableNet::netToHost16;
using PortableNet::netToHost32;


#define ntohs(x) netToHost16(x)
#define ntohl(x) netToHost32(x)

namespace PacketAnalyzer {

bool PacketParser::parse(const RawPacket &raw, ParsedPacket &parsed) {
  parsed = ParsedPacket();
  parsed.timestamp_sec = raw.header.ts_sec;
  parsed.timestamp_usec = raw.header.ts_usec;

  const uint8_t *data = raw.data.data();
  size_t len = raw.data.size();
  size_t offset = 0;

  if (!parseEthernet(data, len, parsed, offset)) {
    return false;
  }

  if (parsed.ether_type == EtherType::IPv4) {
    if (!parseIPv4(data, len, parsed, offset)) {
      return false;
    }

    if (parsed.protocol == Protocol::TCP) {
      if (!parseTCP(data, len, parsed, offset)) {
        return false;
      }
    } else if (parsed.protocol == Protocol::UDP) {
      if (!parseUDP(data, len, parsed, offset)) {
        return false;
      }
    }
  }

  if (offset < len) {
    parsed.payload_length = len - offset;
    parsed.payload_data = data + offset;
  } else {
    parsed.payload_length = 0;
    parsed.payload_data = nullptr;
  }

  return true;
}

bool PacketParser::parseEthernet(const uint8_t *data, size_t len,
                                 ParsedPacket &parsed, size_t &offset) {
  
  constexpr size_t ETH_HEADER_LEN = 14;

  if (len < ETH_HEADER_LEN) {
    return false; 
  }

  parsed.dest_mac = macToString(data);

  parsed.src_mac = macToString(data + 6);

  parsed.ether_type = ntohs(*reinterpret_cast<const uint16_t *>(data + 12));

  offset = ETH_HEADER_LEN;
  return true;
}

bool PacketParser::parseIPv4(const uint8_t *data, size_t len,
                             ParsedPacket &parsed, size_t &offset) {
  
  constexpr size_t MIN_IP_HEADER_LEN = 20;

  if (len < offset + MIN_IP_HEADER_LEN) {
    return false; 
  }

  const uint8_t *ip_data = data + offset;

  
  uint8_t version_ihl = ip_data[0];
  parsed.ip_version = (version_ihl >> 4) & 0x0F;
  uint8_t ihl = version_ihl & 0x0F; 

  if (parsed.ip_version != 4) {
    return false; 
  }

  size_t ip_header_len = ihl * 4; 
  if (ip_header_len < MIN_IP_HEADER_LEN || len < offset + ip_header_len) {
    return false;
  }

  parsed.ttl = ip_data[8];
  parsed.protocol = ip_data[9];

  uint32_t src_ip;
  memcpy(&src_ip, ip_data + 12, 4);
  parsed.src_ip = ipToString(src_ip);

  uint32_t dest_ip;
  memcpy(&dest_ip, ip_data + 16, 4);
  parsed.dest_ip = ipToString(dest_ip);

  parsed.has_ip = true;
  offset += ip_header_len;

  return true;
}

bool PacketParser::parseTCP(const uint8_t *data, size_t len,
                            ParsedPacket &parsed, size_t &offset) {
  
  constexpr size_t MIN_TCP_HEADER_LEN = 20;

  if (len < offset + MIN_TCP_HEADER_LEN) {
    return false;
  }

  const uint8_t *tcp_data = data + offset;

  parsed.src_port = ntohs(*reinterpret_cast<const uint16_t *>(tcp_data));

  parsed.dest_port = ntohs(*reinterpret_cast<const uint16_t *>(tcp_data + 2));

  parsed.seq_number = ntohl(*reinterpret_cast<const uint32_t *>(tcp_data + 4));

  parsed.ack_number = ntohl(*reinterpret_cast<const uint32_t *>(tcp_data + 8));

  
  uint8_t data_offset = (tcp_data[12] >> 4) & 0x0F;
  size_t tcp_header_len = data_offset * 4;

  parsed.tcp_flags = tcp_data[13];

  if (tcp_header_len < MIN_TCP_HEADER_LEN || len < offset + tcp_header_len) {
    return false;
  }

  parsed.has_tcp = true;
  offset += tcp_header_len;

  return true;
}

bool PacketParser::parseUDP(const uint8_t *data, size_t len,
                            ParsedPacket &parsed, size_t &offset) {
  
  constexpr size_t UDP_HEADER_LEN = 8;

  if (len < offset + UDP_HEADER_LEN) {
    return false;
  }

  const uint8_t *udp_data = data + offset;

  parsed.src_port = ntohs(*reinterpret_cast<const uint16_t *>(udp_data));

  parsed.dest_port = ntohs(*reinterpret_cast<const uint16_t *>(udp_data + 2));

  parsed.has_udp = true;
  offset += UDP_HEADER_LEN;

  return true;
}

string PacketParser::macToString(const uint8_t *mac) {
  ostringstream ss;
  ss << hex << setfill('0');
  for (int i = 0; i < 6; i++) {
    if (i > 0)
      ss << ":";
    ss << setw(2) << static_cast<int>(mac[i]);
  }
  return ss.str();
}

string PacketParser::ipToString(uint32_t ip) {
  
  
  ostringstream ss;
  ss << ((ip >> 0) & 0xFF) << "." << ((ip >> 8) & 0xFF) << "."
     << ((ip >> 16) & 0xFF) << "." << ((ip >> 24) & 0xFF);
  return ss.str();
}

string PacketParser::protocolToString(uint8_t protocol) {
  switch (protocol) {
  case Protocol::ICMP:
    return "ICMP";
  case Protocol::TCP:
    return "TCP";
  case Protocol::UDP:
    return "UDP";
  default:
    return "Unknown(" + to_string(protocol) + ")";
  }
}

string PacketParser::tcpFlagsToString(uint8_t flags) {
  string result;
  if (flags & TCPFlags::SYN)
    result += "SYN ";
  if (flags & TCPFlags::ACK)
    result += "ACK ";
  if (flags & TCPFlags::FIN)
    result += "FIN ";
  if (flags & TCPFlags::RST)
    result += "RST ";
  if (flags & TCPFlags::PSH)
    result += "PSH ";
  if (flags & TCPFlags::URG)
    result += "URG ";
  if (!result.empty())
    result.pop_back(); 
  return result.empty() ? "none" : result;
}

} 
