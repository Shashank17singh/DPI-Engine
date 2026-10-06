#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include "pcap_reader.h"
#include <array>
#include <cstdint>
#include <string>

using namespace std;

namespace PacketAnalyzer {

struct EthernetHeader {
  array<uint8_t, 6> dest_mac; 
  array<uint8_t, 6> src_mac;  
  uint16_t ether_type;             
};

struct IPv4Header {
  uint8_t version_ihl;     
  uint8_t tos;             
  uint16_t total_length;   
  uint16_t identification; 
  uint16_t flags_fragment; 
  uint8_t ttl;             
  uint8_t protocol;        
  uint16_t checksum;       
  uint32_t src_ip;         
  uint32_t dest_ip;        
                           
};

struct TCPHeader {
  uint16_t src_port;       
  uint16_t dest_port;      
  uint32_t seq_number;     
  uint32_t ack_number;     
  uint8_t data_offset;     
  uint8_t flags;           
  uint16_t window;         
  uint16_t checksum;       
  uint16_t urgent_pointer; 
};

struct UDPHeader {
  uint16_t src_port;  
  uint16_t dest_port; 
  uint16_t length;    
  uint16_t checksum;  
};

struct ParsedPacket {
  
  uint32_t timestamp_sec;
  uint32_t timestamp_usec;

  
  string src_mac;
  string dest_mac;
  uint16_t ether_type;

  
  bool has_ip = false;
  uint8_t ip_version;
  string src_ip;
  string dest_ip;
  uint8_t protocol; 
  uint8_t ttl;

  
  bool has_tcp = false;
  bool has_udp = false;
  uint16_t src_port;
  uint16_t dest_port;

  
  uint8_t tcp_flags;
  uint32_t seq_number;
  uint32_t ack_number;

  
  size_t payload_length;
  const uint8_t *payload_data = nullptr; 
};

class PacketParser {
public:
  static bool parse(const RawPacket &raw, ParsedPacket &parsed);

  
  static string macToString(const uint8_t *mac);
  static string ipToString(uint32_t ip);
  static string protocolToString(uint8_t protocol);
  static string tcpFlagsToString(uint8_t flags);

private:
  static bool parseEthernet(const uint8_t *data, size_t len,
                            ParsedPacket &parsed, size_t &offset);
  static bool parseIPv4(const uint8_t *data, size_t len, ParsedPacket &parsed,
                        size_t &offset);
  static bool parseTCP(const uint8_t *data, size_t len, ParsedPacket &parsed,
                       size_t &offset);
  static bool parseUDP(const uint8_t *data, size_t len, ParsedPacket &parsed,
                       size_t &offset);
};


namespace TCPFlags {
constexpr uint8_t FIN = 0x01;
constexpr uint8_t SYN = 0x02;
constexpr uint8_t RST = 0x04;
constexpr uint8_t PSH = 0x08;
constexpr uint8_t ACK = 0x10;
constexpr uint8_t URG = 0x20;
} 


namespace Protocol {
constexpr uint8_t ICMP = 1;
constexpr uint8_t TCP = 6;
constexpr uint8_t UDP = 17;
} 


namespace EtherType {
constexpr uint16_t IPv4 = 0x0800;
constexpr uint16_t IPv6 = 0x86DD;
constexpr uint16_t ARP = 0x0806;
} 

} 

#endif 
