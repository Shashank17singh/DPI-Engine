#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

using namespace std;

namespace PacketAnalyzer {

struct PcapGlobalHeader {
  uint32_t magic_number;  
  uint16_t version_major; 
  uint16_t version_minor; 
  int32_t thiszone;       
  uint32_t sigfigs;       
  uint32_t snaplen;       
  uint32_t network;       
};

struct PcapPacketHeader {
  uint32_t ts_sec;   
  uint32_t ts_usec;  
  uint32_t incl_len; 
  uint32_t orig_len; 
};

struct RawPacket {
  PcapPacketHeader header;
  vector<uint8_t> data; 
};

class PcapReader {
public:
  PcapReader() = default;
  ~PcapReader();

  bool open(const string &filename);

  void close();

  bool readNextPacket(RawPacket &packet);

  const PcapGlobalHeader &getGlobalHeader() const { return global_header_; }

  
  bool isOpen() const { return file_.is_open(); }

  
  bool needsByteSwap() const { return needs_byte_swap_; }

private:
  ifstream file_;
  PcapGlobalHeader global_header_;
  bool needs_byte_swap_ = false;

  
  uint16_t maybeSwap16(uint16_t value);
  uint32_t maybeSwap32(uint32_t value);
};

} 

#endif 
