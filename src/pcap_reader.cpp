#include "pcap_reader.h"
#include <cstring>
#include <iostream>

using namespace std;

namespace PacketAnalyzer {

// Magic numbers for PCAP files
constexpr uint32_t PCAP_MAGIC_NATIVE = 0xa1b2c3d4;  // Native byte order
constexpr uint32_t PCAP_MAGIC_SWAPPED = 0xd4c3b2a1; // Swapped byte order

PcapReader::~PcapReader() { close(); }

bool PcapReader::open(const string &filename) {
  // Close any previously opened file
  close();

  file_.open(filename, ios::binary);
  if (!file_.is_open()) {
    cerr << "Error: Could not open file: " << filename << endl;
    return false;
  }

  file_.read(reinterpret_cast<char *>(&global_header_),
             sizeof(PcapGlobalHeader));
  if (!file_.good()) {
    cerr << "Error: Could not read PCAP global header" << endl;
    close();
    return false;
  }

  if (global_header_.magic_number == PCAP_MAGIC_NATIVE) {
    needs_byte_swap_ = false;
  } else if (global_header_.magic_number == PCAP_MAGIC_SWAPPED) {
    needs_byte_swap_ = true;
    global_header_.version_major = maybeSwap16(global_header_.version_major);
    global_header_.version_minor = maybeSwap16(global_header_.version_minor);
    global_header_.snaplen = maybeSwap32(global_header_.snaplen);
    global_header_.network = maybeSwap32(global_header_.network);
  } else {
    cerr << "Error: Invalid PCAP magic number: 0x" << hex
              << global_header_.magic_number << dec << endl;
    close();
    return false;
  }

  cout << "Opened PCAP file: " << filename << endl;
  cout << "  Version: " << global_header_.version_major << "."
            << global_header_.version_minor << endl;
  cout << "  Snaplen: " << global_header_.snaplen << " bytes" << endl;
  cout << "  Link type: " << global_header_.network
            << (global_header_.network == 1 ? " (Ethernet)" : "") << endl;

  return true;
}

void PcapReader::close() {
  if (file_.is_open()) {
    file_.close();
  }
  needs_byte_swap_ = false;
}

bool PcapReader::readNextPacket(RawPacket &packet) {
  if (!file_.is_open()) {
    return false;
  }

  file_.read(reinterpret_cast<char *>(&packet.header),
             sizeof(PcapPacketHeader));
  if (!file_.good()) {
    // End of file or error
    return false;
  }

  if (needs_byte_swap_) {
    packet.header.ts_sec = maybeSwap32(packet.header.ts_sec);
    packet.header.ts_usec = maybeSwap32(packet.header.ts_usec);
    packet.header.incl_len = maybeSwap32(packet.header.incl_len);
    packet.header.orig_len = maybeSwap32(packet.header.orig_len);
  }

  // Sanity check on packet length
  if (packet.header.incl_len > global_header_.snaplen ||
      packet.header.incl_len > 65535) {
    cerr << "Error: Invalid packet length: " << packet.header.incl_len
              << endl;
    return false;
  }

  packet.data.resize(packet.header.incl_len);
  file_.read(reinterpret_cast<char *>(packet.data.data()),
             packet.header.incl_len);
  if (!file_.good()) {
    cerr << "Error: Could not read packet data" << endl;
    return false;
  }

  return true;
}

uint16_t PcapReader::maybeSwap16(uint16_t value) {
  if (!needs_byte_swap_)
    return value;
  return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8);
}

uint32_t PcapReader::maybeSwap32(uint32_t value) {
  if (!needs_byte_swap_)
    return value;
  return ((value & 0xFF000000) >> 24) | ((value & 0x00FF0000) >> 8) |
         ((value & 0x0000FF00) << 8) | ((value & 0x000000FF) << 24);
}

} // namespace PacketAnalyzer
