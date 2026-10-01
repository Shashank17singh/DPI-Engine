#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

namespace PacketAnalyzer {

/**
 * @brief PCAP Global Header structure.
 * 
 * Represents the 24-byte global header at the beginning of a .pcap file.
 */
struct PcapGlobalHeader {
  uint32_t magic_number;  // 0xa1b2c3d4 (or swapped for big-endian)
  uint16_t version_major; // Usually 2
  uint16_t version_minor; // Usually 4
  int32_t thiszone;       // GMT offset (usually 0)
  uint32_t sigfigs;       // Accuracy of timestamps (usually 0)
  uint32_t snaplen;       // Max length of captured packets
  uint32_t network;       // Data link type (1 = Ethernet)
};

/**
 * @brief PCAP Packet Header structure.
 * 
 * Represents the 16-byte header prepended to each packet in a .pcap file.
 */
struct PcapPacketHeader {
  uint32_t ts_sec;   // Timestamp seconds
  uint32_t ts_usec;  // Timestamp microseconds
  uint32_t incl_len; // Number of bytes saved in file
  uint32_t orig_len; // Actual length of packet
};

/**
 * @brief Raw Packet structure.
 * 
 * Represents a single captured packet with its header and raw data.
 */
struct RawPacket {
  PcapPacketHeader header;
  std::vector<uint8_t> data; // The actual packet bytes
};

/**
 * @brief PcapReader class.
 * 
 * Handles reading packets from a .pcap file.
 */
class PcapReader {
public:
  PcapReader() = default;
  ~PcapReader();

  /**
   * @brief Open a pcap file for reading.
   * 
   * @param filename Path to the .pcap file.
   * @return true if opened successfully, false otherwise.
   */
  bool open(const std::string &filename);

  /**
   * @brief Close the currently open file.
   */
  void close();

  /**
   * @brief Read the next packet from the file.
   * 
   * @param packet Structure to hold the read packet.
   * @return true if a packet was read, false if EOF or error.
   */
  bool readNextPacket(RawPacket &packet);

  /**
   * @brief Get the global header info.
   * 
   * @return The PCAP global header.
   */
  const PcapGlobalHeader &getGlobalHeader() const { return global_header_; }

  // Check if file is open
  bool isOpen() const { return file_.is_open(); }

  // Check if we need to swap byte order
  bool needsByteSwap() const { return needs_byte_swap_; }

private:
  std::ifstream file_;
  PcapGlobalHeader global_header_;
  bool needs_byte_swap_ = false;

  // Helper to swap bytes if needed
  uint16_t maybeSwap16(uint16_t value);
  uint32_t maybeSwap32(uint32_t value);
};

} // namespace PacketAnalyzer

#endif // PCAP_READER_H
