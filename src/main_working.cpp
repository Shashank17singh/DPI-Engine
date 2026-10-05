// Working DPI Engine - Simplified but functional
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "packet_parser.h"
#include "pcap_reader.h"
#include "sni_extractor.h"
#include "types.h"

using namespace std;

using namespace PacketAnalyzer;
using namespace DPI;

struct Flow {
  FiveTuple tuple;
  AppType app_type = AppType::UNKNOWN;
  string sni;
  uint64_t packets = 0;
  uint64_t bytes = 0;
  bool blocked = false;
};

class BlockingRules {
public:
  unordered_set<uint32_t> blocked_ips;
  unordered_set<AppType> blocked_apps;
  vector<string> blocked_domains; // Simple substring match

  void blockIP(const string &ip) {
    uint32_t addr = DPI::Utils::parseIP(ip);
    blocked_ips.insert(addr);
    cout << "[Rules] Blocked IP: " << ip << "\n";
  }

  void blockApp(const string &app) {
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
      if (appTypeToString(static_cast<AppType>(i)) == app) {
        blocked_apps.insert(static_cast<AppType>(i));
        cout << "[Rules] Blocked app: " << app << "\n";
        return;
      }
    }
    cerr << "[Rules] Unknown app: " << app << "\n";
  }

  void blockDomain(const string &domain) {
    blocked_domains.push_back(domain);
    cout << "[Rules] Blocked domain: " << domain << "\n";
  }

  bool isBlocked(uint32_t src_ip, AppType app, const string &sni) const {
    if (blocked_ips.count(src_ip))
      return true;
    if (blocked_apps.count(app))
      return true;
    for (const auto &dom : blocked_domains) {
      if (sni.find(dom) != string::npos)
        return true;
    }
    return false;
  }

};

void printUsage(const char *prog) {
  cout
      << R"(
DPI Engine - Deep Packet Inspection System
==========================================

Usage: )"
      << prog << R"( <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block traffic from source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)

Example:
  )" << prog
      << R"( capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
)";
}

int main(int argc, char *argv[]) {
  if (argc < 3) {
    printUsage(argv[0]);
    return 1;
  }

  string input_file = argv[1];
  string output_file = argv[2];

  BlockingRules rules;

  for (int i = 3; i < argc; i++) {
    string arg = argv[i];
    if (arg == "--block-ip" && i + 1 < argc) {
      rules.blockIP(argv[++i]);
    } else if (arg == "--block-app" && i + 1 < argc) {
      rules.blockApp(argv[++i]);
    } else if (arg == "--block-domain" && i + 1 < argc) {
      rules.blockDomain(argv[++i]);
    }
  }

  cout << "\n";
  cout
      << "╔══════════════════════════════════════════════════════════════╗\n";
  cout
      << "║                    DPI ENGINE v1.0                            ║\n";
  cout
      << "╚══════════════════════════════════════════════════════════════╝\n\n";

  PcapReader reader;
  if (!reader.open(input_file)) {
    return 1;
  }

  ofstream output(output_file, ios::binary);
  if (!output.is_open()) {
    cerr << "Error: Cannot open output file\n";
    return 1;
  }

  const auto &header = reader.getGlobalHeader();
  output.write(reinterpret_cast<const char *>(&header), sizeof(header));

  unordered_map<FiveTuple, Flow, FiveTupleHash> flows;

  uint64_t total_packets = 0;
  uint64_t forwarded = 0;
  uint64_t dropped = 0;
  unordered_map<AppType, uint64_t> app_stats;

  RawPacket raw;
  ParsedPacket parsed;

  cout << "[DPI] Processing packets...\n";

  while (reader.readNextPacket(raw)) {
    total_packets++;

    if (!PacketParser::parse(raw, parsed))
      continue;
    if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp))
      continue;

    FiveTuple tuple;
    tuple.src_ip = DPI::Utils::parseIP(parsed.src_ip);
    tuple.dst_ip = DPI::Utils::parseIP(parsed.dest_ip);
    tuple.src_port = parsed.src_port;
    tuple.dst_port = parsed.dest_port;
    tuple.protocol = parsed.protocol;

    Flow &flow = flows[tuple];
    if (flow.packets == 0) {
      flow.tuple = tuple;
    }
    flow.packets++;
    flow.bytes += raw.data.size();

    // Try SNI extraction - even for flows already marked as generic HTTPS
    if ((flow.app_type == AppType::UNKNOWN ||
         flow.app_type == AppType::HTTPS) &&
        flow.sni.empty() && parsed.has_tcp && parsed.dest_port == 443) {

      size_t payload_offset = 14;
      uint8_t ip_ihl = raw.data[14] & 0x0F;
      payload_offset += ip_ihl * 4;

      if (payload_offset + 12 < raw.data.size()) {
        uint8_t tcp_offset = (raw.data[payload_offset + 12] >> 4) & 0x0F;
        payload_offset += tcp_offset * 4;

        if (payload_offset < raw.data.size()) {
          size_t payload_len = raw.data.size() - payload_offset;
          if (payload_len > 5) { // Minimum TLS record header
            string sni_val;
            bool has_sni = SNIExtractor::extract(raw.data.data() + payload_offset, payload_len, sni_val);
            if (has_sni) {
              flow.sni = sni_val;
              flow.app_type = sniToAppType(sni_val);
            }
          }
        }
      }
    }

    if ((flow.app_type == AppType::UNKNOWN || flow.app_type == AppType::HTTP) &&
        flow.sni.empty() && parsed.has_tcp && parsed.dest_port == 80) {

      size_t payload_offset = 14;
      uint8_t ip_ihl = raw.data[14] & 0x0F;
      payload_offset += ip_ihl * 4;

      if (payload_offset + 12 < raw.data.size()) {
        uint8_t tcp_offset = (raw.data[payload_offset + 12] >> 4) & 0x0F;
        payload_offset += tcp_offset * 4;

        if (payload_offset < raw.data.size()) {
          size_t payload_len = raw.data.size() - payload_offset;
          string sni_val;
          bool has_sni = HTTPHostExtractor::extract(raw.data.data() + payload_offset, payload_len, sni_val);
          if (has_sni) {
            flow.sni = sni_val;
            flow.app_type = sniToAppType(sni_val);
          }
        }
      }
    }

    if (flow.app_type == AppType::UNKNOWN &&
        (parsed.dest_port == 53 || parsed.src_port == 53)) {
      flow.app_type = AppType::DNS;
    }

    if (flow.app_type == AppType::UNKNOWN) {
      if (parsed.dest_port == 443)
        flow.app_type = AppType::HTTPS;
      else if (parsed.dest_port == 80)
        flow.app_type = AppType::HTTP;
    }

    if (!flow.blocked) {
      flow.blocked = rules.isBlocked(tuple.src_ip, flow.app_type, flow.sni);
      if (flow.blocked) {
        cout << "[BLOCKED] " << parsed.src_ip << " -> " << parsed.dest_ip
                  << " (" << appTypeToString(flow.app_type);
        if (!flow.sni.empty())
          cout << ": " << flow.sni;
        cout << ")\n";
      }
    }

    app_stats[flow.app_type]++;

    if (flow.blocked) {
      dropped++;
    } else {
      forwarded++;
      PcapPacketHeader pkt_hdr;
      pkt_hdr.ts_sec = raw.header.ts_sec;
      pkt_hdr.ts_usec = raw.header.ts_usec;
      pkt_hdr.incl_len = raw.data.size();
      pkt_hdr.orig_len = raw.data.size();
      output.write(reinterpret_cast<const char *>(&pkt_hdr), sizeof(pkt_hdr));
      output.write(reinterpret_cast<const char *>(raw.data.data()),
                   raw.data.size());
    }
  }

  reader.close();
  output.close();

  cout << "\n";
  cout
      << "╔══════════════════════════════════════════════════════════════╗\n";
  cout
      << "║                      PROCESSING REPORT                       ║\n";
  cout
      << "╠══════════════════════════════════════════════════════════════╣\n";
  cout << "║ Total Packets:      " << setw(10) << total_packets
            << "                             ║\n";
  cout << "║ Forwarded:          " << setw(10) << forwarded
            << "                             ║\n";
  cout << "║ Dropped:            " << setw(10) << dropped
            << "                             ║\n";
  cout << "║ Active Flows:       " << setw(10) << flows.size()
            << "                             ║\n";
  cout
      << "╠══════════════════════════════════════════════════════════════╣\n";
  cout
      << "║                    APPLICATION BREAKDOWN                     ║\n";
  cout
      << "╠══════════════════════════════════════════════════════════════╣\n";

  vector<pair<AppType, uint64_t>> sorted_apps(app_stats.begin(),
                                                        app_stats.end());
  sort(sorted_apps.begin(), sorted_apps.end(),
            [](const auto &a, const auto &b) { return a.second > b.second; });

  for (const auto& kv : sorted_apps) {
    const auto& app = kv.first;
    const auto& count = kv.second;
    double pct = 100.0 * count / total_packets;
    int bar_len = static_cast<int>(pct / 5);
    string bar(bar_len, '#');

    cout << "║ " << setw(15) << left << appTypeToString(app)
              << setw(8) << right << count << " " << setw(5)
              << fixed << setprecision(1) << pct << "% "
              << setw(20) << left << bar << "  ║\n";
  }

  cout
      << "╚══════════════════════════════════════════════════════════════╝\n";

  cout << "\n[Detected Applications/Domains]\n";
  unordered_map<string, AppType> unique_snis;
  for (const auto& kv : flows) {
    const auto& tuple = kv.first;
    const auto& flow = kv.second;
    if (!flow.sni.empty()) {
      unique_snis[flow.sni] = flow.app_type;
    }
  }
  for (const auto& kv : unique_snis) {
    const auto& sni = kv.first;
    const auto& app = kv.second;
    cout << "  - " << sni << " -> " << appTypeToString(app) << "\n";
  }

  cout << "\nOutput written to: " << output_file << "\n";

  return 0;
}
