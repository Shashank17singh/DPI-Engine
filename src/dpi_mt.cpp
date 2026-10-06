


#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
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

template <typename T> class TSQueue {
public:
  TSQueue(size_t max_size = 10000) : max_size_(max_size), shutdown_(false) {}

  void push(T item) {
    unique_lock<mutex> lock(mutex_);
    not_full_.wait(lock,
                   [this] { return queue_.size() < max_size_ || shutdown_; });
    if (shutdown_)
      return;
    queue_.push(move(item));
    not_empty_.notify_one();
  }

  optional<T> pop(int timeout_ms = 100) {
    unique_lock<mutex> lock(mutex_);
    if (!not_empty_.wait_for(lock, chrono::milliseconds(timeout_ms),
                             [this] { return !queue_.empty() || shutdown_; })) {
      return false;
    }
    if (queue_.empty())
      return false;
    T item = move(queue_.front());
    queue_.pop();
    not_full_.notify_one();
    return item;
  }

  void shutdown() {
    lock_guard<mutex> lock(mutex_);
    shutdown_ = true;
    not_empty_.notify_all();
    not_full_.notify_all();
  }

  size_t size() const {
    lock_guard<mutex> lock(mutex_);
    return queue_.size();
  }

  bool is_shutdown() const { return shutdown_; }

private:
  queue<T> queue_;
  mutable mutex mutex_;
  condition_variable not_empty_;
  condition_variable not_full_;
  size_t max_size_;
  atomic<bool> shutdown_;
};

struct Packet {
  uint32_t id;
  uint32_t ts_sec;
  uint32_t ts_usec;
  FiveTuple tuple;
  vector<uint8_t> data;
  uint8_t tcp_flags;
  size_t payload_offset;
  size_t payload_length;
};

struct FlowEntry {
  FiveTuple tuple;
  AppType app_type = AppType::UNKNOWN;
  string sni;
  uint64_t packets = 0;
  uint64_t bytes = 0;
  bool blocked = false;
  bool classified = false;
};

class Rules {
public:
  void blockIP(const string &ip) {
    lock_guard<mutex> lock(mutex_);
    blocked_ips_.insert(DPI::Utils::parseIP(ip));
    cout << "[Rules] Blocked IP: " << ip << "\n";
  }

  void blockApp(const string &app) {
    lock_guard<mutex> lock(mutex_);
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
      if (appTypeToString(static_cast<AppType>(i)) == app) {
        blocked_apps_.insert(static_cast<AppType>(i));
        cout << "[Rules] Blocked app: " << app << "\n";
        return;
      }
    }
    cerr << "[Rules] Unknown app: " << app << "\n";
  }

  void blockDomain(const string &domain) {
    lock_guard<mutex> lock(mutex_);
    blocked_domains_.push_back(domain);
    cout << "[Rules] Blocked domain: " << domain << "\n";
  }

  // Rules are populated before processing starts, so read access is thread-safe
  bool isBlocked(uint32_t src_ip, AppType app, const string &sni) const {
    if (blocked_ips_.count(src_ip))
      return true;
    if (blocked_apps_.count(app))
      return true;
    for (const auto &dom : blocked_domains_) {
      if (sni.find(dom) != string::npos)
        return true;
    }
    return false;
  }

private:
  mutable mutex mutex_;
  unordered_set<uint32_t> blocked_ips_;
  unordered_set<AppType> blocked_apps_;
  vector<string> blocked_domains_;
};

struct Stats {
  atomic<uint64_t> total_packets{0};
  atomic<uint64_t> total_bytes{0};
  atomic<uint64_t> forwarded{0};
  atomic<uint64_t> dropped{0};
  atomic<uint64_t> tcp_packets{0};
  atomic<uint64_t> udp_packets{0};

  mutex app_mutex;
  unordered_map<AppType, uint64_t> app_counts;
  unordered_map<string, AppType> detected_snis;

  // Merge local thread stats into global stats
  void mergeLocal(const unordered_map<AppType, uint64_t>& local_app_counts, 
                  const unordered_map<string, AppType>& local_snis) {
    lock_guard<mutex> lock(app_mutex);
    for (const auto& kv : local_app_counts) {
      app_counts[kv.first] += kv.second;
    }
    for (const auto& kv : local_snis) {
      detected_snis[kv.first] = kv.second;
    }
  }
};

class FastPath {
public:
  FastPath(int id, Rules *rules, Stats *stats, TSQueue<Packet> *output_queue)
      : id_(id), rules_(rules), stats_(stats), output_queue_(output_queue) {}

  void start() {
    running_ = true;
    thread_ = thread(&FastPath::run, this);
  }

  void stop() {
    running_ = false;
    input_queue_.shutdown();
    if (thread_.joinable())
      thread_.join();
  }

  TSQueue<Packet> &queue() { return input_queue_; }

  uint64_t processed() const { return processed_; }

private:
  int id_;
  Rules *rules_;
  Stats *stats_;
  TSQueue<Packet> *output_queue_;
  TSQueue<Packet> input_queue_;
  unordered_map<FiveTuple, FlowEntry, FiveTupleHash> flows_;
  
  // Local stats to avoid global lock contention
  unordered_map<AppType, uint64_t> local_app_counts_;
  unordered_map<string, AppType> local_snis_;

  atomic<bool> running_{false};
  thread thread_;
  atomic<uint64_t> processed_{0};

  void run() {
    while (running_) {
      auto pkt_opt = input_queue_.pop(100);
      if (!pkt_opt)
        continue;

      processed_++;
      Packet &pkt = *pkt_opt;

      FlowEntry &flow = flows_[pkt.tuple];
      if (flow.packets == 0) {
        flow.tuple = pkt.tuple;
      }
      flow.packets++;
      flow.bytes += pkt.data.size();

      if (!flow.classified) {
        classifyFlow(pkt, flow);
      }

      if (!flow.blocked) {
        flow.blocked =
            rules_->isBlocked(pkt.tuple.src_ip, flow.app_type, flow.sni);
      }

      // Record locally to avoid global mutex contention on every packet
      local_app_counts_[flow.app_type]++;
      if (!flow.sni.empty()) {
        local_snis_[flow.sni] = flow.app_type;
      }

      if (flow.blocked) {
        stats_->dropped++;
      } else {
        stats_->forwarded++;
        output_queue_->push(move(pkt));
      }
    }
    
    // Merge local stats back to global on exit
    stats_->mergeLocal(local_app_counts_, local_snis_);
  }

  void classifyFlow(Packet &pkt, FlowEntry &flow) {
    
    if (pkt.tuple.dst_port == 443 && pkt.payload_length > 5) {
      const uint8_t *payload = pkt.data.data() + pkt.payload_offset;
      string sni_val;
      bool has_sni = SNIExtractor::extract(payload, pkt.payload_length, sni_val);
      if (has_sni) {
        flow.sni = sni_val;
        flow.app_type = sniToAppType(sni_val);
        flow.classified = true;
        return;
      }
    }

    
    if (pkt.tuple.dst_port == 80 && pkt.payload_length > 10) {
      const uint8_t *payload = pkt.data.data() + pkt.payload_offset;
      string sni_val;
      bool has_sni = HTTPHostExtractor::extract(payload, pkt.payload_length, sni_val);
      if (has_sni) {
        flow.sni = sni_val;
        flow.app_type = sniToAppType(sni_val);
        flow.classified = true;
        return;
      }
    }

    
    if (pkt.tuple.dst_port == 53 || pkt.tuple.src_port == 53) {
      flow.app_type = AppType::DNS;
      flow.classified = true;
      return;
    }

    
    if (pkt.tuple.dst_port == 443) {
      flow.app_type = AppType::HTTPS;
    } else if (pkt.tuple.dst_port == 80) {
      flow.app_type = AppType::HTTP;
    }
  }
};

class LoadBalancer {
public:
  LoadBalancer(int id, vector<FastPath *> fps)
      : id_(id), fps_(move(fps)), num_fps_(fps_.size()) {}

  void start() {
    running_ = true;
    thread_ = thread(&LoadBalancer::run, this);
  }

  void stop() {
    running_ = false;
    input_queue_.shutdown();
    if (thread_.joinable())
      thread_.join();
  }

  TSQueue<Packet> &queue() { return input_queue_; }

  uint64_t dispatched() const { return dispatched_; }

private:
  int id_;
  vector<FastPath *> fps_;
  size_t num_fps_;
  TSQueue<Packet> input_queue_;

  atomic<bool> running_{false};
  thread thread_;
  atomic<uint64_t> dispatched_{0};

  void run() {
    while (running_) {
      auto pkt_opt = input_queue_.pop(100);
      if (!pkt_opt)
        continue;

      FiveTupleHash hasher;
      size_t fp_idx = hasher(pkt_opt->tuple) % num_fps_;

      fps_[fp_idx]->queue().push(move(*pkt_opt));
      dispatched_++;
    }
  }
};

class DPIEngine {
public:
  struct Config {
    int num_lbs = 2;
    int fps_per_lb = 2;
  };

  DPIEngine(const Config &cfg) : config_(cfg) {
    int total_fps = cfg.num_lbs * cfg.fps_per_lb;

    cout << "\n";
    cout
        << "╔══════════════════════════════════════════════════════════════╗\n";
    cout << "║              DPI ENGINE v2.0 (Multi-threaded)              "
                 "   ║\n";
    cout
        << "╠══════════════════════════════════════════════════════════════╣\n";
    cout << "║ Load Balancers: " << setw(2) << cfg.num_lbs
              << "    FPs per LB: " << setw(2) << cfg.fps_per_lb
              << "    Total FPs: " << setw(2) << total_fps << "     ║\n";
    cout << "╚════════════════════════════════════════════════════════════"
                 "══╝\n\n";

    for (int i = 0; i < total_fps; i++) {
      fps_.push_back(
          make_unique<FastPath>(i, &rules_, &stats_, &output_queue_));
    }

    for (int lb = 0; lb < cfg.num_lbs; lb++) {
      vector<FastPath *> lb_fps;
      int start = lb * cfg.fps_per_lb;
      for (int i = 0; i < cfg.fps_per_lb; i++) {
        lb_fps.push_back(fps_[start + i].get());
      }
      lbs_.push_back(make_unique<LoadBalancer>(lb, move(lb_fps)));
    }
  }

  void blockIP(const string &ip) { rules_.blockIP(ip); }
  void blockApp(const string &app) { rules_.blockApp(app); }
  void blockDomain(const string &dom) { rules_.blockDomain(dom); }

  bool process(const string &input_file, const string &output_file) {
    PcapReader reader;
    if (!reader.open(input_file))
      return false;

    ofstream output(output_file, ios::binary);
    if (!output.is_open()) {
      cerr << "Cannot open output file\n";
      return false;
    }

    const auto &hdr = reader.getGlobalHeader();
    output.write(reinterpret_cast<const char *>(&hdr), sizeof(hdr));

    for (auto &fp : fps_)
      fp->start();
    for (auto &lb : lbs_)
      lb->start();

    atomic<bool> output_running{true};
    thread output_thread([&]() {
      while (output_running || output_queue_.size() > 0) {
        auto pkt_opt = output_queue_.pop(50);
        if (!pkt_opt)
          continue;

        PcapPacketHeader phdr;
        phdr.ts_sec = pkt_opt->ts_sec;
        phdr.ts_usec = pkt_opt->ts_usec;
        phdr.incl_len = pkt_opt->data.size();
        phdr.orig_len = pkt_opt->data.size();

        output.write(reinterpret_cast<const char *>(&phdr), sizeof(phdr));
        output.write(reinterpret_cast<const char *>(pkt_opt->data.data()),
                     pkt_opt->data.size());
      }
    });

    cout << "[Reader] Processing packets...\n";
    RawPacket raw;
    ParsedPacket parsed;
    uint32_t pkt_id = 0;

    while (reader.readNextPacket(raw)) {
      if (!PacketParser::parse(raw, parsed))
        continue;
      if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp))
        continue;

      Packet pkt;
      pkt.id = pkt_id++;
      pkt.ts_sec = raw.header.ts_sec;
      pkt.ts_usec = raw.header.ts_usec;
      pkt.tcp_flags = parsed.tcp_flags;
      pkt.data = move(raw.data);

      pkt.tuple.src_ip = DPI::Utils::parseIP(parsed.src_ip);
      pkt.tuple.dst_ip = DPI::Utils::parseIP(parsed.dest_ip);
      pkt.tuple.src_port = parsed.src_port;
      pkt.tuple.dst_port = parsed.dest_port;
      pkt.tuple.protocol = parsed.protocol;

      pkt.payload_offset = 14; 
      if (pkt.data.size() > 14) {
        uint8_t ip_ihl = pkt.data[14] & 0x0F;
        pkt.payload_offset += ip_ihl * 4;

        if (parsed.has_tcp && pkt.payload_offset + 12 < pkt.data.size()) {
          uint8_t tcp_off = (pkt.data[pkt.payload_offset + 12] >> 4) & 0x0F;
          pkt.payload_offset += tcp_off * 4;
        } else if (parsed.has_udp) {
          pkt.payload_offset += 8;
        }

        if (pkt.payload_offset < pkt.data.size()) {
          pkt.payload_length = pkt.data.size() - pkt.payload_offset;
        } else {
          pkt.payload_length = 0;
        }
      }

      stats_.total_packets++;
      stats_.total_bytes += pkt.data.size();
      if (parsed.has_tcp)
        stats_.tcp_packets++;
      else if (parsed.has_udp)
        stats_.udp_packets++;

      FiveTupleHash hasher;
      size_t lb_idx = hasher(pkt.tuple) % lbs_.size();
      lbs_[lb_idx]->queue().push(move(pkt));
    }

    cout << "[Reader] Done reading " << pkt_id << " packets\n";
    reader.close();

    this_thread::sleep_for(chrono::milliseconds(500));

    for (auto &lb : lbs_)
      lb->stop();
    for (auto &fp : fps_)
      fp->stop();

    output_running = false;
    output_queue_.shutdown();
    output_thread.join();

    output.close();

    printReport();

    return true;
  }

private:
  Config config_;
  Rules rules_;
  Stats stats_;
  TSQueue<Packet> output_queue_;
  vector<unique_ptr<FastPath>> fps_;
  vector<unique_ptr<LoadBalancer>> lbs_;

  void printReport() {
    cout << "\n";
    cout
        << "╔══════════════════════════════════════════════════════════════╗\n";
    cout << "║                      PROCESSING REPORT                     "
                 "   ║\n";
    cout
        << "╠══════════════════════════════════════════════════════════════╣\n";
    cout << "║ Total Packets:      " << setw(12)
              << stats_.total_packets.load()
              << "                           ║\n";
    cout << "║ Total Bytes:        " << setw(12)
              << stats_.total_bytes.load() << "                           ║\n";
    cout << "║ TCP Packets:        " << setw(12)
              << stats_.tcp_packets.load() << "                           ║\n";
    cout << "║ UDP Packets:        " << setw(12)
              << stats_.udp_packets.load() << "                           ║\n";
    cout
        << "╠══════════════════════════════════════════════════════════════╣\n";
    cout << "║ Forwarded:          " << setw(12)
              << stats_.forwarded.load() << "                           ║\n";
    cout << "║ Dropped:            " << setw(12)
              << stats_.dropped.load() << "                           ║\n";

    cout
        << "╠══════════════════════════════════════════════════════════════╣\n";
    cout << "║ THREAD STATISTICS                                          "
                 "   ║\n";
    for (size_t i = 0; i < lbs_.size(); i++) {
      cout << "║   LB" << i << " dispatched:   " << setw(12)
                << lbs_[i]->dispatched() << "                           ║\n";
    }
    for (size_t i = 0; i < fps_.size(); i++) {
      cout << "║   FP" << i << " processed:    " << setw(12)
                << fps_[i]->processed() << "                           ║\n";
    }

    cout
        << "╠══════════════════════════════════════════════════════════════╣\n";
    cout << "║                   APPLICATION BREAKDOWN                    "
                 "   ║\n";
    cout
        << "╠══════════════════════════════════════════════════════════════╣\n";

    lock_guard<mutex> lock(stats_.app_mutex);

    vector<pair<AppType, uint64_t>> sorted_apps(
        stats_.app_counts.begin(), stats_.app_counts.end());
    sort(sorted_apps.begin(), sorted_apps.end(),
              [](const auto &a, const auto &b) { return a.second > b.second; });

    uint64_t total = stats_.total_packets.load();
    for (const auto& kv : sorted_apps) {
      const auto& app = kv.first;
      const auto& count = kv.second;
      double pct = total > 0 ? (100.0 * count / total) : 0;
      int bar = static_cast<int>(pct / 5);
      string bar_str(bar, '#');

      cout << "║ " << setw(15) << left << appTypeToString(app)
                << setw(8) << right << count << " " << setw(5)
                << fixed << setprecision(1) << pct << "% "
                << setw(20) << left << bar_str << "  ║\n";
    }

    cout
        << "╚══════════════════════════════════════════════════════════════╝\n";

    if (!stats_.detected_snis.empty()) {
      cout << "\n[Detected Domains/SNIs]\n";
      for (const auto& kv : stats_.detected_snis) {
      const auto& sni = kv.first;
      const auto& app = kv.second;
        cout << "  - " << sni << " -> " << appTypeToString(app) << "\n";
      }
    }
  }
};

void printUsage(const char *prog) {
  cout
      << R"(
DPI Engine v2.0 - Multi-threaded Deep Packet Inspection
========================================================

Usage: )"
      << prog << R"( <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)
  --lbs <n>              Number of load balancer threads (default: 2)
  --fps <n>              FP threads per LB (default: 2)

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

  string input = argv[1];
  string output = argv[2];

  DPIEngine::Config cfg;
  vector<string> block_ips, block_apps, block_domains;

  for (int i = 3; i < argc; i++) {
    string arg = argv[i];
    if (arg == "--block-ip" && i + 1 < argc)
      block_ips.push_back(argv[++i]);
    else if (arg == "--block-app" && i + 1 < argc)
      block_apps.push_back(argv[++i]);
    else if (arg == "--block-domain" && i + 1 < argc)
      block_domains.push_back(argv[++i]);
    else if (arg == "--lbs" && i + 1 < argc)
      cfg.num_lbs = stoi(argv[++i]);
    else if (arg == "--fps" && i + 1 < argc)
      cfg.fps_per_lb = stoi(argv[++i]);
  }

  DPIEngine engine(cfg);

  for (const auto &ip : block_ips)
    engine.blockIP(ip);
  for (const auto &app : block_apps)
    engine.blockApp(app);
  for (const auto &dom : block_domains)
    engine.blockDomain(dom);

  if (!engine.process(input, output)) {
    return 1;
  }

  cout << "\nOutput written to: " << output << "\n";
  return 0;
}
