#include "types.h"
#include <algorithm>
#include <cctype>
#include <sstream>

using namespace std;

namespace DPI {

namespace Utils {

uint32_t parseIP(const string &ip) {
  uint32_t result = 0;
  int octet = 0, shift = 0;
  for (char c : ip) {
    if (c == '.') {
      result |= (octet << shift);
      shift += 8;
      octet = 0;
    } else if (c >= '0' && c <= '9') {
      octet = octet * 10 + (c - '0');
    }
  }
  return result | (octet << shift);
}

string formatIP(uint32_t ip) {
  ostringstream s;
  s << ((ip >> 0) & 0xFF) << "." << ((ip >> 8) & 0xFF) << "."
    << ((ip >> 16) & 0xFF) << "." << ((ip >> 24) & 0xFF);
  return s.str();
}

} // namespace Utils

string FiveTuple::toString() const {
  ostringstream ss;
  ss << Utils::formatIP(src_ip) << ":" << src_port << " -> "
     << Utils::formatIP(dst_ip) << ":" << dst_port << " ("
     << (protocol == 6 ? "TCP" : (protocol == 17 ? "UDP" : "?")) << ")";

  return ss.str();
}

string appTypeToString(AppType type) {
  switch (type) {
  case AppType::UNKNOWN:
    return "Unknown";
  case AppType::HTTP:
    return "HTTP";
  case AppType::HTTPS:
    return "HTTPS";
  case AppType::DNS:
    return "DNS";
  case AppType::TLS:
    return "TLS";
  case AppType::QUIC:
    return "QUIC";
  case AppType::GOOGLE:
    return "Google";
  case AppType::FACEBOOK:
    return "Facebook";
  case AppType::YOUTUBE:
    return "YouTube";
  case AppType::TWITTER:
    return "Twitter/X";
  case AppType::INSTAGRAM:
    return "Instagram";
  case AppType::NETFLIX:
    return "Netflix";
  case AppType::AMAZON:
    return "Amazon";
  case AppType::MICROSOFT:
    return "Microsoft";
  case AppType::APPLE:
    return "Apple";
  case AppType::WHATSAPP:
    return "WhatsApp";
  case AppType::TELEGRAM:
    return "Telegram";
  case AppType::TIKTOK:
    return "TikTok";
  case AppType::SPOTIFY:
    return "Spotify";
  case AppType::ZOOM:
    return "Zoom";
  case AppType::DISCORD:
    return "Discord";
  case AppType::GITHUB:
    return "GitHub";
  case AppType::CLOUDFLARE:
    return "Cloudflare";
  default:
    return "Unknown";
  }
}

// True only if `host` IS `suffix`, or ends with `suffix` on a label
// boundary (preceded by '.'). Plain substring search is unsafe for short
// domain suffixes like "x.com" or "t.co" -- e.g. "netflix.com" contains
// "x.com" as a raw substring even though it has nothing to do with x.com.
static bool hasDomainSuffix(const string &host,
                            const string &suffix) {
  if (host.size() < suffix.size())
    return false;
  size_t start = host.size() - suffix.size();
  if (host.compare(start, suffix.size(), suffix) != 0)
    return false;
  return start == 0 || host[start - 1] == '.';
}

// Map SNI/domain to application type
AppType sniToAppType(const string &sni) {
  if (sni.empty())
    return AppType::UNKNOWN;

  string lower_sni = sni;
  transform(lower_sni.begin(), lower_sni.end(), lower_sni.begin(),
                 [](unsigned char c) { return tolower(c); });

  if (lower_sni.find("google") != string::npos ||
      lower_sni.find("gstatic") != string::npos ||
      lower_sni.find("googleapis") != string::npos ||
      lower_sni.find("ggpht") != string::npos ||
      lower_sni.find("gvt1") != string::npos) {
    return AppType::GOOGLE;
  }

  if (lower_sni.find("youtube") != string::npos ||
      lower_sni.find("ytimg") != string::npos ||
      lower_sni.find("youtu.be") != string::npos ||
      lower_sni.find("yt3.ggpht") != string::npos) {
    return AppType::YOUTUBE;
  }

  if (lower_sni.find("facebook") != string::npos ||
      lower_sni.find("fbcdn") != string::npos ||
      hasDomainSuffix(lower_sni, "fb.com") ||
      lower_sni.find("fbsbx") != string::npos ||
      hasDomainSuffix(lower_sni, "meta.com")) {
    return AppType::FACEBOOK;
  }

  if (lower_sni.find("instagram") != string::npos ||
      lower_sni.find("cdninstagram") != string::npos) {
    return AppType::INSTAGRAM;
  }

  if (lower_sni.find("whatsapp") != string::npos ||
      hasDomainSuffix(lower_sni, "wa.me")) {
    return AppType::WHATSAPP;
  }

  if (lower_sni.find("twitter") != string::npos ||
      lower_sni.find("twimg") != string::npos ||
      hasDomainSuffix(lower_sni, "x.com") ||
      hasDomainSuffix(lower_sni, "t.co")) {
    return AppType::TWITTER;
  }

  if (lower_sni.find("netflix") != string::npos ||
      lower_sni.find("nflxvideo") != string::npos ||
      lower_sni.find("nflximg") != string::npos) {
    return AppType::NETFLIX;
  }

  if (lower_sni.find("amazon") != string::npos ||
      lower_sni.find("amazonaws") != string::npos ||
      lower_sni.find("cloudfront") != string::npos ||
      hasDomainSuffix(lower_sni, "aws")) {
    return AppType::AMAZON;
  }

  if (lower_sni.find("microsoft") != string::npos ||
      hasDomainSuffix(lower_sni, "msn.com") ||
      lower_sni.find("office") != string::npos ||
      lower_sni.find("azure") != string::npos ||
      hasDomainSuffix(lower_sni, "live.com") ||
      lower_sni.find("outlook") != string::npos ||
      lower_sni.find("bing") != string::npos) {
    return AppType::MICROSOFT;
  }

  if (lower_sni.find("apple") != string::npos ||
      lower_sni.find("icloud") != string::npos ||
      lower_sni.find("mzstatic") != string::npos ||
      lower_sni.find("itunes") != string::npos) {
    return AppType::APPLE;
  }

  if (lower_sni.find("telegram") != string::npos ||
      hasDomainSuffix(lower_sni, "t.me")) {
    return AppType::TELEGRAM;
  }

  if (lower_sni.find("tiktok") != string::npos ||
      lower_sni.find("tiktokcdn") != string::npos ||
      lower_sni.find("musical.ly") != string::npos ||
      lower_sni.find("bytedance") != string::npos) {
    return AppType::TIKTOK;
  }

  if (lower_sni.find("spotify") != string::npos ||
      hasDomainSuffix(lower_sni, "scdn.co")) {
    return AppType::SPOTIFY;
  }

  if (lower_sni.find("zoom") != string::npos) {
    return AppType::ZOOM;
  }

  if (lower_sni.find("discord") != string::npos ||
      lower_sni.find("discordapp") != string::npos) {
    return AppType::DISCORD;
  }

  if (lower_sni.find("github") != string::npos ||
      lower_sni.find("githubusercontent") != string::npos) {
    return AppType::GITHUB;
  }

  if (lower_sni.find("cloudflare") != string::npos ||
      lower_sni.find("cf-") != string::npos) {
    return AppType::CLOUDFLARE;
  }

  return AppType::HTTPS;
}

} // namespace DPI
