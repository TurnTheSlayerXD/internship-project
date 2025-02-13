#ifndef RECORD_H
#define RECORD_H

#include "pcap.h"
#include <iostream>

namespace snif {

struct RecordKey {
  uint ip_src = 0;
  uint ip_dst = 0;

  uint16_t port_src = 0;
  uint16_t port_dst = 0;

  RecordKey(uint ip_src = 0, uint ip_dst = 0, uint16_t port_src = 0,
            uint16_t port_dst = 0) noexcept
      : ip_src{ip_src}, ip_dst{ip_dst}, port_src{port_src}, port_dst{port_dst} {
  }
  RecordKey(const RecordKey &o) noexcept = default;
  RecordKey(RecordKey &&o) noexcept = default;

  RecordKey &operator=(const RecordKey &o) noexcept = default;
  RecordKey &operator=(RecordKey &&o) noexcept = default;

  bool operator==(const RecordKey &rhs) const {
    return ip_src == rhs.ip_src && ip_dst == rhs.ip_dst &&
           port_src == rhs.port_src && port_dst == rhs.port_dst;
  }
};

struct PacketRecord {

  RecordKey key;

  size_t n_bytes;

  PacketRecord(const RecordKey &key = {}, size_t n_bytes = 0) noexcept
      : key{key}, n_bytes{n_bytes} {}

  PacketRecord(const PacketRecord &) noexcept = default;
  PacketRecord(PacketRecord &&) noexcept = default;
  PacketRecord &operator=(const PacketRecord &) noexcept = default;
  PacketRecord &operator=(PacketRecord &&) noexcept = default;
};

struct RecordSupply {

  size_t n_packets;
  size_t n_bytes;

  RecordSupply(size_t n_packets = 0, size_t n_bytes = 0) noexcept
      : n_packets{n_packets}, n_bytes{n_bytes} {}
  RecordSupply(const RecordSupply &) noexcept = default;
  RecordSupply(RecordSupply &&) noexcept = default;
  RecordSupply &operator=(const RecordSupply &) noexcept = default;
  RecordSupply &operator=(RecordSupply &&) noexcept = default;
};

// char ip_src[INET_ADDRSTRLEN];
// char ip_dst[INET_ADDRSTRLEN];

// inet_ntop(AF_INET, &k.ip_src, ip_src, INET_ADDRSTRLEN);
// inet_ntop(AF_INET, &k.ip_dst, ip_dst, INET_ADDRSTRLEN);
static std::string to_string(const RecordKey &k, const RecordSupply &s) {
  constexpr int message_len = 200;

  char message[message_len];

  char ip_src[INET_ADDRSTRLEN];
  char ip_dst[INET_ADDRSTRLEN];

  inet_ntop(AF_INET, &k.ip_src, ip_src, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &k.ip_dst, ip_dst, INET_ADDRSTRLEN);

  std::snprintf(message, message_len,
                "%s,%s,%d,%d,"
                "%lu,%lu",
                ip_src, ip_dst, k.port_src, k.port_dst, s.n_packets, s.n_bytes);
  return std::string(message);
}

struct RecordHash {

  size_t operator()(const RecordKey &key) const noexcept {
    return (std::hash<uint>{}(key.ip_src) ^
            (std::hash<uint>{}(key.ip_dst) << 1)) |
           (std::hash<uint16_t>{}(key.port_src) ^
            (std::hash<uint16_t>{}(key.port_dst) << 2));
  }
};
} // namespace snif

#endif