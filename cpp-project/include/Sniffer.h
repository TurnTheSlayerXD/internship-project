#ifndef SNIFFER_H
#define SNIFFER_H

#include "Record.h"
#include "SnifferParams.h"
#include <cassert>
#include <cstring>
#include <unordered_map>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <ctime>

#include <filesystem>

namespace snif {
class SnifferException : std::exception {

  std::string reason_;

public:
  SnifferException(std::string &&reason) : reason_{reason + "\n"} {}

  const char *what() const noexcept override { return reason_.c_str(); }
};

template <typename T> struct Finite {
  T cb;
  Finite(T cb) : cb{cb} {}
  ~Finite() { cb(); }
};

class Sniffer {
  pcap_t *device_;
  std::unordered_map<RecordKey, RecordSupply, RecordHash> dict_;
  SnifferParams params_;
  static constexpr const char *csvheader = "ip_src,ip_dst,port_src,port_dst,"
                                           "n_packets,n_bytes\n";

public:
  Sniffer(const SnifferParams &params);

  Sniffer(const Sniffer &other) = delete;
  Sniffer(Sniffer &&other) noexcept;
  Sniffer &operator=(const Sniffer &other) = delete;

  ~Sniffer() noexcept;

  void process();
  void write_to_stdout();

  void write_to_csv(const char *out_path);

private:
  static void handler_without_timeout(u_char *userData,
                                      const struct pcap_pkthdr *pkthdr,
                                      const u_char *packet) {
    auto dict =
        (std::unordered_map<snif::RecordKey, snif::RecordSupply, RecordHash>
             *)(userData);
    base_handler(dict, pkthdr, packet);
  }
  static void handler_with_timeout(u_char *userData,
                                   const struct pcap_pkthdr *pkthdr,
                                   const u_char *packet) {

    auto [dict, fin_time, device] =
        *(std::tuple<std::unordered_map<snif::RecordKey, snif::RecordSupply,
                                        RecordHash> *,
                     std::time_t *, pcap_t *> *)(userData);

    std::time_t cur_time = std::time(nullptr);

    if (cur_time >= *fin_time) {
      pcap_breakloop(device);
    }
    base_handler(dict, pkthdr, packet);
  }

  static void base_handler(
      std::unordered_map<snif::RecordKey, snif::RecordSupply, RecordHash> *dict,
      const struct pcap_pkthdr *pkthdr, const u_char *packet) {

    auto add_to_dict = [&dict](const PacketRecord &record) {
      if (!dict->contains(record.key)) {
        dict->insert({record.key, RecordSupply{1, record.n_bytes}});
      } else {
        auto &ref = dict->at(record.key);
        ref.n_bytes += record.n_bytes;
        ++ref.n_packets;
      }
    };

    const ether_header *ethernetHeader = (struct ether_header *)packet;

    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
      PacketRecord record;

      const ip *ip_header = (ip *)(packet + sizeof(ether_header));
      record.key.ip_src = ip_header->ip_src.s_addr;
      record.key.ip_dst = ip_header->ip_dst.s_addr;

      switch (ip_header->ip_p) {
      case IPPROTO_TCP: {
        const struct tcphdr *tcp_header =
            (struct tcphdr *)(packet + sizeof(ether_header) + sizeof(ip));
        record.key.port_src = ntohs(tcp_header->source);
        record.key.port_dst = ntohs(tcp_header->dest);

        record.n_bytes =
            pkthdr->len - (sizeof(ether_header) + sizeof(ip) + sizeof(tcphdr));
        add_to_dict(record);

        break;
      }
      case IPPROTO_UDP: {
        const struct udphdr *udp_header =
            (struct udphdr *)(packet + sizeof(struct ether_header) +
                              sizeof(struct ip));
        record.key.port_src = ntohs(udp_header->source);
        record.key.port_dst = ntohs(udp_header->dest);
        record.n_bytes =
            pkthdr->len - (sizeof(ether_header) + sizeof(ip) + sizeof(udphdr));

        add_to_dict(record);

        break;
      }
      default:
        std::cout << "Unkown transport protocol\n";
        break;
      }
    }
  }
};
} // namespace snif
#endif
