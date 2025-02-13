#include "Sniffer.h"

snif::Sniffer::Sniffer(const SnifferParams &params) : params_{params} {

  char errbuf[PCAP_ERRBUF_SIZE];

  switch (params_.device_type) {
  case InputDevice::Undefined: {
    pcap_if_t *devs[3];
    if (pcap_findalldevs(devs, errbuf) != 0 || devs[0] == nullptr) {
      throw SnifferException(std::string(errbuf));
    }
    params_.device_arg = devs[0]->name;
    device_ = pcap_open_live(params_.device_arg, BUFSIZ, 1, 1000, errbuf);

    break;
  }
  case InputDevice::Interface: {
    device_ = pcap_open_live(params_.device_arg, BUFSIZ, 1, 1000, errbuf);
    break;
  }
  case InputDevice::File: {
    device_ = pcap_open_offline(params_.device_arg, errbuf);
    break;
  }
  }

  if (!device_) {
    throw SnifferException(std::string(errbuf));
  }
}

snif::Sniffer::Sniffer(Sniffer &&other) noexcept {
  device_ = other.device_;
  other.device_ = nullptr;
  params_ = other.params_;
  dict_ = std::move(other.dict_);
}

snif::Sniffer::~Sniffer() noexcept {
  if (device_ != nullptr) {
    pcap_close(device_);
  }
}

static constexpr int filter_len = 30;
void build_filter_expr(char *const dst) {

  auto tcp = getprotobyname("tcp")->p_proto;
  auto udp = getprotobyname("udp")->p_proto;
  snprintf(dst, filter_len, "ip proto %d and ip proto %d", tcp, udp);
}

void snif::Sniffer::process() {

#ifdef WITH_FILTER
  bpf_program filter;

  char filter_expr[filter_len];
  build_filter_expr(filter_expr);

  if (pcap_compile(device_, &filter, filter_expr, 0, PCAP_NETMASK_UNKNOWN) ==
      -1) {
    throw SnifferException(std::string("Unable to compile filter: ") +
                           std::string(pcap_geterr(device_)));
  }
  if (pcap_setfilter(device_, &filter) == -1) {
    throw SnifferException(std::string("Unable to install filter: ") +
                           std::string(pcap_geterr(device_)));
  }
#endif

  pcap_handler handler;
  u_char *forw_data;
  std::time_t fin_time = std::time(nullptr) + params_.timeout;
  std::tuple<decltype(dict_) *, time_t *, pcap_t *> forw_args;

  if (params_.timeout > 0) {

    handler = handler_with_timeout;
    forw_args = std::make_tuple(&dict_, &fin_time, device_);
    forw_data = (u_char *)&forw_args;
  } else {
    handler = handler_without_timeout;
    forw_data = (u_char *)&dict_;
  }
  int error;

  if ((error = pcap_loop(device_, params_.n_packs, handler, forw_data)) != 0 &&
      error != PCAP_ERROR_BREAK) {
    throw SnifferException(std::string("Error while sniffing: ") +
                           pcap_geterr(device_));
  }
}
void snif::Sniffer::write_to_stdout() {

  std::cout << csvheader;
  for (const auto &[key, value] : dict_) {
    std::cout << "WTF" << snif::to_string(key, value) << "\n";
  }
}

void snif::Sniffer::write_to_csv(const char *out_path) {

  std::FILE *f = nullptr;

  Finite fin{[&f]() {
    if (f != nullptr)
      std::fclose(f);
  }};

  namespace fs = std::filesystem;

  if (fs::is_directory(out_path)) {
    char nm[20];
    std::snprintf(nm, 20, "data_%d.csv", 0);
    fs::path fs_pat{std::string(out_path) + nm};
    for (int i = 1; fs::exists(fs_pat); ++i) {
      std::snprintf(nm, 20, "data_%d.csv", i);
      fs_pat.replace_filename(nm);
      if (i >= 1000) {
        throw SnifferException(std::string("Too many files with same name: ") +
                               fs_pat.c_str());
      }
    }
    out_path = fs_pat.c_str();
  }

  if (!(f = std::fopen(out_path, "w"))) {
    throw SnifferException(std::string("Unable to write to directory: ") +
                           out_path);
  }
  if (std::fwrite(csvheader, std::strlen(csvheader), 1, f) != 1) {
    throw SnifferException(
        std::string("Error occured while writing to file: ") + out_path);
  }

  for (const auto &[key, value] : dict_) {
    const auto str = snif::to_string(key, value) + "\n";
    if (std::fwrite(str.c_str(), str.size(), 1, f) != 1) {
      throw SnifferException(
          std::string("Error occured while writing to file: ") + out_path);
    }
  }
}
