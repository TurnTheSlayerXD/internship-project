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

snif::Sniffer::~Sniffer() {
  if (device_ != nullptr) {
    pcap_close(device_);
  }
}

void snif::Sniffer::process() {

    pcap_compile("")

}
void snif::Sniffer::write_to_stdout() {}

void snif::Sniffer::write_to_csv() 
