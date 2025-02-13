#include <iostream>

#include "Sniffer.h"

#include <cassert>

int main(int argc, char **argv) {

  constexpr const char *help_info =
      "On default listening first found interface\n"
      "-h --help : get help\n"
      "-o --out : file to write sniffing result to, default: ./data_X.csv"
      "-i --interface : interface to listen to\n"
      "-f --file : pcap file to read data from\n"
      "-c --count : amount of packets to snif, default: endless\n"
      "-t --timeout : amount of time to snif, default: 10, for endless <=0 \n";
  snif::SnifferParams params;

  const char *out_path = "data_0.csv";

  for (int i = 1; i < argc; i += 2) {
    if (std::strcmp("-h", argv[i]) == 0 ||
        std::strcmp("--help", argv[i]) == 0) {
      fprintf(stdout, help_info);
      return 0;

    } else if (std::strcmp("-o", argv[i]) == 0 ||
               std::strcmp("--out", argv[i]) == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Not enough arguments for --out\n");
        return -1;
      }
      out_path = argv[i + 1];
    } else if (std::strcmp("-i", argv[i]) == 0 ||
               std::strcmp("--interface", argv[i]) == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Not enough arguments for --interface\n");
        return -1;
      }
      params.device_arg = argv[i + 1];
      params.device_type = snif::InputDevice::Interface;
    } else if (std::strcmp("-f", argv[i]) == 0 ||
               std::strcmp("--file", argv[i]) == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Not enough arguments for --file\n");
        return -1;
      }
      params.device_arg = argv[i + 1];
      params.device_type = snif::InputDevice::File;

    } else if (std::strcmp("-c", argv[i]) == 0 ||
               std::strcmp("--count", argv[i]) == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Not enough arguments for --count\n");
        return -1;
      }
      int num;
      try {
        num = std::stoi(argv[i + 1]);
      } catch (const std::exception &e) {
        fprintf(stderr, "Could not interpret --count argument as integer\n");
        return -1;
      }
      params.n_packs = num;
    }

    else if (std::strcmp("-t", argv[i]) == 0 ||
             std::strcmp("--timeout", argv[i]) == 0) {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "Not enough arguments for --time\n");
        return -1;
      }
      std::time_t num;
      try {
        num = std::stol(argv[i + 1]);
      } catch (const std::exception &e) {
        std::fprintf(stderr,
                     "Could not interpret --time argument as integer: %s\n",
                     e.what());
        return -1;
      }
      params.timeout = num;
    }
  }

  try {
    snif::Sniffer sniffer(params);

    try {
      sniffer.process();
    } catch (const snif::SnifferException &e) {
      fprintf(stderr, "Sniffer exception: %s", e.what());
    } catch (const std::exception &e) {
      fprintf(stderr, "Std exception: %s", e.what());
    }
    sniffer.write_to_csv(out_path);
  } catch (const snif::SnifferException &e) {
    fprintf(stderr, "Sniffer exception: %s", e.what());
  } catch (const std::exception &e) {
    fprintf(stderr, "Std exception: %s", e.what());
  }
}