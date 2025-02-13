#include <iostream>

#include "Sniffer.h"

int main(int argc, char **argv) {

  constexpr const char *help_info = "";

  snif::SnifferParams params;

  const char *out_path = nullptr;

  for (int i = 0; i < argc;) {

    if (std::strcmp("-h", argv[i]) == 0 ||
        std::strcmp("--help", argv[i]) == 0) {
      fprintf(stdout, help_info);
      i += 1;
    } else if (std::strcmp("-o", argv[i]) == 0 ||
               std::strcmp("--out", argv[i]) == 0) {
      if (i + 1 == argc) {
        fprintf(stderr, "Not enough arguments for --out\n");
        return -1;
      }
      out_path = argv[i + 1];
    } else if (std::strcmp("-i", argv[i]) == 0 ||
               std::strcmp("--interface", argv[i]) == 0) {
      if (i + 1 == argc) {
        fprintf(stderr, "Not enough arguments for --interface\n");
        return -1;
      }
      params.device_arg = argv[i + 1];
    } else if (std::strcmp("-f", argv[i]) == 0 ||
               std::strcmp("--file", argv[i]) == 0) {
      if (i + 1 == argc) {
        fprintf(stderr, "Not enough arguments for --file\n");
        return -1;
      }
      params.device_arg = argv[i + 1];
    } else if (std::strcmp("-c", argv[i]) == 0 ||
               std::strcmp("--count", argv[i]) == 0) {
      if (i + 1 == argc) {
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
      if (i + 1 == argc) {
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

    try {
      snif::Sniffer sniffer(params);

      if (out_path != nullptr) {
        sniffer.process();
        sniffer.write_to_csv(out_path);
      } else {
        sniffer.write_to_stdout();
      }
    } catch (const snif::SnifferException &e) {
      fprintf(stderr, "Sniffer exception: %s", e.what());
    } catch (const std::exception &e) {
      fprintf(stderr, "Std exception: %s", e.what());
    }
  }
}