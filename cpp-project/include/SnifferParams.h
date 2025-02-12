#ifndef SNIFFERPARAMS_H

#define SNIFFERPARAMS_H

namespace snif {

enum class InputDevice { File, Interface, Undefined };

struct SnifferParams {
  int n_packs;
  const char *out_path;
  InputDevice device_type;
  char *device_arg;

  SnifferParams()
      : n_packs{100}, out_path{nullptr}, device_type{InputDevice::Undefined},
        device_arg{nullptr} {}
  SnifferParams(const SnifferParams &params) = default;
};
} 

#endif