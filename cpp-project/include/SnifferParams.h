#ifndef SNIFFERPARAMS_H

#define SNIFFERPARAMS_H

namespace snif {

#include <iostream>
enum class InputDevice { File, Interface, Undefined };

struct SnifferParams {
  int n_packs;
  InputDevice device_type;
  char *device_arg;
  time_t timeout;
  SnifferParams() noexcept
      : n_packs{-1}, device_type{InputDevice::Undefined},
        device_arg{nullptr}, timeout{0} {}
  SnifferParams(const SnifferParams &params) noexcept = default;
  SnifferParams(SnifferParams &&params) noexcept = default;
  SnifferParams &operator=(const SnifferParams &params) noexcept = default;
  SnifferParams &operator=(SnifferParams &&params) noexcept = default;
};
} // namespace snif

#endif