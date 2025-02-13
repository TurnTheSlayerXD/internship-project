#ifndef SNIFFERPARAMS_H

#define SNIFFERPARAMS_H

namespace snif {

enum class InputDevice { File, Interface, Undefined };

struct SnifferParams {
  int n_packs;
  InputDevice device_type;
  char *device_arg;
  std::time_t timeout;

  SnifferParams()
      : n_packs{100}, device_type{InputDevice::Undefined},
        device_arg{nullptr}, timeout{1000} {}
  SnifferParams(const SnifferParams &params) noexcept = default;
  SnifferParams(SnifferParams &&params) noexcept = default;
  SnifferParams &operator=(const SnifferParams &params) noexcept = default;
  SnifferParams &operator=(SnifferParams &&) noexcept = default;
  SnifferParams(SnifferParams &&params) noexcept = default;

  ~SnifferParams() noexcept = default;
};
} // namespace snif

#endif