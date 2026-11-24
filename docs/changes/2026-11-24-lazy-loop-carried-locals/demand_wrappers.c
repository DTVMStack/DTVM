#include <stdint.h>

// Export only the wrappers, so the lazy background queue cannot compile
// the loop kernels ahead of their first call.
#define WRAP_KERNEL(Name)                                                      \
  uint64_t Name(uint32_t count, uint32_t seed);                                \
  __attribute__((export_name(#Name)))                                          \
  uint64_t call_##Name(uint32_t count, uint32_t seed) {                        \
    return Name(count, seed);                                                  \
  }

WRAP_KERNEL(shift32)
WRAP_KERNEL(shift64)
WRAP_KERNEL(immediate64)
