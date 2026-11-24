#include <stdint.h>

#define DEFINE_KERNEL(name, expression)                                        \
  uint64_t name(uint32_t count, uint32_t state) {                              \
    uint64_t sum = 0;                                                          \
    for (uint32_t i = 0; i < count; ++i) {                                     \
      state = state * UINT32_C(1664525) + UINT32_C(1013904223);                \
      int32_t x = (int32_t)state;                                              \
      sum += (expression);                                                     \
    }                                                                          \
    return sum;                                                                \
  }

DEFINE_KERNEL(div3, x / 3)
DEFINE_KERNEL(div7, x / -7)
DEFINE_KERNEL(div1009, x / 1009)
DEFINE_KERNEL(div1024, x / 1024)
DEFINE_KERNEL(divtime, (int64_t)(x / 60) + x / 3600 + x / 86400)
DEFINE_KERNEL(bucket7, x % 7)
