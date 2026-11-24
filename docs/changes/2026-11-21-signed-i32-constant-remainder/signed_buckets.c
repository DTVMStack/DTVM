#include <stdint.h>

#define DEFINE_BUCKET(name, divisor)                                         \
  uint64_t name(uint32_t count, uint32_t state) {                              \
    uint64_t sum = 0;                                                         \
    for (uint32_t i = 0; i < count; ++i) {                                    \
      state = state * UINT32_C(1664525) + UINT32_C(1013904223);                \
      sum += (int32_t)state % (divisor);                                      \
    }                                                                        \
    return sum;                                                              \
  }

DEFINE_BUCKET(bucket3, 3)
DEFINE_BUCKET(bucket7, 7)
DEFINE_BUCKET(bucket1009, -1009)
DEFINE_BUCKET(bucket1024, 1024)
