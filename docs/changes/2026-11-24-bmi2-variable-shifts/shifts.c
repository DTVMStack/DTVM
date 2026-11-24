#include <stdint.h>

#define SHIFT_KERNEL(Name, Unsigned, Signed, Count)                            \
  uint64_t Name(uint32_t count, uint32_t state) {                              \
    Unsigned a = state;                                                        \
    Unsigned b = (Unsigned)UINT64_C(0x8123456781234567);                       \
    Unsigned c = (Unsigned)UINT64_C(0xfedcba98fedcba98);                       \
    for (uint32_t i = 0; i < count; ++i) {                                     \
      state = state * UINT32_C(1664525) + UINT32_C(1013904223);                \
      unsigned n = (Count);                                                    \
      a = (a << n) + b;                                                        \
      b = (b >> n) ^ c;                                                        \
      c = (Unsigned)((Signed)c >> (n ^ 7)) + a;                                \
    }                                                                          \
    return a ^ b ^ c;                                                          \
  }

SHIFT_KERNEL(shift32, uint32_t, int32_t, state & 31)
SHIFT_KERNEL(shift64, uint64_t, int64_t, state & 63)
SHIFT_KERNEL(immediate64, uint64_t, int64_t, 7)
