#include <stdint.h>

// Accumulate signed bucket offsets for a stream of varying 32-bit coordinates.
uint64_t bucket32(uint32_t count, uint32_t state) {
  uint64_t sum = 0;
  for (uint32_t i = 0; i < count; ++i) {
    state = state * UINT32_C(1664525) + UINT32_C(1013904223);
    sum += (int32_t)state % 1024;
  }
  return sum;
}

// The new signed coordinate depends on the previous 64-bit remainder.
uint64_t bucket64(uint32_t count, uint64_t state) {
  for (uint32_t i = 0; i < count; ++i) {
    state =
        state * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
    state = (int64_t)state % -INT64_C(1099511627776);
  }
  return state;
}

// Non-power-of-two control, with the same recurrence as bucket32.
uint64_t bucket32_other(uint32_t count, uint32_t state) {
  uint64_t sum = 0;
  for (uint32_t i = 0; i < count; ++i) {
    state = state * UINT32_C(1664525) + UINT32_C(1013904223);
    sum += (int32_t)state % 1009;
  }
  return sum;
}
