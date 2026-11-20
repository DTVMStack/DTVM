#include <stdint.h>

uint64_t mix_wide24(uint64_t state, uint64_t k0, uint64_t k1, uint64_t k2,
                    uint64_t k3, uint64_t k4, uint64_t k5, uint64_t k6,
                    uint64_t k7, uint64_t k8, uint64_t k9, uint64_t k10,
                    uint64_t k11, uint64_t k12, uint64_t k13, uint64_t k14,
                    uint64_t k15, uint64_t k16, uint64_t k17, uint64_t k18,
                    uint64_t k19, uint64_t k20, uint64_t k21, uint64_t k22,
                    uint64_t k23) {
  state = (state * UINT64_C(16777619)) ^ k0;
  state = (state * UINT64_C(16777619)) ^ k1;
  state = (state * UINT64_C(16777619)) ^ k2;
  state = (state * UINT64_C(16777619)) ^ k3;
  state = (state * UINT64_C(16777619)) ^ k4;
  state = (state * UINT64_C(16777619)) ^ k5;
  state = (state * UINT64_C(16777619)) ^ k6;
  state = (state * UINT64_C(16777619)) ^ k7;
  state = (state * UINT64_C(16777619)) ^ k8;
  state = (state * UINT64_C(16777619)) ^ k9;
  state = (state * UINT64_C(16777619)) ^ k10;
  state = (state * UINT64_C(16777619)) ^ k11;
  state = (state * UINT64_C(16777619)) ^ k12;
  state = (state * UINT64_C(16777619)) ^ k13;
  state = (state * UINT64_C(16777619)) ^ k14;
  state = (state * UINT64_C(16777619)) ^ k15;
  state = (state * UINT64_C(16777619)) ^ k16;
  state = (state * UINT64_C(16777619)) ^ k17;
  state = (state * UINT64_C(16777619)) ^ k18;
  state = (state * UINT64_C(16777619)) ^ k19;
  state = (state * UINT64_C(16777619)) ^ k20;
  state = (state * UINT64_C(16777619)) ^ k21;
  state = (state * UINT64_C(16777619)) ^ k22;
  state = (state * UINT64_C(16777619)) ^ k23;
  return state;
}

uint64_t mix_small32(uint64_t state, uint64_t k0, uint64_t k1, uint64_t k2,
                     uint64_t k3, uint64_t k4, uint64_t k5, uint64_t k6,
                     uint64_t k7, uint64_t k8, uint64_t k9, uint64_t k10,
                     uint64_t k11, uint64_t k12, uint64_t k13, uint64_t k14,
                     uint64_t k15, uint64_t k16, uint64_t k17, uint64_t k18,
                     uint64_t k19, uint64_t k20, uint64_t k21, uint64_t k22,
                     uint64_t k23, uint64_t k24, uint64_t k25, uint64_t k26,
                     uint64_t k27, uint64_t k28, uint64_t k29, uint64_t k30,
                     uint64_t k31) {
  state = (state * UINT64_C(16777619)) ^ k0;
  state = (state * UINT64_C(16777619)) ^ k1;
  state = (state * UINT64_C(16777619)) ^ k2;
  state = (state * UINT64_C(16777619)) ^ k3;
  state = (state * UINT64_C(16777619)) ^ k4;
  state = (state * UINT64_C(16777619)) ^ k5;
  state = (state * UINT64_C(16777619)) ^ k6;
  state = (state * UINT64_C(16777619)) ^ k7;
  state = (state * UINT64_C(16777619)) ^ k8;
  state = (state * UINT64_C(16777619)) ^ k9;
  state = (state * UINT64_C(16777619)) ^ k10;
  state = (state * UINT64_C(16777619)) ^ k11;
  state = (state * UINT64_C(16777619)) ^ k12;
  state = (state * UINT64_C(16777619)) ^ k13;
  state = (state * UINT64_C(16777619)) ^ k14;
  state = (state * UINT64_C(16777619)) ^ k15;
  state = (state * UINT64_C(16777619)) ^ k16;
  state = (state * UINT64_C(16777619)) ^ k17;
  state = (state * UINT64_C(16777619)) ^ k18;
  state = (state * UINT64_C(16777619)) ^ k19;
  state = (state * UINT64_C(16777619)) ^ k20;
  state = (state * UINT64_C(16777619)) ^ k21;
  state = (state * UINT64_C(16777619)) ^ k22;
  state = (state * UINT64_C(16777619)) ^ k23;
  state = (state * UINT64_C(16777619)) ^ k24;
  state = (state * UINT64_C(16777619)) ^ k25;
  state = (state * UINT64_C(16777619)) ^ k26;
  state = (state * UINT64_C(16777619)) ^ k27;
  state = (state * UINT64_C(16777619)) ^ k28;
  state = (state * UINT64_C(16777619)) ^ k29;
  state = (state * UINT64_C(16777619)) ^ k30;
  state = (state * UINT64_C(16777619)) ^ k31;
  return state;
}
