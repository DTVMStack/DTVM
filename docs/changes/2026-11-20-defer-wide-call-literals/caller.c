#include <stdint.h>

extern uint64_t mix_wide24(uint64_t state, uint64_t k0, uint64_t k1,
                           uint64_t k2, uint64_t k3, uint64_t k4, uint64_t k5,
                           uint64_t k6, uint64_t k7, uint64_t k8, uint64_t k9,
                           uint64_t k10, uint64_t k11, uint64_t k12,
                           uint64_t k13, uint64_t k14, uint64_t k15,
                           uint64_t k16, uint64_t k17, uint64_t k18,
                           uint64_t k19, uint64_t k20, uint64_t k21,
                           uint64_t k22, uint64_t k23);

uint64_t run_wide24(uint32_t count, uint64_t state) {
  while (count--) {
    state = mix_wide24(
        state, UINT64_C(81985529216486895), UINT64_C(411569258730616712),
        UINT64_C(741152988244746529), UINT64_C(1070736717758876346),
        UINT64_C(1400320447273006163), UINT64_C(1729904176787135980),
        UINT64_C(2059487906301265797), UINT64_C(2389071635815395614),
        UINT64_C(2718655365329525431), UINT64_C(3048239094843655248),
        UINT64_C(3377822824357785065), UINT64_C(3707406553871914882),
        UINT64_C(4036990283386044699), UINT64_C(4366574012900174516),
        UINT64_C(4696157742414304333), UINT64_C(5025741471928434150),
        UINT64_C(5355325201442563967), UINT64_C(5684908930956693784),
        UINT64_C(6014492660470823601), UINT64_C(6344076389984953418),
        UINT64_C(6673660119499083235), UINT64_C(7003243849013213052),
        UINT64_C(7332827578527342869), UINT64_C(7662411308041472686));
  }
  return state;
}

extern uint64_t
mix_small32(uint64_t state, uint64_t k0, uint64_t k1, uint64_t k2, uint64_t k3,
            uint64_t k4, uint64_t k5, uint64_t k6, uint64_t k7, uint64_t k8,
            uint64_t k9, uint64_t k10, uint64_t k11, uint64_t k12, uint64_t k13,
            uint64_t k14, uint64_t k15, uint64_t k16, uint64_t k17,
            uint64_t k18, uint64_t k19, uint64_t k20, uint64_t k21,
            uint64_t k22, uint64_t k23, uint64_t k24, uint64_t k25,
            uint64_t k26, uint64_t k27, uint64_t k28, uint64_t k29,
            uint64_t k30, uint64_t k31);

uint64_t run_small32(uint32_t count, uint64_t state) {
  while (count--) {
    state = mix_small32(
        state, UINT64_C(123456789), UINT64_C(123540306), UINT64_C(123623823),
        UINT64_C(123707340), UINT64_C(123790857), UINT64_C(123874374),
        UINT64_C(123957891), UINT64_C(124041408), UINT64_C(124124925),
        UINT64_C(124208442), UINT64_C(124291959), UINT64_C(124375476),
        UINT64_C(124458993), UINT64_C(124542510), UINT64_C(124626027),
        UINT64_C(124709544), UINT64_C(124793061), UINT64_C(124876578),
        UINT64_C(124960095), UINT64_C(125043612), UINT64_C(125127129),
        UINT64_C(125210646), UINT64_C(125294163), UINT64_C(125377680),
        UINT64_C(125461197), UINT64_C(125544714), UINT64_C(125628231),
        UINT64_C(125711748), UINT64_C(125795265), UINT64_C(125878782),
        UINT64_C(125962299), UINT64_C(126045816));
  }
  return state;
}
