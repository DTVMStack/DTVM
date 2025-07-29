
// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_PLATFORM_SGX_TIME_H
#define ZEN_PLATFORM_SGX_TIME_H

#include <time.h>

namespace zen::sgx::chrono {
typedef int TimeT;

struct tp {
  int n = 0;
  static int time_since_epoch() { return 0; }

  tp operator-(const tp &other) const {
    tp result{n - other.n};
    return result;
  }
};

template <typename Rep, typename Period> struct duration {
  duration(tp){};
  static float count() { return 0.0; }
};

struct milliseconds {
  uint64_t count() { return 0; }
};

struct SteadyClock {
  typedef tp time_point;
  int now() { return 0; };
};

struct SystemClock {
  typedef tp time_point;
  static time_point now() { return time_point{}; };
  static time_t to_time_t(time_point) { return 0; }
};

template <typename T> T duration_cast(int v) { return T{}; }
} // namespace zen::sgx::chrono
#endif