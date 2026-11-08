// Copyright (C) 2026 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once

namespace COMPILER {

// Keep opt-in, host support and allocation mode decisions in one place.
struct ScalarAVXPolicy {
  static constexpr bool enabled(bool Requested, bool HostAVX, bool Greedy) {
    return Requested && HostAVX && Greedy;
  }
};

} // namespace COMPILER
