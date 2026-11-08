// Copyright (C) 2026 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once

namespace COMPILER {

// Keep explicit controls, host support and allocation decisions in one place.
struct ScalarAVXPolicy {
  static constexpr bool enabled(bool Forced, bool AutoEnabled, bool HostAVX,
                                bool Greedy, bool SelectedLoopGreedy) {
    return HostAVX && Greedy && (Forced || (AutoEnabled && SelectedLoopGreedy));
  }
};

} // namespace COMPILER
