// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include "compiler/common/common_defs.h"
#include <cstdint>

namespace COMPILER {

class CgFunction;

class CgPhiElimination : public NonCopyable {
public:
  struct Statistics {
    uint64_t PhiInstructions = 0;
    uint64_t PhiIncomingEdges = 0;
    uint64_t CandidateEdgeCopies = 0;
    uint64_t IdentityEdgeCopies = 0;
    uint64_t EmittedCopyInstructions = 0;
    uint64_t SplitCriticalEdges = 0;
  };

  Statistics runOnCgFunction(CgFunction &MF);
};

} // namespace COMPILER
