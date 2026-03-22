// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include "compiler/common/common_defs.h"

namespace COMPILER {

class CgFunction;

class CgPhiElimination : public NonCopyable {
public:
  void runOnCgFunction(CgFunction &MF);
};

} // namespace COMPILER
