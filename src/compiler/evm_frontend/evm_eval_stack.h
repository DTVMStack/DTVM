// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "common/type.h"
#include "compiler/context.h"
#include "compiler/mir/constants.h"
#include "compiler/mir/function.h"
#include "compiler/mir/instructions.h"
#include "compiler/mir/opcode.h"
#include "compiler/mir/pointer.h"
#include "evmc/evmc.h"
#include "intx/intx.hpp"

namespace COMPILER {

template <class T> class EVMEvalStack {
public:
  void push(const T &Item) { Stack.emplace_back(Item); }

  T pop() {
    if (Stack.empty()) {
      throw getErrorWithPhase(ErrorCode::EVMStackUnderflow,
                              ErrorPhase::Compilation,
                              ErrorSubphase::MIREmission);
    }
    T Item = Stack.back();
    Stack.pop_back();
    return Item;
  }

  T &peek(size_t Index = 0) {
    if (Index >= Stack.size()) {
      throw getErrorWithPhase(ErrorCode::EVMStackUnderflow,
                              ErrorPhase::Compilation,
                              ErrorSubphase::MIREmission);
    }
    return Stack[Stack.size() - 1 - Index];
  }

  size_t size() const { return Stack.size(); }
  bool empty() const { return Stack.empty(); }

private:
  std::vector<T> Stack;
};

} // namespace COMPILER
