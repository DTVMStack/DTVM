// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_ACTION_VALUE_STACK_H_
#define ZEN_ACTION_VALUE_STACK_H_

#include "common/defines.h"
#include <cstdint>
#include <stack>

namespace zen::action {

template <typename Operand> class VMEvalStack {
public:
  void push(const Operand &Op) { StackImpl.push(Op); }

  Operand pop() {
    ZEN_ASSERT(!StackImpl.empty());
    Operand Top = StackImpl.top();
    StackImpl.pop();
    return Top;
  }

  Operand getTop() const {
    ZEN_ASSERT(!StackImpl.empty());
    return StackImpl.top();
  }

  uint32_t getSize() const { return StackImpl.size(); }

  bool empty() const { return StackImpl.empty(); }

private:
  std::stack<Operand> StackImpl;
};

} // namespace zen::action

#endif
