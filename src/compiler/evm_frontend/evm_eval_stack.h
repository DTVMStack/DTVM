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
      throw std::runtime_error("EVM stack underflow");
    }
    T Item = Stack.back();
    Stack.pop_back();
    return Item;
  }

  T &peek(size_t Index = 0) {
    if (Index >= Stack.size()) {
      throw std::runtime_error("EVM stack underflow");
    }
    return Stack[Stack.size() - 1 - Index];
  }

  size_t size() const { return Stack.size(); }
  bool empty() const { return Stack.empty(); }

private:
  std::vector<T> Stack;
};

} // namespace COMPILER
