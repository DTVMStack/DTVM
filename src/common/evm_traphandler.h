// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_COMMON_EVM_TRAPHANDLER_H
#define ZEN_COMMON_EVM_TRAPHANDLER_H

#include "common/defines.h"
#include <vector>

#ifdef ZEN_ENABLE_CPU_EXCEPTION
#include <csetjmp>
#include <csignal>
#endif // ZEN_ENABLE_CPU_EXCEPTION

namespace zen {

namespace runtime {
class EVMInstance;
} // namespace runtime

namespace common::evm_traphandler {

struct EVMTrapState {
  void *PC = nullptr;
  void *FrameAddr = nullptr;
  void *FaultingAddress = nullptr;
  uint32_t NumIgnoredFrames = 0;
  const std::vector<void *> *Traces = nullptr;
};

#ifdef ZEN_ENABLE_CPU_EXCEPTION

struct FrameCapture {
  void *PC = nullptr;        // rip, maybe empty if not provided
  void *FrameAddr = nullptr; // rbp
};

class EVMCallThreadState {

  typedef void (*SigActionHandlerType)(int, siginfo_t *, void *);

public:
  EVMCallThreadState(runtime::EVMInstance *Inst, jmp_buf *Env, void *FrameAddr,
                     void *PC = nullptr)
      : Inst(Inst) {
    StartFrame = {.PC = PC, .FrameAddr = FrameAddr};
    Parent = currentThreadStateOrUpdate(nullptr, false);
    currentThreadStateOrUpdate(this, false);
    JmpBuf = Env;
    if (Parent) {
      // pause parent tls signal handler action
      Parent->stopHandler();
    }
  }
  ~EVMCallThreadState() {
    currentThreadStateOrUpdate(Parent, Parent == nullptr);
    stopHandler();
    // because thread local current reset to nullptr when root tls exit
    // so restart parent when child exit is safe
    if (Parent) {
      Parent->restartHandler();
    }
  }

  // thread local current
  static EVMCallThreadState *current() {
    return currentThreadStateOrUpdate(nullptr, false);
  }

  EVMCallThreadState *parent() const { return Parent; }

  jmp_buf *jmpbuf() { return JmpBuf; }

  void setHandler(SigActionHandlerType Handler) { restartHandler(); }

  void stopHandler() { Handling = false; }

  void restartHandler() { Handling = true; }

  void jmpToMarked(int Signum) { longjmp(*JmpBuf, Signum); }

  void setTrapFrameAddr(void *Addr, void *PC, void *FaultingAddress,
                        uint32_t NumIgnoredFrames) {
    this->TrapFrameAddr = Addr;
    this->PC = PC;
    this->FaultingAddress = FaultingAddress;
    this->NumIgnoredTrapFrames = NumIgnoredFrames;
  }

  void setGasRegisterValue(uint64_t GasRegisterValue) {
    CurGasRegisterValue = GasRegisterValue;
  }

  uint64_t getGasRegisterValue() const { return CurGasRegisterValue; }

  EVMTrapState getTrapState() const {
    return EVMTrapState{
        .PC = PC,
        .FrameAddr = TrapFrameAddr,
        .FaultingAddress = FaultingAddress,
        .NumIgnoredFrames = NumIgnoredTrapFrames,
        .Traces = &Traces,
    };
  }

  bool handling() const { return Handling; }

  void setJITTraces();

  const std::vector<void *> getTraces() const { return Traces; }

private:
  static EVMCallThreadState *
  currentThreadStateOrUpdate(EVMCallThreadState *NewValue, bool Clear) {
    thread_local EVMCallThreadState *Current = nullptr;
    if (NewValue) {
      Current = NewValue;
    }
    if (Clear) {
      Current = nullptr;
    }
    return Current;
  }

  runtime::EVMInstance *Inst = nullptr;
  FrameCapture StartFrame;
  EVMCallThreadState *Parent = nullptr;
  bool Handling = false;

  jmp_buf *JmpBuf = nullptr; // must be default nullptr
  // the frames count to ignore when dump wasm call stack by trap_frame_addr_
  uint32_t NumIgnoredTrapFrames = 0;
  // the frame address(rbp register) when trap happen
  void *TrapFrameAddr = nullptr;
  void *PC = nullptr;
  // faulting instruction
  void *FaultingAddress = nullptr;
  // saved value from gas register when trap
  uint64_t CurGasRegisterValue = 0;
  std::vector<void *> Traces;
};

// Note: Similar to WASM initPlatformTrapHandler, keep logic consistent
// TODO: Refactor to share common code with WASM version
bool initEVMPlatformTrapHandler();

// when gcc no-frame-pointer, the rbp of triggerInstanceExceptionOnJIT
// may not used
// so need set it when unwind backtrace after ud2
#define SAVE_EVM_HOSTAPI_FRAME_POINTER_TO_TLS                                  \
  void *FrameAddr = __builtin_frame_address(0);                                \
  auto TLS = common::evm_traphandler::EVMCallThreadState::current();           \
  TLS->setTrapFrameAddr(FrameAddr, nullptr, nullptr, 0);

#endif // ZEN_ENABLE_CPU_EXCEPTION

} // namespace common::evm_traphandler
} // namespace zen

#endif // ZEN_COMMON_EVM_TRAPHANDLER_H
