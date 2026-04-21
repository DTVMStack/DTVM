// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Use CPU exception handling and signal to process wasm trap
 * dont' include in SGX environment
 */

#ifndef ZEN_COMMON_TRAPHANDLER_H
#define ZEN_COMMON_TRAPHANDLER_H

#include "common/defines.h"
#include <memory>
#include <vector>

#ifdef ZEN_ENABLE_CPU_EXCEPTION
#include <csetjmp>
#include <csignal>
#endif // ZEN_ENABLE_CPU_EXCEPTION

namespace zen {

namespace runtime {
class Instance;
} // namespace runtime

namespace common::traphandler {

struct TrapState {
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

// ThreadLocalStorage of trap call
class CallThreadState {

  typedef void (*SigActionHandlerType)(int, siginfo_t *, void *);

public:
  CallThreadState(runtime::Instance *Inst, jmp_buf *Env, void *FrameAddr,
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

  ~CallThreadState() {
    currentThreadStateOrUpdate(Parent, Parent == nullptr);
    stopHandler();
    // because thread local current reset to nullptr when root tls exit
    // so restart parent when child exit is safe
    if (Parent) {
      Parent->restartHandler();
    }
  }

  // thread local current
  static CallThreadState *current() {
    return currentThreadStateOrUpdate(nullptr, false);
  }

  CallThreadState *parent() const { return Parent; }

  jmp_buf *jmpbuf() { return JmpBuf; }

  void setHandler(SigActionHandlerType Handler) { restartHandler(); }

  void stopHandler() { Handling = false; }

  void restartHandler() { Handling = true; }

  void jmpToMarked(int Signum) {
    // Unblock the signal before longjmp, since we no longer use SA_NODEFER.
    // Without this, the signal remains blocked after longjmp and subsequent
    // traps of the same signal type would be silently ignored.
    sigset_t SigSet;
    sigemptyset(&SigSet);
    sigaddset(&SigSet, Signum);
    int UnblockResult = sigprocmask(SIG_UNBLOCK, &SigSet, nullptr);
    ZEN_ASSERT(UnblockResult == 0);
    longjmp(*JmpBuf, Signum);
  }

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

  TrapState getTrapState() const {
    return TrapState{
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
  static CallThreadState *currentThreadStateOrUpdate(CallThreadState *NewValue,
                                                     bool Clear) {
    thread_local CallThreadState *Current = nullptr;
    if (NewValue) {
      Current = NewValue;
    }
    if (Clear) {
      Current = nullptr;
    }
    return Current;
  }

  runtime::Instance *Inst = nullptr;
  FrameCapture StartFrame;
  CallThreadState *Parent = nullptr;
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

// this function shoule be call only in one compile-unit.
// and should be called only once.
bool initPlatformTrapHandler();

// when gcc no-frame-pointer, the rbp of triggerInstanceExceptionOnJIT
// may not used
// so need set it when unwind backtrace after ud2
#define SAVE_HOSTAPI_FRAME_POINTER_TO_TLS                                      \
  void *FrameAddr = __builtin_frame_address(0);                                \
  auto TLS = common::traphandler::CallThreadState::current();                  \
  TLS->setTrapFrameAddr(FrameAddr, nullptr, nullptr, 0);

#endif // ZEN_ENABLE_CPU_EXCEPTION

} // namespace common::traphandler
} // namespace zen

#endif // ZEN_COMMON_TRAPHANDLER_H
