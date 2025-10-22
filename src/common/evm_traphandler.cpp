// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "common/evm_traphandler.h"
#include "entrypoint/entrypoint.h"
#include "runtime/evm_instance.h"
#include "utils/backtrace.h"
#include "utils/logging.h"
#include <memory>

namespace zen::common {

namespace evm_traphandler {

#ifdef ZEN_ENABLE_CPU_EXCEPTION
void EVMCallThreadState::setJITTraces() {
  void *FrameAddr = TrapFrameAddr;
  void *StartAddr = StartFrame.FrameAddr;
  if (Inst) {
    return;
  }
  if (!FrameAddr || !StartAddr) {
    return;
  }
  uint32_t IgnoredDepth = getTrapState().NumIgnoredFrames;
  ZEN_ASSERT(Inst);
  void *JITCode = Inst->getModule()->getJITCode();
  void *JITCodeEnd =
      static_cast<uint8_t *>(JITCode) + Inst->getModule()->getJITCodeSize();
  Traces = utils::createBacktraceUntil(FrameAddr, PC, StartAddr, IgnoredDepth,
                                       reinterpret_cast<void *>(callNative),
                                       reinterpret_cast<void *>(callNative_end),
                                       JITCode, JITCodeEnd);
}

bool initEVMPlatformTrapHandler() {
  static struct sigaction PrevSigill;
  static struct sigaction PrevSigfpe;
  static struct sigaction PrevSigsegv;
  static struct sigaction PrevSigbus;

  static auto GetPrevSigAction = [](int SigNum) {
    switch (SigNum) {
    case SIGILL:
      return &PrevSigill;
    case SIGFPE:
      return &PrevSigfpe;
    case SIGSEGV:
      return &PrevSigsegv;
    case SIGBUS:
      return &PrevSigbus;
    default: {
      ZEN_LOG_ERROR("unknown signal: %d\n", SigNum);
      abort();
    }
    }
  };

  static auto TrapHandler = [](int SigNum, siginfo_t *SigInfo, void *Ctx) {
    ucontext_t *UCtx = (ucontext_t *)Ctx;
    void *FaultingAddress = SigInfo->si_addr;

    // on dawin read uctx.__ss.__rbp
#ifdef ZEN_BUILD_TARGET_X86_64
#ifdef ZEN_BUILD_PLATFORM_DARWIN
    // rbx is gas register in singlepass x86-64
    uint64_t GasRegisterValue = (uint64_t)((UCtx->uc_mcontext)->__ss.__rbx);

    void *FrameAddr = (void *)((UCtx->uc_mcontext)->__ss.__rbp);
    void *RIP = (void *)((UCtx->uc_mcontext)->__ss.__rip);
#else
    // linux
    // rbx is gas register in singlepass x86-64
    uint64_t GasRegisterValue = (uint64_t)((UCtx->uc_mcontext).gregs[REG_RBX]);

    void *FrameAddr = (void *)((UCtx->uc_mcontext).gregs[REG_RBP]);
    void *RIP = (void *)((UCtx->uc_mcontext).gregs[REG_RIP]);
#endif
#else
    // aarch64
#ifdef ZEN_BUILD_PLATFORM_DARWIN
    // x22 is gas register in singlepass arm
    uint64_t GasRegisterValue = (uint64_t)((UCtx->uc_mcontext)->__ss.__x[22]);
    void *FrameAddr = (void *)((UCtx->uc_mcontext)->__ss.__fp);
    void *RIP = (void *)((UCtx->uc_mcontext)->__ss.__pc);
#else
    // linux aarch64
    // x22 is gas register in singlepass arm
    uint64_t GasRegisterValue = (uint64_t)((UCtx->uc_mcontext).regs[22]);
    void *FrameAddr = (void *)((UCtx->uc_mcontext).regs[29]);
    void *RIP = (void *)((UCtx->uc_mcontext).pc);
#endif // ZEN_BUILD_PLATFORM_DARWIN
#endif
    auto PrevSigAction = GetPrevSigAction(SigNum);
    auto CurrentTLS = EVMCallThreadState::current();
    if (!CurrentTLS || !CurrentTLS->handling()) {
      // This signal is not for any compiled wasm code we expect, so we
      // need to forward the signal to the next handler. If there is no
      // next handler (SIG_IGN or SIG_DFL), then it's time to crash. To do
      // this, we set the signal back to its original disposition and
      // return. This will cause the faulting op to be re-executed which
      // will crash in the normal way. If there is a next handler, call
      // it. It will either crash synchronously, fix up the instruction
      // so that execution can continue and return, or trigger a crash by
      // returning the signal to it's original disposition and returning.
      if ((PrevSigAction->sa_flags & SA_SIGINFO) != 0) {
        PrevSigAction->sa_sigaction(SigNum, SigInfo, Ctx);
      } else if ((void (*)(int))PrevSigAction->sa_sigaction == SIG_DFL ||
                 ((void (*)(int))PrevSigAction->sa_sigaction == SIG_IGN)) {
        // resume prev sigact
        sigaction(SigNum, PrevSigAction, nullptr);
      } else {
        ((void (*)(int))PrevSigAction->sa_sigaction)(SigNum);
      }
      return;
    }

    if (CurrentTLS->getTrapState().FrameAddr) {
      // when trap frame addr set before, maybe the trap caller function
      // not use rbp eg. setExceptionOnJit when gcc no-frame-pointer call
      // ud2
      FrameAddr = CurrentTLS->getTrapState().FrameAddr;
    }
    CurrentTLS->setGasRegisterValue(GasRegisterValue);
    // capture the rbp register for backtrace here
    CurrentTLS->setTrapFrameAddr(FrameAddr, RIP, FaultingAddress, 0);
    // capture traces until outside tls.start_frame
    CurrentTLS->setJITTraces();

    CurrentTLS->jmpToMarked(SigNum);
  };

  auto RegisterFunc = [](struct sigaction *Slot, int Signal) {
    struct sigaction Handler;
    memset(&Handler, 0x0, sizeof(struct sigaction));
#ifdef ZEN_ENABLE_VIRTUAL_STACK
    Handler.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
#else
    Handler.sa_flags = SA_SIGINFO | SA_NODEFER;
#endif // ZEN_ENABLE_VIRTUAL_STACK
    Handler.sa_sigaction = TrapHandler;
    sigemptyset(&Handler.sa_mask);
    if (sigaction(Signal, &Handler, Slot) != 0) {
      ZEN_LOG_ERROR("unable to install signal handler: %d\n", Signal);
      abort();
      return;
    }
  };

  // unreachable use ud2 to raise SIGILL
  RegisterFunc(&PrevSigill, SIGILL);
  // x86 throw SIGFPE when /0
#ifdef ZEN_BUILD_TARGET_X86_64
  RegisterFunc(&PrevSigfpe, SIGFPE);
#endif // ZEN_BUILD_TARGET_X86_64

  RegisterFunc(&PrevSigsegv, SIGSEGV);
  // SIGBUS happen when memory address not aligned
  RegisterFunc(&PrevSigbus, SIGBUS);

  return true;
}

#endif // ZEN_ENABLE_CPU_EXCEPTION

} // namespace evm_traphandler
} // namespace zen::common
