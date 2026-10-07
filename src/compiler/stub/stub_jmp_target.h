// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef COMPILER_STUB_STUB_JMP_TARGET_H
#define COMPILER_STUB_STUB_JMP_TARGET_H

#include "common/defines.h"
#include <cstdint>
#include <cstring>

namespace COMPILER {
namespace stub_jmp {

/// Initial `jmp rel32` displacement written by `compileFunctionToStub`:
/// jump to the next instruction (the compile-on-request trampoline).
inline constexpr int32_t kTrampolineRel32 = 0;

/// The stub `jmp` is 5 bytes (`0xe9` + rel32). rel32 is stored at Stub+1.
inline int32_t computeRel32(const uint8_t *CurStubCodePtr,
                            const uint8_t *TargetPtr) {
  int64_t CallRelOffset = TargetPtr - CurStubCodePtr - 5;
  ZEN_ASSERT(CallRelOffset <= UINT32_MAX);
  return static_cast<int32_t>(CallRelOffset);
}

inline int32_t loadRel32(const uint8_t *CurStubCodePtr) {
  int32_t Rel32 = 0;
  std::memcpy(&Rel32, CurStubCodePtr + 1, sizeof(Rel32));
  return Rel32;
}

/// Unconditional tear-free publish of the stub `jmp` target (x86_64 `xchg`).
/// Background GreedyRA uses this to upgrade trampoline or FastRA.
inline void updateTarget(uint8_t *CurStubCodePtr, uint8_t *TargetPtr) {
  int32_t CallRelOffsetI32 = computeRel32(CurStubCodePtr, TargetPtr);

  /// Atomic write of the 4-byte offset in `jmp` instruction is required.
  /// `__atomic_store_n` is optimized to `mov` and `mfence` in gcc 9, which does
  /// not ensure atomicity. Hence, we use inline assembly for guaranteed
  /// atomicity. `xchg` is tear-free but does not enforce publish monotonicity;
  /// FastRA must use tryUpdateTargetIfTrampoline instead.

  /// \note x86_64 only
  asm volatile(
      "xchgl %0, 1(%1)" // +1 because the jmp instruction's first byte is opcode
      :
      : "r"(CallRelOffsetI32), "r"(CurStubCodePtr)
      : "memory");
}

/// CAS-publish TargetPtr only if the stub still jumps to the trampoline
/// (`rel32 == 0`). Returns true iff this thread installed TargetPtr.
///
/// Foreground FastRA must use this so a concurrent GreedyRA `xchg` cannot be
/// downgraded: if the stub is already FastRA or GreedyRA, the CAS fails and
/// the existing target is left unchanged.
inline bool tryUpdateTargetIfTrampoline(uint8_t *CurStubCodePtr,
                                        uint8_t *TargetPtr) {
  int32_t Desired = computeRel32(CurStubCodePtr, TargetPtr);
  int32_t Expected = kTrampolineRel32;
  uint8_t Success = 0;

  /// \note x86_64 only. The rel32 at Stub+1 is unaligned; locked `cmpxchg`
  /// matches the existing unaligned `xchg` publish path.
  asm volatile("lock cmpxchgl %2, 1(%3)\n\t"
               "sete %0"
               : "=q"(Success), "+a"(Expected)
               : "r"(Desired), "r"(CurStubCodePtr)
               : "memory", "cc");
  return Success != 0;
}

} // namespace stub_jmp
} // namespace COMPILER

#endif // COMPILER_STUB_STUB_JMP_TARGET_H
