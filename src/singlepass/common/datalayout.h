// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_SINGLEPASS_COMMON_DATALAYOUT_H
#define ZEN_SINGLEPASS_COMMON_DATALAYOUT_H

// ============================================================================
// data_layout.h
//
// map locals and globals to location of base and offset, where base can be
// frame pointer or global pointer
//
// ============================================================================

#include "singlepass/common/definitions.h"
#include <vector>

// ============================================================================
// global layout:
//   each global are aligned according to its type
//   |----------------|
//   | globals        |
//   |----------------|
//   | import globals |
//   |----------------| <- %r14, global_base
//
// stack layout:
//   each local are aligned according to its type
//   | extra params   |
//   |----------------| <- %rbp+16
//   | return address |
//   | saved rbp      |              pushq %rbp
//   |----------------| <- %rbp      movq  %rsp, %rbp
//   | callee-saved   |              subq  $stack_size, %rsp
//   | param-backup   |              ......
//   | rest locals    |              movq %rbp, %rsp
//   | eval-stack     |              retq
//   | output param   |
//   |----------------| <- %rsp
// ============================================================================

// ============================================================================
// DataLayout
//
// layout locals on stack and globals for WASM instance
//
// ============================================================================

namespace zen::singlepass {

template <typename ABI> class DataLayout {
protected:
  class GlobalInfo {
  private:
    WASMType Type;   // WASM type of the global
    bool Mutable;    // is global mutable
    uint32_t Offset; // offset against global_data

  public:
    GlobalInfo(WASMType Type, bool Mutable, uint32_t Offset)
        : Type(Type), Mutable(Mutable), Offset(Offset) {
      ZEN_ASSERT(common::to_underlying(Type) < (1 << 4));
      ZEN_ASSERT(Offset < (1 << 27));
    }

    WASMType getType() const { return Type; }
    bool getMutable() const { return Mutable != 0; }
    int32_t getOffset() const { return Offset; }
  };

protected:
  ABI &Abi;                        // ABI
  std::vector<GlobalInfo> Globals; // all globals in the instance

public:
  DataLayout(ABI &Abi) : Abi(Abi) {}

  const ABI &getABI() const { return Abi; }

  void initModule(JITCompilerContext *Ctx) {
    ZEN_ASSERT(Globals.size() == 0);
    runtime::Module *Mod = Ctx->Mod;
    uint32_t TotalGlobalCount = Mod->getNumTotalGlobals();
    Globals.reserve(TotalGlobalCount);

    for (uint32_t I = 0; I < Mod->getNumImportGlobals(); ++I) {
      const auto &ImportGlobal = *Mod->getImportGlobal(I);
      Globals.push_back(GlobalInfo(ImportGlobal.Type, ImportGlobal.Mutable,
                                   ImportGlobal.Offset));
    }

    for (uint32_t I = 0; I < Mod->getNumInternalGlobals(); ++I) {
      const auto &Global = Mod->getInternalGlobal(I);
      Globals.push_back(GlobalInfo(Global.Type, Global.Mutable, Global.Offset));
    }

    ZEN_ASSERT(Globals.size() == TotalGlobalCount);
  }

  void finalizeModule(JITCompilerContext *Ctx) {
    ZEN_ASSERT(Globals.size() == Ctx->Mod->getNumTotalGlobals());
    Globals.clear();
  }
};

// ============================================================================
// OnePassDataLayout
//
// layout stack, heap and temporary space for one pass jit compiler
//
// ============================================================================

template <typename ABI> class OnePassDataLayout : public DataLayout<ABI> {
public:
  class LocalInfo {
  private:
    WASMType Type;  // WASM type of the local
    uint32_t Reg;   // Register number if local is in register
    int32_t Offset; // offset if local is on stack

  public:
    LocalInfo(WASMType Type, int32_t Offset)
        : Type(Type), Reg(ABI::InvalidParamReg), Offset(Offset) {
      ZEN_ASSERT((Offset >= -(1 << 22)) && Offset < (1 << 22));
    }

    LocalInfo(WASMType Type, uint32_t Reg, int32_t Offset)
        : Type(Type), Reg(Reg), Offset(Offset) {
      ZEN_ASSERT(common::to_underlying(Type) < (1 << 4));
      ZEN_ASSERT(Reg < (1 << 4));
      ZEN_ASSERT((Offset >= -(1 << 22)) && Offset < (1 << 22));
    }

    WASMType getType() const { return Type; }
    uint32_t getReg() const { return Reg; }
    int32_t getOffset() const { return Offset; }
    bool inReg() const { return Reg != ABI::InvalidParamReg; }
    void setClearReg() { Reg = ABI::InvalidParamReg; }
  }; // LocalInfo

protected:
  JITCompilerContext *Ctx;       // JIT compile context containing current WASM
                                 // function been jit'ed
  std::vector<LocalInfo> Locals; // all locals in the function
  uint32_t GpPresSavedArea;      // callee-saved int register backup
  uint32_t FpPresSavedArea;      // callee-saved fp register backup
  int32_t StackUsed;             // total used stack, include above and temp
                                 //   for eval stack
  int32_t StackBudget;           // total stack allocated
  bool ParamInRegister;          // is param still in register

public:
  OnePassDataLayout(ABI &Abi)
      : DataLayout<ABI>(Abi), Ctx(nullptr), GpPresSavedArea(0),
        FpPresSavedArea(0), StackUsed(0), StackBudget(0),
        ParamInRegister(false) {}

public:
  void initFunction(JITCompilerContext *JITCtx) {
    Ctx = JITCtx;
    // save %rbx, %r12, %r13, %r14, %r15
    // TODO: need to define callee-saved register convention
    GpPresSavedArea = 0; // ABI::GpRegWidth * ABI::NumGpPresRegs;
    FpPresSavedArea = 0; // ABI::FpRegWidth * ABI::NumFpPresRegs;
  }

  void finalizeFunction() {
    ZEN_ASSERT(Locals.size() ==
               Ctx->FuncType->NumParams + Ctx->Func->NumLocals);
    Locals.clear();
  }

public:
  uint32_t getNumReturns() const {
    ZEN_ASSERT(Ctx->FuncType != nullptr);
    return Ctx->FuncType->NumReturns;
  }

  WASMType getReturnType(uint32_t Index) {
    ZEN_ASSERT(Index < getNumReturns());
    return static_cast<WASMType>(Ctx->FuncType->getReturnTypes()[Index]);
  }

  uint32_t getIntPresSavedCount() const {
    return GpPresSavedArea / ABI::GpRegWidth;
  }

  uint32_t getStackBudget() const { return StackBudget; }

  LocalInfo getLocalInfo(uint32_t LocalIdx) {
    ZEN_ASSERT(LocalIdx < Locals.size());
    return Locals[LocalIdx];
  }

  void clearLocalInRegister(uint32_t LocalIdx) {
    ZEN_ASSERT(LocalIdx < Locals.size());
    ZEN_ASSERT(Locals[LocalIdx].inReg());
    Locals[LocalIdx].setClearReg();
  }
};

} // namespace zen::singlepass

#endif // ZEN_SINGLEPASS_COMMON_DATALAYOUT_H
