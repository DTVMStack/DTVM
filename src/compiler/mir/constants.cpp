// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "compiler/mir/constants.h"
#include "compiler/context.h"
#include <cstdint>

using namespace COMPILER;

MConstantInt *MConstantInt::get(CompileContext &Ctx, MType &Ty, APInt V) {
  // get an existing value or the insertion position
  MConstantInt *&Slot = Ctx.IntConstants[V];
  if (!Slot) {
    // Get the corresponding integer type for the bit width of the value.
    Slot = reinterpret_cast<MConstantInt *>(Ctx.ThreadMemPool.allocate(
        sizeof(MConstantInt), alignof(MConstantInt)));
    new (Slot) MConstantInt(Ty, V);
  }
  return Slot;
}

MConstantInt *MConstantInt::get(CompileContext &Ctx, MType &Ty, uint64_t V) {
  return MConstantInt::get(Ctx, Ty, APInt(Ty.getBitWidth(), V, Ty.isSigned()));
}

MConstantFloat *MConstantFloat::get(CompileContext &Ctx, MType &Ty, APFloat V) {
  // get an existing value or the insertion position
  MConstantFloat *&Slot = Ctx.FPConstants[V];
  if (!Slot) {
    // Get the corresponding integer type for the bit width of the value.
    Slot = reinterpret_cast<MConstantFloat *>(Ctx.ThreadMemPool.allocate(
        sizeof(MConstantFloat), alignof(MConstantFloat)));
    new (Slot) MConstantFloat(Ty, V);
  }
  return Slot;
}

MConstantFloat *MConstantFloat::get(CompileContext &Ctx, MType &Ty, float V) {
  return MConstantFloat::get(Ctx, Ty, APFloat(V));
}

MConstantFloat *MConstantFloat::get(CompileContext &Ctx, MType &Ty, double V) {
  return MConstantFloat::get(Ctx, Ty, APFloat(V));
}

MConstantInt *MConstantInt::getU256(CompileContext &Ctx,
                                    const std::string &HexStr) {
  std::string cleanHex = HexStr;
  if (cleanHex.size() >= 2 && cleanHex.substr(0, 2) == "0x") {
    cleanHex = cleanHex.substr(2);
  }

  APInt value(256, cleanHex, 16);
  return MConstantInt::get(Ctx, Ctx.U256Type, value);
}

MConstantInt *MConstantInt::getU256(CompileContext &Ctx, const APInt &V) {
  APInt val256 = V.getBitWidth() == 256 ? V : V.zextOrTrunc(256);
  return MConstantInt::get(Ctx, Ctx.U256Type, val256);
}

MConstantInt *MConstantInt::getU256Zero(CompileContext &Ctx) {
  return MConstantInt::get(Ctx, Ctx.U256Type, APInt(256, 0));
}

MConstantInt *MConstantInt::getU256One(CompileContext &Ctx) {
  return MConstantInt::get(Ctx, Ctx.U256Type, APInt(256, 1));
}

void MConstant::print(llvm::raw_ostream &OS) const {
  if (Type.isInteger()) {
    const MConstantInt *ConstInt = cast<MConstantInt>(this);
    ConstInt->getValue().print(OS, ConstInt->getType().isSigned());
  } else if (Type.isFloat()) {
    const MConstantFloat *ConstFloat = cast<MConstantFloat>(this);
    const APFloat &APF = ConstFloat->getValue();
    SmallVector<char, 16> Buf;
    APF.toString(Buf);
    OS << Buf;
  } else {
    ZEN_UNREACHABLE();
  }
}

#if !defined(NDEBUG) || defined(LLVM_ENABLE_DUMP)
void MConstant::dump() const { print(llvm::dbgs()); }
#endif
