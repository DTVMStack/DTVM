// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "compiler/mir/constant.h"
#include "compiler/mir/type.h"
#include "llvm/ADT/APFloat.h"
#include "llvm/ADT/APInt.h"

namespace COMPILER {

using namespace llvm;

class CompileContext;

class MConstantInt : public MConstant {
public:
  static MConstantInt *get(CompileContext &Ctx, MType &Ty, APInt V);
  static MConstantInt *get(CompileContext &Ctx, MType &Ty, uint64_t V);
  static bool classof(const MConstant *Constant) {
    return Constant->getType().isInteger();
  }

  APInt getValue() const { return Val; }

private:
  APInt Val;

  MConstantInt(MType &Ty, const APInt &V) : MConstant(Ty), Val(V) {}
};

class MConstantFloat : public MConstant {
public:
  static MConstantFloat *get(CompileContext &Ctx, MType &Ty, APFloat V);
  static MConstantFloat *get(CompileContext &Ctx, MType &Ty, float V);
  static MConstantFloat *get(CompileContext &Ctx, MType &Ty, double V);
  static bool classof(const MConstant *Constant) {
    return Constant->getType().isFloat();
  }

  const APFloat &getValue() const { return Val; }

private:
  APFloat Val;

  MConstantFloat(MType &Ty, const APFloat &V) : MConstant(Ty), Val(V) {}
};

} // namespace COMPILER
