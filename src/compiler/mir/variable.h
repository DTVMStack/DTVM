// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_COMPILER_MIR_VARIABLE_H
#define ZEN_COMPILER_MIR_VARIABLE_H

#include "compiler/common/common_defs.h"

namespace COMPILER {

class MType;

class Variable : public NonCopyable {
public:
  Variable(uint32_t Idx, MType *Ty) : VarIdx(Idx), Type(Ty) {}

  MType *getType() const { return Type; }

  VariableIdx getVarIdx() const { return VarIdx; }

  void setPhysicalRegister(unsigned PhysReg) { PhysicalReg = PhysReg; }
  unsigned getPhysicalRegister() const { return PhysicalReg; }
  bool hasPhysicalRegister() const { return PhysicalReg != 0; }

private:
  VariableIdx VarIdx;
  MType *Type = nullptr;
  unsigned PhysicalReg = 0;
};

} // namespace COMPILER

#endif // ZEN_COMPILER_MIR_VARIABLE_H
