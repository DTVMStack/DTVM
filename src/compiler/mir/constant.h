// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "compiler/mir/type.h"

namespace COMPILER {

class MConstant : public NonCopyable {
public:
  MConstant(const MType &Ty) : Type(Ty){};

  ~MConstant() = default;

  const MType &getType() const { return Type; }

  void print(llvm::raw_ostream &OS) const;

  void dump() const;

private:
  const MType &Type;
};

inline llvm::raw_ostream &operator<<(llvm::raw_ostream &OS,
                                     const MConstant &Constant) {
  Constant.print(OS);
  return OS;
}

inline llvm::raw_ostream &operator<<(llvm::raw_ostream &OS,
                                     const MConstant *Constant) {
  Constant->print(OS);
  return OS;
}

} // namespace COMPILER
