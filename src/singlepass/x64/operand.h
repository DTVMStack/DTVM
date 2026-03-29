// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_SINGLEPASS_X64_OPERAND_H
#define ZEN_SINGLEPASS_X64_OPERAND_H

// ============================================================================
// x64/operand.h
//
// code generator for x64 one pass jit compiler
//
// ============================================================================

#include "singlepass/common/datalayout.h"
#include "singlepass/common/definitions.h"
#include "singlepass/x64/asm/register.h"

namespace zen::singlepass {

// ============================================================================
// Operator Kind, which can be reg, imm, mem, label
// ============================================================================
enum X64OperandKind {
  OK_None = 0,            // none
  OK_Register = 1,        // register
  OK_IntConst = 2,        // 32bit integer
  OK_BaseOffset = 3,      // memloc for base + offset
  OK_BaseIndexScale1 = 4, // memloc for base + index * 1 + offset
  OK_BaseIndexScale2 = 5, // memloc for base + index * 2 + offset
  OK_BaseIndexScale4 = 6, // memloc for base + index * 4 + offset
  OK_BaseIndexScale8 = 7, // memloc for base + index * 8 + offset
  OK_Label = 8,           // label
  OK_Function = 9,        // function
  OK_Last,
}; // X64OperandKind

class X64InstOperand {
public:
  // tempoorary flag
  enum OperandFlags {
    FLAG_NONE = 0,
    FLAG_TEMP_MEM = 0x40, // register in reg1 is temp
    FLAG_TEMP_REG = 0x80, // whole memory is temp on stack
  };

private:
  uint8_t OpKind = 0;              // Operand kind
  WASMType WType = WASMType::VOID; // WASM value type
  uint8_t Reg1 = 0;                // register 1 number
  uint8_t Reg2 = 0;                // register 2 number
  int32_t Value = 0;               // constant value or offset

public:
  // constructor
  X64InstOperand() : OpKind(OK_None), WType(WASMType::VOID) {}

  X64InstOperand(WASMType Type, X64::RegNum Reg, OperandFlags Flags)
      : WType(Type), Reg1(Reg) {
    ZEN_ASSERT(Flags == FLAG_NONE || Flags == FLAG_TEMP_REG);
    OpKind = Flags | OK_Register;
  }

  X64InstOperand(WASMType Type, int32_t Value)
      : OpKind(OK_IntConst), WType(Type), Value(Value) {
    ZEN_ASSERT(Type == WASMType::I32 || Type == WASMType::I64);
  }

  X64InstOperand(WASMType Type, X64::RegNum Base, uint32_t Offset,
                 OperandFlags Flags)
      : WType(Type), Reg1(Base), Value(Offset) {
    ZEN_ASSERT((Flags & ~(FLAG_TEMP_MEM | FLAG_TEMP_REG)) == 0);
    OpKind = Flags | OK_BaseOffset;
  }

  X64InstOperand(WASMType Type, X64::RegNum Base, X64::RegNum Heap,
                 uint32_t Offset, OperandFlags Flags)
      : WType(Type), Reg1(Base), Reg2(Heap), Value(Offset) {
    ZEN_ASSERT(Flags == FLAG_NONE || Flags == FLAG_TEMP_REG);
    OpKind = Flags | OK_BaseIndexScale1;
  }

  X64OperandKind getKind() const {
    return (X64OperandKind)(OpKind & (FLAG_TEMP_MEM - 1));
  }
  WASMType getType() const { return (WASMType)WType; }
  X64::RegNum getReg() const {
    ZEN_ASSERT(isReg());
    return (X64::RegNum)Reg1;
  }
  int32_t getImm() const {
    ZEN_ASSERT(isImm());
    return Value;
  }
  X64::RegNum getBase() const {
    ZEN_ASSERT(isMem());
    return (X64::RegNum)Reg1;
  }
  X64::RegNum getIndex() const {
    ZEN_ASSERT(isSIB());
    return (X64::RegNum)Reg2;
  }
  int32_t getOffset() const {
    ZEN_ASSERT(isMem());
    return Value;
  }
  OperandFlags getFlags() const {
    return (OperandFlags)(OpKind & (FLAG_TEMP_MEM | FLAG_TEMP_REG));
  }

  bool isReg() const { return getKind() == OK_Register; }
  bool isImm() const { return getKind() == OK_IntConst; }
  bool isMem() const {
    return getKind() >= OK_BaseOffset && getKind() <= OK_BaseIndexScale8;
  }
  bool isNone() const { return getKind() == OK_None; }
  bool isSIB() const {
    return getKind() >= OK_BaseIndexScale1 && getKind() <= OK_BaseIndexScale8;
  }
  bool isTempReg() const { return (OpKind & FLAG_TEMP_REG); }
  uint8_t getRawOpKind() const { return OpKind; }
  bool isTempMem() const { return (OpKind & FLAG_TEMP_MEM); }

  template <X64::Type Ty>
  const typename X64TypeAttr<Ty>::Type &getRegRef() const {
    ZEN_ASSERT(getWASMTypeFromX64Type<Ty>() == getType() ||
               (X64TypeAttr<Ty>::Kind == X64::GPR &&
                getWASMTypeKind(getType()) == WASMTypeKind::INTEGER &&
                getWASMTypeSize(getType()) >= X64TypeAttr<Ty>::Size));
    return X64Reg::getRegRef<Ty>(getReg());
  }

  template <X64::Type Ty>
  const typename X64TypeAttr<Ty>::Type &getStoreVal() const {
    // for store value where value is I32/I64 but type can be I8/I16
    ZEN_ASSERT(getWASMTypeFromX64Type<Ty>() == getType() ||
               (X64TypeAttr<Ty>::getKind == X64::GPR &&
                getWASMTypeKind(getType()) == WASMTypeKind::INTEGER &&
                getWASMTypeSize(getType()) >= X64TypeAttr<Ty>::Size));
    return X64Reg::getRegRef<Ty>(getReg());
  }

  const asmjit::x86::Gpq &getBaseReg() const {
    return X64Reg::getRegRef<X64::I64>(getBase());
  }

  const asmjit::x86::Gpq &getIndexReg() const {
    return X64Reg::getRegRef<X64::I64>(getIndex());
  }

  template <X64::Type Ty> const asmjit::x86::Mem getMem() const {
    constexpr uint32_t Size = X64TypeAttr<Ty>::Size;
    if (getKind() == OK_BaseOffset) {
      return asmjit::x86::Mem(getBaseReg(), getOffset(), Size);
    }
    if (getKind() == OK_BaseIndexScale1) {
      return asmjit::x86::Mem(getIndexReg(), getBaseReg(), 0, getOffset(),
                              Size);
    }
    ZEN_UNREACHABLE();
  }
}; // X64InstOperand

} // namespace zen::singlepass

#endif // ZEN_SINGLEPASS_X64_OPERAND_H
