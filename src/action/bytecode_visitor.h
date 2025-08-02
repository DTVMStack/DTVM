// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_ACTION_BYTECODE_VISITOR_H
#define ZEN_ACTION_BYTECODE_VISITOR_H

#include "common/defines.h"
#include "common/enums.h"
#include "common/operators.h"
#include "common/type.h"
#include "runtime/module.h"
#include "utils/wasm.h"
#include "vm_eval_stack.h"
#include <stack>
#include <vector>

#ifdef ZEN_ENABLE_CHECKED_ARITHMETIC
#include "action/hook.h"
#endif

namespace zen::action {

using common::BinaryOperator;
using common::CompareOperator;
using common::ErrorCode;
using common::getErrorWithExtraMessage;
using common::getWASMBlockTypeFromOpcode;
using common::isWASMTypeFloat;
using common::isWASMTypeInteger;
using common::Opcode;
using common::UnaryOperator;
using common::WASMType;
using common::WASMTypeAttr;
using runtime::TypeEntry;
using utils::readFixedNumber;
using utils::readSafeLEBNumber;
using utils::skipCurrentBlock;

// ============================================================================
// WASMByteCodeDecoder
//
// Decode WASM function byte code and call IRBuilder's interface to convert
// the byte code to other forms
//
// ============================================================================

template <typename IRBuilder> class WASMByteCodeVisitor {
  typedef typename IRBuilder::CtrlBlockKind CtrlBlockKind;
  typedef typename IRBuilder::ArgumentInfo ArgumentInfo;
  typedef typename IRBuilder::BlockInfo CtrlBlockInfo;
  typedef typename IRBuilder::CompilerContext CompilerContext;
  typedef typename IRBuilder::Operand Operand; // operand to build ir
  typedef VMEvalStack<Operand> EvalStack;      // byte code evaluation stack

public:
  WASMByteCodeVisitor(IRBuilder &Builder, CompilerContext *Ctx)
      : Builder(Builder), Ctx(Ctx), CurMod(&Ctx->getWasmMod()),
        CurFunc(&Ctx->getWasmFuncCode()) {
    ZEN_ASSERT(Ctx);
  }

  bool compile() {
    ZEN_ASSERT(Stack.getSize() == 0);
    Builder.initFunction(Ctx);
    bool Ret = decode();
    Builder.finalizeFunctionBase();
    ZEN_ASSERT(Stack.getSize() == 0);
    return Ret;
  }

private:
  void push(Operand Opnd) {
    ZEN_ASSERT(!Opnd.isReg() || Opnd.isTempReg());
    ZEN_ASSERT(Opnd.getType() != WASMType::VOID);
    Stack.push(Opnd);
  }

  Operand pop() {
    Operand Opnd = Stack.pop();
    // poped from stack, try to release it
    Builder.releaseOperand(Opnd);
    return Opnd;
  }

  Operand getTop() { return Stack.getTop(); }

  bool decode() {
    const uint8_t *Ip = CurFunc->CodePtr;
    const uint8_t *IpEnd = Ip + CurFunc->CodeSize;
    int32_t I32;
    int64_t I64;
    uint32_t U32;
    float F32;
    double F64;

    while (Ip < IpEnd) {
      auto &CurBlock = Builder.getCurrentBlockInfo();
      uint8_t Opcode = *Ip++;

      switch (Opcode) {
      case Opcode::UNREACHABLE:
        handleUnreachable();
        Ip = skipCurrentBlock(Ip, IpEnd);
        CurBlock.setReachable(false);
        break;

      case Opcode::NOP:
        break;

      case Opcode::BLOCK: {
        WASMType BlockType = getWASMBlockTypeFromOpcode(*Ip++);
        handleBlock(BlockType);
        break;
      }

      case Opcode::LOOP: {
        WASMType BlockType = getWASMBlockTypeFromOpcode(*Ip++);
        handleLoop(BlockType);
        break;
      }

      case Opcode::IF: {
        WASMType BlockType = getWASMBlockTypeFromOpcode(*Ip++);
        handleIf(BlockType);
        break;
      }

      case Opcode::ELSE:
        handleElse();
        CurBlock.setReachable(true);
        break;

      case Opcode::END:
        handleEnd();
        break;

      case Opcode::BR:
        Ip = readSafeLEBNumber(Ip, U32);
        handleBranch(U32);
        Ip = skipCurrentBlock(Ip, IpEnd);
        CurBlock.setReachable(false);
        break;

      case Opcode::BR_IF:
        Ip = readSafeLEBNumber(Ip, U32);
        handleBranchIf(U32);
        break;

      case Opcode::BR_TABLE:
        Ip = readSafeLEBNumber(Ip, U32);
        Ip = handleBranchTable(Ip, IpEnd, U32);
        Ip = skipCurrentBlock(Ip, IpEnd);
        CurBlock.setReachable(false);
        break;

      case Opcode::RETURN:
        Ip = skipCurrentBlock(Ip, IpEnd);
        handleReturn();
        CurBlock.setReachable(false);
        break;

      case Opcode::CALL: {
        Ip = readSafeLEBNumber(Ip, U32);
        if (U32 == CurMod->getGasFuncIdx()) {
          handleGasCall();
          break;
        }
#ifdef ZEN_ENABLE_CHECKED_ARITHMETIC
#define HANDLE_CHECKED_ARITHMETIC_CALL_POSTHOOK
        HANDLE_CHECKED_ARITHMETIC_CALL(CurMod, U32)
#undef HANDLE_CHECKED_ARITHMETIC_CALL_POSTHOOK
#endif // ZEN_ENABLE_CHECKED_ARITHMETIC
        runtime::CodeEntry *CalleeFunc = CurMod->getCodeEntry(U32);
        uint32_t CalleeOffset = CalleeFunc ? CalleeFunc->CodeOffset : 0;
        uint32_t CallSiteOffset = Ip - CurFunc->CodePtr + CurFunc->CodeOffset;
        uint32_t CallOffset = std::abs(int32_t(CallSiteOffset - CalleeOffset));

        handleCall(U32, CallOffset);
        break;
      }

      case Opcode::CALL_INDIRECT:
        Ip = readSafeLEBNumber(Ip, U32);
        Ip++; // Skip table index(0)
        handleCallIndirect(U32, 0);
        break;

      case Opcode::DROP:
      case Opcode::DROP_64:
        handleDrop();
        break;

      case Opcode::SELECT:
      case Opcode::SELECT_64:
        handleSelect();
        break;

      case Opcode::GET_LOCAL:
        Ip = readSafeLEBNumber(Ip, U32);
        handleGetLocal(U32);
        break;

      case Opcode::SET_LOCAL:
        Ip = readSafeLEBNumber(Ip, U32);
        handleSetLocal(U32);
        break;

      case Opcode::TEE_LOCAL:
        Ip = readSafeLEBNumber(Ip, U32);
        handleTeeLocal(U32);
        break;

      case Opcode::GET_GLOBAL:
        Ip = readSafeLEBNumber(Ip, U32);
        handleGetGlobal(U32);
        break;

      case Opcode::SET_GLOBAL:
        Ip = readSafeLEBNumber(Ip, U32);
        handleSetGlobal(U32);
        break;

      case Opcode::I32_LOAD:
        Ip = handleLoad<WASMType::I32, WASMType::I32, false>(Ip);
        break;
      case Opcode::I32_LOAD8_S:
        Ip = handleLoad<WASMType::I32, WASMType::I8, true>(Ip);
        break;
      case Opcode::I32_LOAD8_U:
        Ip = handleLoad<WASMType::I32, WASMType::I8, false>(Ip);
        break;
      case Opcode::I32_LOAD16_S:
        Ip = handleLoad<WASMType::I32, WASMType::I16, true>(Ip);
        break;
      case Opcode::I32_LOAD16_U:
        Ip = handleLoad<WASMType::I32, WASMType::I16, false>(Ip);
        break;
      case Opcode::I64_LOAD:
        Ip = handleLoad<WASMType::I64, WASMType::I64, false>(Ip);
        break;
      case Opcode::I64_LOAD8_S:
        Ip = handleLoad<WASMType::I64, WASMType::I8, true>(Ip);
        break;
      case Opcode::I64_LOAD8_U:
        Ip = handleLoad<WASMType::I64, WASMType::I8, false>(Ip);
        break;
      case Opcode::I64_LOAD16_S:
        Ip = handleLoad<WASMType::I64, WASMType::I16, true>(Ip);
        break;
      case Opcode::I64_LOAD16_U:
        Ip = handleLoad<WASMType::I64, WASMType::I16, false>(Ip);
        break;
      case Opcode::I64_LOAD32_S:
        Ip = handleLoad<WASMType::I64, WASMType::I32, true>(Ip);
        break;
      case Opcode::I64_LOAD32_U:
        Ip = handleLoad<WASMType::I64, WASMType::I32, false>(Ip);
        break;
      case Opcode::F32_LOAD:
        Ip = handleLoad<WASMType::F32, WASMType::F32, false>(Ip);
        break;
      case Opcode::F64_LOAD:
        Ip = handleLoad<WASMType::F64, WASMType::F64, false>(Ip);
        break;

      case Opcode::I32_STORE:
        Ip = handleStore<WASMType::I32, WASMType::I32>(Ip);
        break;
      case Opcode::I32_STORE8:
        Ip = handleStore<WASMType::I32, WASMType::I8>(Ip);
        break;
      case Opcode::I32_STORE16:
        Ip = handleStore<WASMType::I32, WASMType::I16>(Ip);
        break;
      case Opcode::I64_STORE:
        Ip = handleStore<WASMType::I64, WASMType::I64>(Ip);
        break;
      case Opcode::I64_STORE8:
        Ip = handleStore<WASMType::I64, WASMType::I8>(Ip);
        break;
      case Opcode::I64_STORE16:
        Ip = handleStore<WASMType::I64, WASMType::I16>(Ip);
        break;
      case Opcode::I64_STORE32:
        Ip = handleStore<WASMType::I64, WASMType::I32>(Ip);
        break;
      case Opcode::F32_STORE:
        Ip = handleStore<WASMType::F32, WASMType::F32>(Ip);
        break;
      case Opcode::F64_STORE:
        Ip = handleStore<WASMType::F64, WASMType::F64>(Ip);
        break;

      case Opcode::MEMORY_SIZE:
        // Skip the memory index(0)
        Ip = readSafeLEBNumber(Ip, U32);
        handleMemorySize();
        break;

      case Opcode::MEMORY_GROW:
        // Skip the memory index(0)
        Ip = readSafeLEBNumber(Ip, U32);
        handleMemoryGrow();
        break;

      case Opcode::I32_CONST:
        Ip = readSafeLEBNumber(Ip, I32);
        handleConst<WASMType::I32>(I32);
        break;
      case Opcode::I64_CONST:
        Ip = readSafeLEBNumber(Ip, I64);
        handleConst<WASMType::I64>(I64);
        break;
      case Opcode::F32_CONST:
        Ip = readFixedNumber(Ip, IpEnd, F32);
        handleConst<WASMType::F32>(F32);
        break;
      case Opcode::F64_CONST:
        Ip = readFixedNumber(Ip, IpEnd, F64);
        handleConst<WASMType::F64>(F64);
        break;

      case Opcode::I32_EQZ: // one operand
        Ip = handleCompare<WASMType::I32, CompareOperator::CO_EQZ>(Ip, IpEnd);
        break;
      case Opcode::I32_EQ:
        Ip = handleCompare<WASMType::I32, CompareOperator::CO_EQ>(Ip, IpEnd);
        break;
      case Opcode::I32_NE:
        Ip = handleCompare<WASMType::I32, CompareOperator::CO_NE>(Ip, IpEnd);
        break;
      case Opcode::I32_LT_S:
        Ip = handleCompare<WASMType::I32, CompareOperator::CO_LT_S>(Ip, IpEnd);
        break;
      case Opcode::I32_LT_U:
        Ip = handleCompare<WASMType::I32, CompareOperator::CO_LT_U>(Ip, IpEnd);
        break;
      case Opcode::I32_GT_S:
        Ip = handleCompare<WASMType::I32, CompareOperator::CO_GT_S>(Ip, IpEnd);
        break;
      case Opcode::I32_GT_U:
        Ip = handleCompare<WASMType::I32, CompareOperator::CO_GT_U>(Ip, IpEnd);
        break;
      case Opcode::I32_LE_S:
        Ip = handleCompare<WASMType::I32, CompareOperator::CO_LE_S>(Ip, IpEnd);
        break;
      case Opcode::I32_LE_U:
        Ip = handleCompare<WASMType::I32, CompareOperator::CO_LE_U>(Ip, IpEnd);
        break;
      case Opcode::I32_GE_S:
        Ip = handleCompare<WASMType::I32, CompareOperator::CO_GE_S>(Ip, IpEnd);
        break;
      case Opcode::I32_GE_U:
        Ip = handleCompare<WASMType::I32, CompareOperator::CO_GE_U>(Ip, IpEnd);
        break;

      case Opcode::I64_EQZ: // one operand
        Ip = handleCompare<WASMType::I64, CompareOperator::CO_EQZ>(Ip, IpEnd);
        break;
      case Opcode::I64_EQ:
        Ip = handleCompare<WASMType::I64, CompareOperator::CO_EQ>(Ip, IpEnd);
        break;
      case Opcode::I64_NE:
        Ip = handleCompare<WASMType::I64, CompareOperator::CO_NE>(Ip, IpEnd);
        break;
      case Opcode::I64_LT_S:
        Ip = handleCompare<WASMType::I64, CompareOperator::CO_LT_S>(Ip, IpEnd);
        break;
      case Opcode::I64_LT_U:
        Ip = handleCompare<WASMType::I64, CompareOperator::CO_LT_U>(Ip, IpEnd);
        break;
      case Opcode::I64_GT_S:
        Ip = handleCompare<WASMType::I64, CompareOperator::CO_GT_S>(Ip, IpEnd);
        break;
      case Opcode::I64_GT_U:
        Ip = handleCompare<WASMType::I64, CompareOperator::CO_GT_U>(Ip, IpEnd);
        break;
      case Opcode::I64_LE_S:
        Ip = handleCompare<WASMType::I64, CompareOperator::CO_LE_S>(Ip, IpEnd);
        break;
      case Opcode::I64_LE_U:
        Ip = handleCompare<WASMType::I64, CompareOperator::CO_LE_U>(Ip, IpEnd);
        break;
      case Opcode::I64_GE_S:
        Ip = handleCompare<WASMType::I64, CompareOperator::CO_GE_S>(Ip, IpEnd);
        break;
      case Opcode::I64_GE_U:
        Ip = handleCompare<WASMType::I64, CompareOperator::CO_GE_U>(Ip, IpEnd);
        break;

      case Opcode::F32_EQ:
        Ip = handleCompare<WASMType::F32, CompareOperator::CO_EQ>(Ip, IpEnd);
        break;
      case Opcode::F32_NE:
        Ip = handleCompare<WASMType::F32, CompareOperator::CO_NE>(Ip, IpEnd);
        break;
      case Opcode::F32_LT:
        Ip = handleCompare<WASMType::F32, CompareOperator::CO_LT>(Ip, IpEnd);
        break;
      case Opcode::F32_GT:
        Ip = handleCompare<WASMType::F32, CompareOperator::CO_GT>(Ip, IpEnd);
        break;
      case Opcode::F32_LE:
        Ip = handleCompare<WASMType::F32, CompareOperator::CO_LE>(Ip, IpEnd);
        break;
      case Opcode::F32_GE:
        Ip = handleCompare<WASMType::F32, CompareOperator::CO_GE>(Ip, IpEnd);
        break;

      case Opcode::F64_EQ:
        Ip = handleCompare<WASMType::F64, CompareOperator::CO_EQ>(Ip, IpEnd);
        break;
      case Opcode::F64_NE:
        Ip = handleCompare<WASMType::F64, CompareOperator::CO_NE>(Ip, IpEnd);
        break;
      case Opcode::F64_LT:
        Ip = handleCompare<WASMType::F64, CompareOperator::CO_LT>(Ip, IpEnd);
        break;
      case Opcode::F64_GT:
        Ip = handleCompare<WASMType::F64, CompareOperator::CO_GT>(Ip, IpEnd);
        break;
      case Opcode::F64_LE:
        Ip = handleCompare<WASMType::F64, CompareOperator::CO_LE>(Ip, IpEnd);
        break;
      case Opcode::F64_GE:
        Ip = handleCompare<WASMType::F64, CompareOperator::CO_GE>(Ip, IpEnd);
        break;

      case Opcode::I32_CLZ:
        handleBitCount<WASMType::I32, UnaryOperator::UO_CLZ>();
        break;
      case Opcode::I32_CTZ:
        handleBitCount<WASMType::I32, UnaryOperator::UO_CTZ>();
        break;
      case Opcode::I32_POPCNT:
        handleBitCount<WASMType::I32, UnaryOperator::UO_POPCNT>();
        break;

      case Opcode::I32_ADD:
        handleBinary<WASMType::I32, BinaryOperator::BO_ADD>();
        break;
      case Opcode::I32_SUB:
        handleBinary<WASMType::I32, BinaryOperator::BO_SUB>();
        break;
      case Opcode::I32_MUL:
        handleBinary<WASMType::I32, BinaryOperator::BO_MUL>();
        break;
      case Opcode::I32_DIV_S:
        handleIDiv<WASMType::I32, BinaryOperator::BO_DIV_S>();
        break;
      case Opcode::I32_DIV_U:
        handleIDiv<WASMType::I32, BinaryOperator::BO_DIV_U>();
        break;
      case Opcode::I32_REM_S:
        handleIDiv<WASMType::I32, BinaryOperator::BO_REM_S>();
        break;
      case Opcode::I32_REM_U:
        handleIDiv<WASMType::I32, BinaryOperator::BO_REM_U>();
        break;
      case Opcode::I32_AND:
        handleBinary<WASMType::I32, BinaryOperator::BO_AND>();
        break;
      case Opcode::I32_OR:
        handleBinary<WASMType::I32, BinaryOperator::BO_OR>();
        break;
      case Opcode::I32_XOR:
        handleBinary<WASMType::I32, BinaryOperator::BO_XOR>();
        break;
      case Opcode::I32_SHL:
        handleShift<WASMType::I32, BinaryOperator::BO_SHL>();
        break;
      case Opcode::I32_SHR_S:
        handleShift<WASMType::I32, BinaryOperator::BO_SHR_S>();
        break;
      case Opcode::I32_SHR_U:
        handleShift<WASMType::I32, BinaryOperator::BO_SHR_U>();
        break;
      case Opcode::I32_ROTL:
        handleShift<WASMType::I32, BinaryOperator::BO_ROTL>();
        break;
      case Opcode::I32_ROTR:
        handleShift<WASMType::I32, BinaryOperator::BO_ROTR>();
        break;

      case Opcode::I64_CLZ:
        handleBitCount<WASMType::I64, UnaryOperator::UO_CLZ>();
        break;
      case Opcode::I64_CTZ:
        handleBitCount<WASMType::I64, UnaryOperator::UO_CTZ>();
        break;
      case Opcode::I64_POPCNT:
        handleBitCount<WASMType::I64, UnaryOperator::UO_POPCNT>();
        break;

      case Opcode::I64_ADD:
        handleBinary<WASMType::I64, BinaryOperator::BO_ADD>();
        break;
      case Opcode::I64_SUB:
        handleBinary<WASMType::I64, BinaryOperator::BO_SUB>();
        break;
      case Opcode::I64_MUL:
        handleBinary<WASMType::I64, BinaryOperator::BO_MUL>();
        break;
      case Opcode::I64_DIV_S:
        handleIDiv<WASMType::I64, BinaryOperator::BO_DIV_S>();
        break;
      case Opcode::I64_DIV_U:
        handleIDiv<WASMType::I64, BinaryOperator::BO_DIV_U>();
        break;
      case Opcode::I64_REM_S:
        handleIDiv<WASMType::I64, BinaryOperator::BO_REM_S>();
        break;
      case Opcode::I64_REM_U:
        handleIDiv<WASMType::I64, BinaryOperator::BO_REM_U>();
        break;
      case Opcode::I64_AND:
        handleBinary<WASMType::I64, BinaryOperator::BO_AND>();
        break;
      case Opcode::I64_OR:
        handleBinary<WASMType::I64, BinaryOperator::BO_OR>();
        break;
      case Opcode::I64_XOR:
        handleBinary<WASMType::I64, BinaryOperator::BO_XOR>();
        break;
      case Opcode::I64_SHL:
        handleShift<WASMType::I64, BinaryOperator::BO_SHL>();
        break;
      case Opcode::I64_SHR_S:
        handleShift<WASMType::I64, BinaryOperator::BO_SHR_S>();
        break;
      case Opcode::I64_SHR_U:
        handleShift<WASMType::I64, BinaryOperator::BO_SHR_U>();
        break;
      case Opcode::I64_ROTL:
        handleShift<WASMType::I64, BinaryOperator::BO_ROTL>();
        break;
      case Opcode::I64_ROTR:
        handleShift<WASMType::I64, BinaryOperator::BO_ROTR>();
        break;

      case Opcode::F32_ABS:
        handleFPUnary<WASMType::F32, UnaryOperator::UO_ABS>();
        break;
      case Opcode::F32_NEG:
        handleFPUnary<WASMType::F32, UnaryOperator::UO_NEG>();
        break;
      case Opcode::F32_CEIL:
        handleFPUnary<WASMType::F32, UnaryOperator::UO_CEIL>();
        break;
      case Opcode::F32_FLOOR:
        handleFPUnary<WASMType::F32, UnaryOperator::UO_FLOOR>();
        break;
      case Opcode::F32_TRUNC:
        handleFPUnary<WASMType::F32, UnaryOperator::UO_TRUNC>();
        break;
      case Opcode::F32_NEAREST:
        handleFPUnary<WASMType::F32, UnaryOperator::UO_NEAREST>();
        break;
      case Opcode::F32_SQRT:
        handleFPUnary<WASMType::F32, UnaryOperator::UO_SQRT>();
        break;

      case Opcode::F32_ADD:
        handleBinary<WASMType::F32, BinaryOperator::BO_ADD>();
        break;
      case Opcode::F32_SUB:
        handleBinary<WASMType::F32, BinaryOperator::BO_SUB>();
        break;
      case Opcode::F32_MUL:
        handleBinary<WASMType::F32, BinaryOperator::BO_MUL>();
        break;
      case Opcode::F32_DIV:
        handleFDiv<WASMType::F32, BinaryOperator::BO_DIV>();
        break;
      case Opcode::F32_MIN:
        handleFloatMinMax<WASMType::F32, BinaryOperator::BO_MIN>();
        break;
      case Opcode::F32_MAX:
        handleFloatMinMax<WASMType::F32, BinaryOperator::BO_MAX>();
        break;
      case Opcode::F32_COPYSIGN:
        handleFloatCopysign<WASMType::F32>();
        break;

      case Opcode::F64_ABS:
        handleFPUnary<WASMType::F64, UnaryOperator::UO_ABS>();
        break;
      case Opcode::F64_NEG:
        handleFPUnary<WASMType::F64, UnaryOperator::UO_NEG>();
        break;
      case Opcode::F64_CEIL:
        handleFPUnary<WASMType::F64, UnaryOperator::UO_CEIL>();
        break;
      case Opcode::F64_FLOOR:
        handleFPUnary<WASMType::F64, UnaryOperator::UO_FLOOR>();
        break;
      case Opcode::F64_TRUNC:
        handleFPUnary<WASMType::F64, UnaryOperator::UO_TRUNC>();
        break;
      case Opcode::F64_NEAREST:
        handleFPUnary<WASMType::F64, UnaryOperator::UO_NEAREST>();
        break;
      case Opcode::F64_SQRT:
        handleFPUnary<WASMType::F64, UnaryOperator::UO_SQRT>();
        break;

      case Opcode::F64_ADD:
        handleBinary<WASMType::F64, BinaryOperator::BO_ADD>();
        break;
      case Opcode::F64_SUB:
        handleBinary<WASMType::F64, BinaryOperator::BO_SUB>();
        break;
      case Opcode::F64_MUL:
        handleBinary<WASMType::F64, BinaryOperator::BO_MUL>();
        break;
      case Opcode::F64_DIV:
        handleFDiv<WASMType::F64, BinaryOperator::BO_DIV>();
        break;
      case Opcode::F64_MIN:
        handleFloatMinMax<WASMType::F64, BinaryOperator::BO_MIN>();
        break;
      case Opcode::F64_MAX:
        handleFloatMinMax<WASMType::F64, BinaryOperator::BO_MAX>();
        break;
      case Opcode::F64_COPYSIGN:
        handleFloatCopysign<WASMType::F64>();
        break;

      case Opcode::I32_WRAP_I64:
        handleIntTrunc();
        break;
      case Opcode::I32_TRUNC_S_F32:
        handleFloatToInt<WASMType::I32, WASMType::F32, true>();
        break;
      case Opcode::I32_TRUNC_U_F32:
        handleFloatToInt<WASMType::I32, WASMType::F32, false>();
        break;
      case Opcode::I32_TRUNC_S_F64:
        handleFloatToInt<WASMType::I32, WASMType::F64, true>();
        break;
      case Opcode::I32_TRUNC_U_F64:
        handleFloatToInt<WASMType::I32, WASMType::F64, false>();
        break;

      case Opcode::I64_EXTEND_S_I32:
        handleIntExtend<WASMType::I64, WASMType::I32, true>();
        break;
      case Opcode::I64_EXTEND_U_I32:
        handleIntExtend<WASMType::I64, WASMType::I32, false>();
        break;
      case Opcode::I64_TRUNC_S_F32:
        handleFloatToInt<WASMType::I64, WASMType::F32, true>();
        break;
      case Opcode::I64_TRUNC_U_F32:
        handleFloatToInt<WASMType::I64, WASMType::F32, false>();
        break;
      case Opcode::I64_TRUNC_S_F64:
        handleFloatToInt<WASMType::I64, WASMType::F64, true>();
        break;
      case Opcode::I64_TRUNC_U_F64:
        handleFloatToInt<WASMType::I64, WASMType::F64, false>();
        break;

      case Opcode::F32_CONVERT_S_I32:
        handleConvert<WASMType::F32, WASMType::I32, true>();
        break;
      case Opcode::F32_CONVERT_U_I32:
        handleConvert<WASMType::F32, WASMType::I32, false>();
        break;
      case Opcode::F32_CONVERT_S_I64:
        handleConvert<WASMType::F32, WASMType::I64, true>();
        break;
      case Opcode::F32_CONVERT_U_I64:
        handleConvert<WASMType::F32, WASMType::I64, false>();
        break;
      case Opcode::F32_DEMOTE_F64:
        handleConvert<WASMType::F32, WASMType::F64, false>();
        break;

      case Opcode::F64_CONVERT_S_I32:
        handleConvert<WASMType::F64, WASMType::I32, true>();
        break;
      case Opcode::F64_CONVERT_U_I32:
        handleConvert<WASMType::F64, WASMType::I32, false>();
        break;
      case Opcode::F64_CONVERT_S_I64:
        handleConvert<WASMType::F64, WASMType::I64, true>();
        break;
      case Opcode::F64_CONVERT_U_I64:
        handleConvert<WASMType::F64, WASMType::I64, false>();
        break;
      case Opcode::F64_PROMOTE_F32:
        handleConvert<WASMType::F64, WASMType::F32, false>();
        break;

      case Opcode::I32_REINTERPRET_F32:
        handleBitcast<WASMType::I32, WASMType::F32>();
        break;
      case Opcode::I64_REINTERPRET_F64:
        handleBitcast<WASMType::I64, WASMType::F64>();
        break;
      case Opcode::F32_REINTERPRET_I32:
        handleBitcast<WASMType::F32, WASMType::I32>();
        break;
      case Opcode::F64_REINTERPRET_I64:
        handleBitcast<WASMType::F64, WASMType::I64>();
        break;

      case Opcode::I32_EXTEND8_S:
        handleIntExtend<WASMType::I32, WASMType::I8, true>();
        break;
      case Opcode::I32_EXTEND16_S:
        handleIntExtend<WASMType::I32, WASMType::I16, true>();
        break;
      case Opcode::I64_EXTEND8_S:
        handleIntExtend<WASMType::I64, WASMType::I8, true>();
        break;
      case Opcode::I64_EXTEND16_S:
        handleIntExtend<WASMType::I64, WASMType::I16, true>();
        break;
      case Opcode::I64_EXTEND32_S:
        handleIntExtend<WASMType::I64, WASMType::I32, true>();
        break;

      default:
        throw getErrorWithExtraMessage(ErrorCode::UnsupportedOpcode,
                                       std::to_string(Opcode));
      }
    }

    // always emit return after function end, as branch instructions might
    // target a function's end and jump out
    handleReturn();

    return true;
  }

  // ==================== Control Instruction Handlers ====================

  void handleUnreachable() { Builder.handleUnreachable(); }

  void handleBlock(WASMType BlockType) {
    Builder.handleBlock(BlockType, Stack.getSize());
  }

  void handleLoop(WASMType BlockType) {
    Builder.handleLoop(BlockType, Stack.getSize());
  }

  void handleIf(WASMType BlockType) {
    Operand Cond = pop();
    Builder.handleIf(Cond, BlockType, Stack.getSize());
  }

  void handleElse() {
    const CtrlBlockInfo &Info = Builder.getCurrentBlockInfo();
    ZEN_ASSERT(verifyCtrlInstValType(Info));
    ZEN_ASSERT(Info.getKind() == CtrlBlockKind::IF);
    if (Info.getType() != WASMType::VOID && Info.reachable()) {
      // make an assignment to copy stack top to block info result
      Operand BlockResult = Info.getResult();
      Builder.makeAssignment(Info.getType(), BlockResult, pop());
    }
    Builder.handleElse(Info);
  }

  void handleEnd() {
    const CtrlBlockInfo &Info = Builder.getCurrentBlockInfo();
    ZEN_ASSERT(verifyCtrlInstValType(Info));

    Operand BlockResult = Info.getResult();
    if (Info.getType() != WASMType::VOID && Info.reachable()) {
      // make an assignment to copy stack top to block info result
      Builder.makeAssignment(Info.getType(), BlockResult, pop());
    }
    // value stack may have excess elements after an unconditional branch;
    // we need to pop them out before returing to the outer block
    while (Stack.getSize() > Info.getStackSize()) {
      Stack.pop();
    }

    // NOTE: `info` is popped off its container after this call
    Builder.handleEnd(Info);

    if (BlockResult.getType() != WASMType::VOID) {
      // save return register to temp location
      push(BlockResult);
    }
  }

  void handleBranch(uint32_t Level) {
    const CtrlBlockInfo &Info = Builder.getBlockInfo(Level);
    bool JumpBack = (Info.getKind() == CtrlBlockKind::LOOP);
    ZEN_ASSERT(verifyCtrlInstValType(Info, JumpBack));
    if (Info.getType() != WASMType::VOID && !JumpBack) {
      // make an assignment to copy stack top to block info result
      Operand BlockResult = Info.getResult();
      Builder.makeAssignment(Info.getType(), BlockResult, getTop());
    }
    Builder.handleBranch(Level, Info);
  }

  void handleBranchIf(uint32_t Level) {
    Operand Opnd = pop();
    const CtrlBlockInfo &Info = Builder.getBlockInfo(Level);
    bool JumpBack = (Info.getKind() == CtrlBlockKind::LOOP);
    ZEN_ASSERT(verifyCtrlInstValType(Info, JumpBack));
    if (Info.getType() != WASMType::VOID && !JumpBack) {
      // make an assignment to copy stack top to block info result
      Operand BlockResult = Info.getResult();
      Builder.makeAssignment(Info.getType(), BlockResult, getTop());
    }
    Builder.handleBranchIf(Opnd, Level, Info);
  }

  const uint8_t *handleBranchTable(const uint8_t *Ip, const uint8_t *End,
                                   uint32_t Count) {
    std::vector<uint32_t> Levels;
    Levels.reserve(Count + 1); // includes last default target
    WASMType Type = WASMType::VOID;
    for (uint32_t I = 0; I < Count + 1; ++I) {
      uint32_t TargetLevel;
      Ip = readSafeLEBNumber(Ip, TargetLevel);
      if (Ip >= End) {
        break;
      }
      const auto &Info = Builder.getBlockInfo(TargetLevel);
      WASMType BlockType = (Info.getKind() == CtrlBlockKind::LOOP)
                               ? WASMType::VOID
                               : Info.getType();
      if (I == 0) {
        Type = BlockType;
      } else {
        ZEN_ASSERT(BlockType == Type);
      }
      Levels.push_back(TargetLevel);
    }
    Operand Opnd = pop();
    Operand StackTop = (Type == WASMType::VOID) ? Operand() : getTop();
    Builder.handleBranchTable(Opnd, StackTop, Levels);
    return Ip;
  }

  void handleReturn() {
    const TypeEntry &Type = Ctx->getWasmFuncType();
    ZEN_ASSERT(Stack.getSize() >= Type.NumReturns);
    if (Type.NumReturns > 0 && Stack.getSize() > 0) {
      Builder.handleReturn(pop());
    } else if (Type.NumReturns == 0) {
      Builder.handleReturn(Operand());
    }
  }

  void handleCall(uint32_t FuncIdx, uint32_t CallOffset) {
    uint32_t NumFunctions = CurMod->getNumTotalFunctions();
    ZEN_ASSERT(FuncIdx < NumFunctions);
    TypeEntry *Type = CurMod->getFunctionType(FuncIdx);
    ZEN_ASSERT(Type);
    uintptr_t Target = 0;
    bool IsImport = FuncIdx < CurMod->getNumImportFunctions();
    bool FarCall = !IsImport && CallOffset > (1 << 24);
    if (IsImport) {
      const auto &ImportFunc = CurMod->getImportFunction(FuncIdx);
      Target = (uintptr_t)ImportFunc.FuncPtr;
      ZEN_ASSERT(Target != 0);
    }
    // TODO: create ArgInfo only with type on demand
    ArgumentInfo ArgInfo(Type);
    std::vector<Operand> Args;
    Args.resize(Type->NumParams);
    collectCallParams(Type, Args);

    Operand Result =
        Builder.handleCall(FuncIdx, Target, IsImport, FarCall, ArgInfo, Args);
    if (Type->NumReturns > 0) {
      push(Result);
    }
  }

  void handleCallIndirect(uint32_t TypeIdx, uint32_t TableIdx) {
    ZEN_ASSERT(CurMod->isValidType(TypeIdx));
    ZEN_ASSERT(TableIdx < CurMod->getNumTotalTables());
    Operand IndirectFuncIdx = pop();
    TypeEntry *Type = CurMod->getDeclaredType(TypeIdx);
    ZEN_ASSERT(Type);
    ArgumentInfo ArgInfo(Type);
    std::vector<Operand> Args;
    Args.resize(Type->NumParams);
    collectCallParams(Type, Args);
    TypeIdx = CurMod->getDeclaredType(TypeIdx)->SmallestTypeIdx;
    Operand Result = Builder.handleCallIndirect(TypeIdx, IndirectFuncIdx,
                                                TableIdx, ArgInfo, Args);

    if (Type->NumReturns > 0) {
      ZEN_ASSERT(Type->NumReturns == 1);
      push(Result);
    }
  }

  // ==================== Parametric Instruction Handlers ====================

  void handleDrop() { pop(); }

  void handleSelect() {
    Operand Cond = pop();
    Operand RHS = pop();
    Operand LHS = pop();
    ZEN_ASSERT(RHS.getType() == LHS.getType());
    ZEN_ASSERT(Cond.getType() == WASMType::I32 ||
               Cond.getType() == WASMType::I64);
    Operand Result = Builder.handleSelect(Cond, LHS, RHS);
    ZEN_ASSERT(Result.getType() == LHS.getType());
    push(Result);
  }

  // ==================== Variable Instruction Handlers ====================

  void handleGetLocal(uint32_t LocalIdx) {
    Operand Result = Builder.handleGetLocal(LocalIdx);
    push(Result);
  }

  void handleSetLocal(uint32_t LocalIdx) {
    Operand Val = pop();
    Builder.handleSetLocal(LocalIdx, Val);
  }

  void handleTeeLocal(uint32_t LocalIdx) {
    Operand Val = getTop();
    Builder.handleSetLocal(LocalIdx, Val);
  }

  void handleGetGlobal(uint32_t GlobalIdx) {
    Operand Result = Builder.handleGetGlobal(GlobalIdx);
    push(Result);
  }

  void handleSetGlobal(uint32_t GlobalIdx) {
    Operand Val = pop();
    Builder.handleSetGlobal(GlobalIdx, Val);
  }

  // ==================== Memory Instruction Handlers ====================

  template <WASMType DestType, WASMType SrcType, bool Sext>
  const uint8_t *handleLoad(const uint8_t *Ip) {
    uint32_t Align;
    uint32_t Offset;
    Ip = readSafeLEBNumber(Ip, Align);
    Ip = readSafeLEBNumber(Ip, Offset);
    Operand Base = pop();
    Operand Result = Builder.template handleLoad<DestType, SrcType, Sext>(
        Base, Offset, Align);
    push(Result);
    return Ip;
  }

  template <WASMType SrcType, WASMType DestType>
  const uint8_t *handleStore(const uint8_t *Ip) {
    uint32_t Align;
    uint32_t Offset;
    Ip = readSafeLEBNumber(Ip, Align);
    Ip = readSafeLEBNumber(Ip, Offset);
    Operand Value = pop();
    Operand Base = pop();
    ZEN_ASSERT(Value.getType() == SrcType);
    Builder.template handleStore<DestType>(Value, Base, Offset, Align);
    return Ip;
  }

  void handleMemorySize() {
    Operand Opnd = Builder.handleMemorySize();
    push(Opnd);
  }

  void handleMemoryGrow() {
    Operand Opnd = pop();
    Operand Result = Builder.handleMemoryGrow(Opnd);
    push(Result);
  }

  // ==================== Numeric Instruction Handlers ====================

  template <WASMType Ty> void handleConst(typename WASMTypeAttr<Ty>::Type Val) {
    Operand Result = Builder.template handleConst<Ty>(Val);
    push(Result);
  }

  template <WASMType Type, CompareOperator Opr>
  const uint8_t *handleCompare(const uint8_t *Ip, const uint8_t *End) {
    // pop operands
    Operand CmpRHS = (Opr != CompareOperator::CO_EQZ) ? pop() : Operand();
    Operand CmpLHS = pop();

    // floating-point comparisons need special handling with regard to NaN
    if (common::isWASMTypeFloat<Type>()) {
      auto Result = Builder.template handleCompareOp<Type, Opr>(CmpLHS, CmpRHS);
      push(Result);
      return Ip;
    }

    // check opportunity for macro-fusion
    uint8_t Opcode = *Ip;
    uint32_t U32Val;
    switch (Opcode) {
    case Opcode::IF: {
      // bounds check
      Ip += 2;
      if (Ip < End) {
        WASMType BlockType = getWASMBlockTypeFromOpcode(*(Ip - 1));
        Builder.template handleFusedCompareIfa<Type, Opr>(
            CmpLHS, CmpRHS, BlockType, Stack.getSize());
      }
      break;
    }

    case Opcode::BR_IF: {
      Ip = readSafeLEBNumber(Ip + 1, U32Val);
      // bounds check
      if (Ip < End) {
        const CtrlBlockInfo &Info = Builder.getBlockInfo(U32Val);
        bool JumpBack = (Info.getKind() == CtrlBlockKind::LOOP);
        ZEN_ASSERT(verifyCtrlInstValType(Info, JumpBack));
        if (Info.getType() != WASMType::VOID && !JumpBack) {
          // make an assignment to copy stack top to block info
          Builder.makeAssignment(Info.getType(), Info.getResult(), getTop());
        }
        Builder.template handleFusedCompareBranchIf<Type, Opr>(CmpLHS, CmpRHS,
                                                               U32Val, Info);
      }
      break;
    }

    case Opcode::SELECT:
    case Opcode::SELECT_64: {
      Ip++;
      if (Ip < End) {
        Operand SelRHS = pop();
        Operand SelLHS = pop();
        Operand Result = Builder.template handleFusedCompareSelect<Type, Opr>(
            CmpLHS, CmpRHS, SelLHS, SelRHS);
        push(Result);
      }
      break;
    }

    default: {
      Operand Result =
          Builder.template handleCompareOp<Type, Opr>(CmpLHS, CmpRHS);
      push(Result);
      break;
    }
    }

    return Ip;
  }

  template <WASMType Type, UnaryOperator Opr> void handleBitCount() {
    Operand Opnd = pop();
    Operand Result = Builder.template handleBitCountOp<Type, Opr>(Opnd);
    push(Result);
  }

  template <WASMType Type, BinaryOperator Opr> void handleBinary() {
    Operand RHS = pop();
    Operand LHS = pop();
    Operand Result = Builder.template handleBinaryOp<Type, Opr>(LHS, RHS);
    push(Result);
  }

  template <WASMType Type, BinaryOperator Opr> void handleIDiv() {
    Operand RHS = pop();
    Operand LHS = pop();
    Operand Result = Builder.template handleIDiv<Type, Opr>(LHS, RHS);
    push(Result);
  }

  template <WASMType Type, BinaryOperator Opr> void handleShift() {
    Operand RHS = pop();
    Operand LHS = pop();
    Operand Result = Builder.template handleShift<Type, Opr>(LHS, RHS);
    push(Result);
  }

  template <WASMType Type, UnaryOperator Opr> void handleFPUnary() {
    Operand Opnd = pop();
    Operand Result = Builder.template handleUnaryOp<Type, Opr>(Opnd);
    push(Result);
  }

  template <WASMType Type, BinaryOperator Opr> void handleFDiv() {
    Operand RHS = pop();
    Operand LHS = pop();
    Operand Result = Builder.template handleFDiv<Type, Opr>(LHS, RHS);
    push(Result);
  }

  template <WASMType Type, BinaryOperator Opr> void handleFloatMinMax() {
    Operand RHS = pop();
    Operand LHS = pop();
    Operand Result = Builder.template handleFloatMinMax<Type, Opr>(LHS, RHS);
    push(Result);
  }

  template <WASMType Type> void handleFloatCopysign() {
    Operand RHS = pop();
    Operand LHS = pop();
    Operand Result = Builder.template handleFloatCopysign<Type>(LHS, RHS);
    push(Result);
  }

  // Truncate i64 to i32
  void handleIntTrunc() {
    Operand Opnd = pop();
    ZEN_ASSERT(Opnd.getType() == WASMType::I64);
    Operand Result = Builder.handleIntTrunc(Opnd);
    ZEN_ASSERT(Result.getType() == WASMType::I32);
    push(Result);
  }

  // Convert float to integer
  template <WASMType DestType, WASMType SrcType, bool Sext>
  void handleFloatToInt() {
    ZEN_STATIC_ASSERT(isWASMTypeInteger<DestType>() &&
                      isWASMTypeFloat<SrcType>());
    Operand Opnd = pop();
    ZEN_ASSERT(Opnd.getType() == SrcType);
    Operand Result =
        Builder.template handleFloatToInt<DestType, SrcType, Sext>(Opnd);
    ZEN_ASSERT(Result.getType() == DestType);
    push(Result);
  }

  // Extend from SrcType to DestType (only for integer)
  template <WASMType DestType, WASMType SrcType, bool Sext>
  void handleIntExtend() {
    Operand Opnd = pop();
    Operand Result =
        Builder.template handleIntExtend<DestType, SrcType, Sext>(Opnd);
    ZEN_ASSERT(Result.getType() == DestType);
    push(Result);
  }

  // Convert from SrcType to DestType (between integer and float-point)
  template <WASMType DestType, WASMType SrcType, bool Sext>
  void handleConvert() {
    Operand Opnd = pop();
    ZEN_ASSERT(Opnd.getType() == SrcType);
    Operand Result =
        Builder.template handleConvert<DestType, SrcType, Sext>(Opnd);
    ZEN_ASSERT(Result.getType() == DestType);
    push(Result);
  }

  // Reinpterpret between integer and floating-point
  template <WASMType DestType, WASMType SrcType> void handleBitcast() {
    Operand Opnd = pop();
    ZEN_ASSERT(Opnd.getType() == SrcType);
    Operand Result = Builder.template handleBitcast<DestType, SrcType>(Opnd);
    push(Result);
  }

  // ==================== Util Methods ====================

  // Verify consistency between control block and eval block
  bool verifyCtrlInstValType(const CtrlBlockInfo &Info, bool JumpBack = false) {
    if (!Builder.getCurrentBlockInfo().reachable()) {
      // value stack becomes unconstrained after an unconditional branch
      return true;
    }
    if (Info.getType() == WASMType::VOID || JumpBack) {
      // on an unconditional branch, value stack may have excess elements
      ZEN_ASSERT(Info.getStackSize() <= Stack.getSize());
    } else {
      ZEN_ASSERT(Info.getStackSize() + 1 <= Stack.getSize());
      // info type == stack top type
      ZEN_ASSERT(Info.getType() == Stack.getTop().getType());
    }
    return true;
  }

  void collectCallParams(TypeEntry *Type, std::vector<Operand> &Args) {
    if (Type->NumParams) {
      ZEN_ASSERT(Args.size() == Type->NumParams);
      for (uint32_t I = 0; I < Type->NumParams; ++I) {
        Args[Type->NumParams - 1 - I] = pop();
      }
    }
  }

  // ==================== Platform Feature Methods ====================

  void handleGasCall() {
    auto Delta = pop();
    ZEN_ASSERT(Delta.getType() == WASMType::I64);
    Builder.handleGasCall(Delta);
  }

  template <bool Signed, WASMType Type, BinaryOperator Opr>
  void handleCheckedArithmetic() {
    auto RHS = pop();
    auto LHS = pop();
    auto Result =
        Builder.template handleCheckedArithmetic<Signed, Type, Opr>(LHS, RHS);
    push(Result);
  }

  template <bool Signed, BinaryOperator Opr>
  void handleCheckedI128Arithmetic() {
    auto RHSHi = pop();
    auto RHSLo = pop();
    auto LHSHi = pop();
    auto LHSLo = pop();
    auto Result = Builder.template handleCheckedI128Arithmetic<Signed, Opr>(
        LHSLo, LHSHi, RHSLo, RHSHi);
    push(Result);
  }

  IRBuilder &Builder;   // ir builder
  EvalStack Stack;      // byte code evaluation stack
  CompilerContext *Ctx; // context
  const runtime::Module *CurMod;
  const runtime::CodeEntry *CurFunc;
};

} // namespace zen::action

#endif // ZEN_ACTION_BYTECODE_VISITOR_H
