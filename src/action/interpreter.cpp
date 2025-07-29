// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "action/interpreter.h"
#include "action/hook.h"
#include "common/errors.h"
#include "entrypoint/entrypoint.h"
#include "runtime/instance.h"
#include "utils/logging.h"
#include "utils/wasm.h"
#include <bitset>
#include <cmath>
#include <type_traits>

namespace zen::action {

using namespace common;
using namespace utils;
using namespace runtime;

//
// local_ptr <-----> frame <-----> control stack <----> value stack
InterpFrame *InterpreterExecContext::allocFrame(FunctionInstance *FuncInst,
                                                uint32_t *LocalPtr) {
  InterpStack *Stack = getInterpStack();
  uint32_t LocalSize = FuncInst->NumLocalCells << 2;
  uint32_t ControlSize = FuncInst->MaxBlockDepth * sizeof(BlockInfo);
  // check stack overflow
  if (Stack->top() + LocalSize + sizeof(InterpFrame) + FuncInst->MaxStackSize +
          ControlSize >=
      Stack->TopBoundary) {
    return nullptr;
  }

  // alloc locals
  std::memset(Stack->top(), 0, LocalSize);
  Stack->Top += LocalSize;

  // alloc Frame
  InterpFrame *Frame = (InterpFrame *)Stack->Top;
  std::memset(Stack->top(), 0, sizeof(InterpFrame));
  Stack->Top += sizeof(InterpFrame);

  // alloc control stack
  Frame->CtrlStackPtr = Frame->CtrlBasePtr = (BlockInfo *)Stack->top();
  Stack->Top += ControlSize;
  Frame->CtrlBoundary = (BlockInfo *)Stack->top();

  // alloc value stack
  Frame->ValueStackPtr = Frame->ValueBasePtr = (uint32_t *)Stack->top();
  Stack->Top += FuncInst->MaxStackSize;
  Frame->ValueBoundary = (uint32_t *)Stack->top();

  Frame->LocalPtr = LocalPtr;
  Frame->FuncInst = FuncInst;
  Frame->Ip = FuncInst->CodePtr;
  Frame->PrevFrame = getCurFrame();

  setCurFrame(Frame);
#ifdef ZEN_ENABLE_DWASM
  runtime::Instance *Inst = getInstance();
  uint32_t CurFuncStackCost =
      (FuncInst->NumParamCells + FuncInst->NumLocalCells) << 2;
  Inst->updateStackCost(CurFuncStackCost);
  if (Inst->getStackCost() > PresetReservedStackSize) {
    throw getError(ErrorCode::DWasmCallStackExceed);
  }
#endif // ZEN_ENABLE_DWASM
  return Frame;
}

void InterpreterExecContext::freeFrame(FunctionInstance *FuncInst,
                                       InterpFrame *Frame) {
  uint8_t *NewTop = reinterpret_cast<uint8_t *>(Frame);
  uint32_t LocalSize = FuncInst->NumLocalCells << 2;
  NewTop -= LocalSize;

  ZEN_ASSERT(NewTop >= Stack->Bottom);
  Stack->Top = NewTop;

#ifdef ZEN_ENABLE_DWASM
  uint32_t CurFuncStackCost =
      (FuncInst->NumParamCells + FuncInst->NumLocalCells) << 2;
  getInstance()->updateStackCost(-CurFuncStackCost);
#endif // ZEN_ENABLE_DWASM
}

enum BinaryOperator {
  BO_ADD,
  BO_SUB,
  BO_MUL,
  BO_DIV,
  BO_DIV_S,
  BO_EQ,
  BO_NE,
  BO_LT,
  BO_GT,
  BO_LE,
  BO_GE,
  BO_REM_S,
  BO_REM_U,
  BO_AND,
  BO_OR,
  BO_XOR,
  BO_SHL,
  BO_SHR,
  BO_ROTL,
  BO_ROTR,
  BO_MIN,
  BO_MAX,
  BO_COPYSIGN,

  BC_CLZ,
  BC_CTZ,
  BC_POP_COUNT_I32,
  BC_POP_COUNT_I64,

  BM_SQRT,
  BM_FLOOR,
  BM_CEIL,
  BM_TRUNC,
  BM_NEAREST,
  BM_ABS,
  BM_NEG_F32,
  BM_NEG_F64
};

template <typename T, typename std::enable_if<!std::is_floating_point<T>::value,
                                              int>::type = 0>
T CanonNaN(T Val) {
  return Val;
}

template <typename T, typename std::enable_if<std::is_floating_point<T>::value,
                                              int>::type = 0>
T CanonNaN(T Val) {
  if (std::isnan(Val)) {
    return std::numeric_limits<float>::quiet_NaN();
  }
  return Val;
}

template <typename T, BinaryOperator Op> struct BinaryOpHelper {
public:
  T operator()(T LHS, T RHS);
};

template <typename T> struct BinaryOpHelper<T, BO_DIV_S> {
public:
  T operator()(T LHS, T RHS) {
    if constexpr (sizeof(T) == 8) {
      if (LHS == (static_cast<int64_t>(0x1ULL << 63)) && RHS == -1) {
        throw getError(ErrorCode::IntegerOverflow);
      }
    } else {
      static_assert(sizeof(T) == 4);
      if (LHS == (static_cast<int32_t>(0x1U << 31)) && RHS == -1) {
        throw getError(ErrorCode::IntegerOverflow);
      }
    }
    if (RHS == 0) {
      throw getError(ErrorCode::IntegerDivByZero);
    }
    return LHS / RHS;
  }
};

template <typename T> struct BinaryOpHelper<T, BO_DIV> {
public:
  T operator()(T LHS, T RHS) {
    if constexpr (!std::is_floating_point<T>::value) {
      if (RHS == 0) {
        throw getError(ErrorCode::IntegerDivByZero);
      }
      return LHS / RHS;
    } else {
      // We need to know whether RHS/LHS is exactly 0, so we should not use
      // approximate judgments like num < 1e-6
      // 0.0 / 0.0 is NaN
      // 1e-10 / 0.0 is +∞
      // -1e-10 / 0.0 is -∞
      if (RHS == 0) {
        return std::isnan(LHS) || LHS == 0
                   ? std::numeric_limits<T>::quiet_NaN()
                   : ((std::signbit(LHS) ^ std::signbit(RHS))
                          ? -std::numeric_limits<T>::infinity()
                          : std::numeric_limits<T>::infinity());
      }
      return CanonNaN(LHS / RHS);
    }
  }
};

template <typename T> struct BinaryOpHelper<T, BO_REM_S> {
public:
  T operator()(T LHS, T RHS) {
    if constexpr (sizeof(T) == 8) {
      if (LHS == (static_cast<int64_t>(0x1ULL << 63)) && RHS == -1) {
        return 0;
      }
    } else {
      static_assert(sizeof(T) == 4);
      if (LHS == (static_cast<int32_t>(0x1U << 31)) && RHS == -1) {
        return 0;
      }
    }

    if (RHS == 0) {
      throw getError(ErrorCode::IntegerDivByZero);
    }

    return LHS % RHS;
  }
};

template <typename T> struct BinaryOpHelper<T, BO_REM_U> {
public:
  T operator()(T LHS, T RHS) {
    if (RHS == 0) {
      throw getError(ErrorCode::IntegerDivByZero);
    }
    return LHS % RHS;
  }
};

template <typename T> struct BinaryOpHelper<T, BO_ROTL> {
public:
  T operator()(T LHS, T RHS) {
    constexpr uint32_t TypeBitNum = sizeof(T) << 3;
    RHS = RHS % TypeBitNum;
    constexpr uint32_t Mask = TypeBitNum - 1;
    RHS &= Mask;
    return (LHS << RHS) | (LHS >> ((0 - RHS) & Mask));
  }
};

template <typename T> struct BinaryOpHelper<T, BO_ROTR> {
public:
  T operator()(T LHS, T RHS) {
    constexpr uint32_t TypeBitNum = sizeof(T) << 3;
    RHS = RHS % TypeBitNum;
    constexpr uint32_t Mask = TypeBitNum - 1;
    RHS &= Mask;
    return (LHS >> RHS) | (LHS << ((0 - RHS) & Mask));
  }
};

template <typename T> struct BinaryOpHelper<T, BO_MIN> {
public:
  T operator()(T LHS, T RHS) {
    if (std::isnan(LHS) || std::isnan(RHS)) {
      return std::numeric_limits<T>::quiet_NaN();
    }
    if (LHS == 0 && RHS == 0) {
      return std::signbit(LHS) ? LHS : RHS;
    }
    return std::min(LHS, RHS);
  }
};

template <typename T> struct BinaryOpHelper<T, BO_MAX> {
public:
  T operator()(T LHS, T RHS) {
    if (std::isnan(LHS) || std::isnan(RHS)) {
      return std::numeric_limits<T>::quiet_NaN();
    }
    if (LHS == 0 && RHS == 0) {
      return std::signbit(LHS) ? RHS : LHS;
    }
    return std::max(LHS, RHS);
  }
};

template <typename T> struct BinaryOpHelper<T, BO_COPYSIGN> {
public:
  T operator()(T LHS, T RHS) {
    return std::signbit(RHS) ? -std::fabs(LHS) : std::fabs(LHS);
  }
};

#define DECL_BINOP_IMPL(Opr, Operation)                                        \
  template <typename T> struct BinaryOpHelper<T, BO_##Opr> {                   \
  public:                                                                      \
    T operator()(T LHS, T RHS) { return CanonNaN(LHS Operation RHS); }         \
  };

DECL_BINOP_IMPL(ADD, +)
DECL_BINOP_IMPL(SUB, -)
DECL_BINOP_IMPL(MUL, *)
DECL_BINOP_IMPL(AND, &)
DECL_BINOP_IMPL(OR, |)
DECL_BINOP_IMPL(XOR, ^)
DECL_BINOP_IMPL(SHL, <<)
DECL_BINOP_IMPL(SHR, >>)
#undef DECL_BINOP_IMPL

#define DECL_COMPARE_IMPL(Opr, Operation)                                      \
  template <typename T> struct BinaryOpHelper<T, BO_##Opr> {                   \
  public:                                                                      \
    int32_t operator()(T LHS, T RHS) { return LHS Operation RHS; }             \
  };

DECL_COMPARE_IMPL(EQ, ==)
DECL_COMPARE_IMPL(NE, !=)
DECL_COMPARE_IMPL(LT, <)
DECL_COMPARE_IMPL(GT, >)
DECL_COMPARE_IMPL(LE, <=)
DECL_COMPARE_IMPL(GE, >=)
#undef DECL_COMPARE_IMPL

class BaseInterpreterImpl {
private:
  InterpreterExecContext &Context;

public:
  BaseInterpreterImpl(InterpreterExecContext &Context) : Context(Context) {}
  void interpret();

private:
  struct CacheValue {
    const uint8_t *ElsePtr = nullptr;
    const uint8_t *EndPtr = nullptr;
  };
  std::unordered_map<const uint8_t *, CacheValue> BlockAddrCache;

  void findBlockAddr(const uint8_t *Start, const uint8_t *End,
                     const uint8_t *&ElseAddr, const uint8_t *&EndAddr) {
    auto It = BlockAddrCache.find(Start);
    if (It != BlockAddrCache.end()) {
      auto &CacheValue = It->second;
      ElseAddr = CacheValue.ElsePtr;
      EndAddr = CacheValue.EndPtr;
      return;
    }

    const uint8_t *Ptr = Start;
    int32_t BlockDepth = 1;

    std::unordered_map<int32_t, const uint8_t *> BlockStartPtrs;

    BlockStartPtrs[0] = Start;

    while (Ptr < End) {
      uint8_t Opcode = *Ptr++;
      switch (Opcode) {
      case UNREACHABLE:
      case NOP:
        break;
      case BLOCK:
      case LOOP:
      case IF:
        // process type
        Ptr = skipBlockType(Ptr, End);
        BlockStartPtrs[BlockDepth] = Ptr;
        BlockDepth++;
        break;
      case ELSE: {
        BlockAddrCache[BlockStartPtrs[BlockDepth - 1]].ElsePtr = Ptr - 1;
        break;
      }
      case BR:
      case BR_IF:
        Ptr = skipLEBNumber<int32_t>(Ptr, End);
        break;
      case BR_TABLE: {
        uint32_t NumTargets = 0;
        Ptr = readSafeLEBNumber(Ptr, NumTargets);
        for (uint32_t I = 0; I <= NumTargets; ++I) {
          Ptr = skipLEBNumber<uint32_t>(Ptr, End);
        }
        break;
      }
      case END: {
        BlockAddrCache[BlockStartPtrs[BlockDepth - 1]].EndPtr = Ptr - 1;
        if (--BlockDepth == 0) {
          auto &CacheValue = BlockAddrCache[BlockStartPtrs[0]];
          ElseAddr = CacheValue.ElsePtr;
          EndAddr = CacheValue.EndPtr;
          return;
        }
        break;
      }
      case DROP:
      case DROP_64:
      case SELECT:
      case SELECT_64:
        break;
      case GET_GLOBAL_64:
      case SET_GLOBAL_64: {
        Ptr = skipLEBNumber<uint32_t>(Ptr, End);
        break;
      }
      case GET_LOCAL:
      case SET_LOCAL:
      case TEE_LOCAL:
      case GET_GLOBAL:
      case SET_GLOBAL:
        Ptr = skipLEBNumber<uint32_t>(Ptr, End);
        break;
      case I32_CONST:
        Ptr = skipLEBNumber<int32_t>(Ptr, End);
        break;
      case I64_CONST:
        Ptr = skipLEBNumber<int64_t>(Ptr, End);
        break;
      case F32_CONST:
        Ptr += sizeof(float);
        break;
      case F64_CONST:
        Ptr += sizeof(double);
        break;
      case I32_EQZ:
      case I32_EQ:
      case I32_NE:
      case I32_LT_S:
      case I32_LT_U:
      case I32_GT_S:
      case I32_GT_U:
      case I32_LE_S:
      case I32_LE_U:
      case I32_GE_S:
      case I32_GE_U:
      case I64_EQZ:
      case I64_EQ:
      case I64_NE:
      case I64_LT_S:
      case I64_LT_U:
      case I64_GT_S:
      case I64_GT_U:
      case I64_LE_S:
      case I64_LE_U:
      case I64_GE_S:
      case I64_GE_U:
      case F32_EQ:
      case F32_NE:
      case F32_LT:
      case F32_GT:
      case F32_LE:
      case F32_GE:
      case F64_EQ:
      case F64_NE:
      case F64_LT:
      case F64_GT:
      case F64_LE:
      case F64_GE:
      case I32_CLZ:
      case I32_CTZ:
      case I32_POPCNT:
      case I32_ADD:
      case I32_SUB:
      case I32_MUL:
      case I32_DIV_S:
      case I32_DIV_U:
      case I32_REM_S:
      case I32_REM_U:
      case I32_AND:
      case I32_OR:
      case I32_XOR:
      case I32_SHL:
      case I32_SHR_S:
      case I32_SHR_U:
      case I32_ROTL:
      case I32_ROTR:
      case I64_CLZ:
      case I64_CTZ:
      case I64_POPCNT:
      case I64_ADD:
      case I64_SUB:
      case I64_MUL:
      case I64_DIV_S:
      case I64_DIV_U:
      case I64_REM_S:
      case I64_REM_U:
      case I64_AND:
      case I64_OR:
      case I64_XOR:
      case I64_SHL:
      case I64_SHR_S:
      case I64_SHR_U:
      case I64_ROTL:
      case I64_ROTR:
      case F32_ABS:
      case F32_NEG:
      case F32_CEIL:
      case F32_FLOOR:
      case F32_TRUNC:
      case F32_NEAREST:
      case F32_SQRT:
      case F32_ADD:
      case F32_SUB:
      case F32_MUL:
      case F32_DIV:
      case F32_MIN:
      case F32_MAX:
      case F32_COPYSIGN:
      case F64_ABS:
      case F64_NEG:
      case F64_CEIL:
      case F64_FLOOR:
      case F64_TRUNC:
      case F64_NEAREST:
      case F64_SQRT:
      case F64_ADD:
      case F64_SUB:
      case F64_MUL:
      case F64_DIV:
      case F64_MIN:
      case F64_MAX:
      case F64_COPYSIGN:
      case I32_WRAP_I64:
      case I32_TRUNC_S_F32:
      case I32_TRUNC_U_F32:
      case I32_TRUNC_S_F64:
      case I32_TRUNC_U_F64:
      case I64_EXTEND_S_I32:
      case I64_EXTEND_U_I32:
      case I64_TRUNC_S_F32:
      case I64_TRUNC_U_F32:
      case I64_TRUNC_S_F64:
      case I64_TRUNC_U_F64:
      case F32_CONVERT_S_I32:
      case F32_CONVERT_U_I32:
      case F32_CONVERT_S_I64:
      case F32_CONVERT_U_I64:
      case F32_DEMOTE_F64:
      case F64_CONVERT_S_I32:
      case F64_CONVERT_U_I32:
      case F64_CONVERT_S_I64:
      case F64_CONVERT_U_I64:
      case F64_PROMOTE_F32:
      case I32_REINTERPRET_F32:
      case I64_REINTERPRET_F64:
      case F32_REINTERPRET_I32:
      case F64_REINTERPRET_I64:
      case I32_EXTEND8_S:
      case I32_EXTEND16_S:
      case I64_EXTEND8_S:
      case I64_EXTEND16_S:
      case I64_EXTEND32_S:
        break;
      case I32_LOAD:
      case I64_LOAD:
      case F32_LOAD:
      case F64_LOAD:
      case I32_LOAD8_S:
      case I32_LOAD8_U:
      case I32_LOAD16_S:
      case I32_LOAD16_U:
      case I64_LOAD8_S:
      case I64_LOAD8_U:
      case I64_LOAD16_S:
      case I64_LOAD16_U:
      case I64_LOAD32_S:
      case I64_LOAD32_U:
      case I32_STORE:
      case I64_STORE:
      case F32_STORE:
      case F64_STORE:
      case I32_STORE8:
      case I32_STORE16:
      case I64_STORE8:
      case I64_STORE16:
      case I64_STORE32:
        Ptr = skipLEBNumber<uint32_t>(Ptr, End);
        Ptr = skipLEBNumber<uint32_t>(Ptr, End);
        break;
      case MEMORY_SIZE:
      case MEMORY_GROW:
        Ptr = skipLEBNumber<uint32_t>(Ptr, End);
        break;
      case RETURN:
        break;
      case CALL: {
        Ptr = skipLEBNumber<uint32_t>(Ptr, End);
        break;
      }
      case CALL_INDIRECT: {
        Ptr = skipLEBNumber<uint32_t>(Ptr, End);
        Ptr++;
        break;
      }
      default:
        ZEN_LOG_ERROR("unimplemented opcode : {%d}", Opcode);
        ZEN_ASSERT_TODO();
        break;
      }
    }

    return;
  }

  void updateFrame(const uint8_t *&Ip, const uint8_t *&IpEnd,
                   InterpFrame *&Frame, uint32_t *&ValStackPtr,
                   BlockInfo *&ControlStackPtr, uint32_t *&LocalPtr,
                   FunctionInstance *&FuncInst, bool IsReturn);

  void syncFrame(const uint8_t *Ip, InterpFrame *&Frame, uint32_t *ValStackPtr,
                 BlockInfo *ControlStackPtr);

  void callFuncInst(FunctionInstance *FuncInstCallee,
                    InterpreterExecContext &Context, const uint8_t *&Ip,
                    const uint8_t *&IpEnd, InterpFrame *&Frame,
                    uint32_t *&ValStackPtr, BlockInfo *&ControlStackPtr,
                    uint32_t *&LocalPtr, FunctionInstance *&FuncInst);

  template <bool Sign, BinaryOperator Opr, typename SignedT, typename UnsignedT,
            typename WasmReturnType>
  WasmReturnType handleCheckedArithmeticImpl(WasmReturnType LHS,
                                             WasmReturnType RHS) {
    if constexpr (Sign && Opr == BinaryOperator::BO_ADD) {
      SignedT Result = 0;
      if (__builtin_add_overflow((SignedT)LHS, (SignedT)RHS, &Result)) {
        throw getError(ErrorCode::IntegerOverflow);
      }
      return static_cast<WasmReturnType>(Result);
    } else if constexpr (Sign && Opr == BinaryOperator::BO_SUB) {
      SignedT Result = 0;
      if (__builtin_sub_overflow((SignedT)LHS, (SignedT)RHS, &Result)) {
        throw getError(ErrorCode::IntegerOverflow);
      }
      return static_cast<WasmReturnType>(Result);
    } else if constexpr (Sign && Opr == BinaryOperator::BO_MUL) {
      SignedT Result = 0;
      if (__builtin_mul_overflow((SignedT)LHS, (SignedT)RHS, &Result)) {
        throw getError(ErrorCode::IntegerOverflow);
      }
      return static_cast<WasmReturnType>(Result);
    } else if constexpr (!Sign && Opr == BinaryOperator::BO_ADD) {
      UnsignedT Result = 0;
      if (__builtin_add_overflow((UnsignedT)LHS, (UnsignedT)RHS, &Result)) {
        throw getError(ErrorCode::IntegerOverflow);
      }
      return static_cast<WasmReturnType>((UnsignedT)Result);
    } else if constexpr (!Sign && Opr == BinaryOperator::BO_SUB) {
      UnsignedT Result = 0;
      if (__builtin_sub_overflow((UnsignedT)LHS, (UnsignedT)RHS, &Result)) {
        throw getError(ErrorCode::IntegerOverflow);
      }
      return static_cast<WasmReturnType>((UnsignedT)Result);
    } else if constexpr (!Sign && Opr == BinaryOperator::BO_MUL) {
      UnsignedT Result = 0;
      if (__builtin_mul_overflow((UnsignedT)LHS, (UnsignedT)RHS, &Result)) {
        throw getError(ErrorCode::IntegerOverflow);
      }
      return static_cast<WasmReturnType>((UnsignedT)Result);
    } else {
      // unreachable
      ZEN_ABORT();
    }
  }

  // return high 64bit of the 128bit result if success
  // otherwise raise integer overflow trap
  template <bool Sign, BinaryOperator Opr>
  int64_t handleCheckedI128ArithmeticImpl(int64_t LHSLo, int64_t LHSHi,
                                          int64_t RHSLo, int64_t RHSHi) {
    if constexpr (Sign && Opr == BinaryOperator::BO_ADD) {
      __int128_t LHS =
          (((__int128_t)LHSHi) << 64) + (__int128_t)((uint64_t)LHSLo);
      __int128_t RHS =
          (((__int128_t)RHSHi) << 64) + (__int128_t)((uint64_t)RHSLo);
      __int128_t Result = 0;
      if (__builtin_add_overflow(LHS, RHS, &Result)) {
        throw getError(ErrorCode::IntegerOverflow);
      }
      return static_cast<int64_t>(Result >> 64);
    } else if constexpr (Sign && Opr == BinaryOperator::BO_SUB) {
      __int128_t LHS =
          (((__int128_t)LHSHi) << 64) + (__int128_t)((uint64_t)LHSLo);
      __int128_t RHS =
          (((__int128_t)RHSHi) << 64) + (__int128_t)((uint64_t)RHSLo);
      __int128_t Result = 0;
      if (__builtin_sub_overflow(LHS, RHS, &Result)) {
        throw getError(ErrorCode::IntegerOverflow);
      }
      return static_cast<int64_t>(Result >> 64);
    } else if constexpr (!Sign && Opr == BinaryOperator::BO_ADD) {
      __uint128_t LHS =
          (((__uint128_t)((uint64_t)LHSHi)) << 64) + (uint64_t)LHSLo;
      __uint128_t RHS =
          (((__uint128_t)((uint64_t)RHSHi)) << 64) + (uint64_t)RHSLo;
      __uint128_t Result = 0;
      if (__builtin_add_overflow(LHS, RHS, &Result)) {
        throw getError(ErrorCode::IntegerOverflow);
      }
      return static_cast<int64_t>(Result >> 64);
    } else if constexpr (!Sign && Opr == BinaryOperator::BO_SUB) {
      __uint128_t LHS =
          (((__uint128_t)((uint64_t)LHSHi)) << 64) + (uint64_t)LHSLo;
      __uint128_t RHS =
          (((__uint128_t)((uint64_t)RHSHi)) << 64) + (uint64_t)RHSLo;
      __uint128_t Result = 0;
      if (__builtin_sub_overflow(LHS, RHS, &Result)) {
        throw getError(ErrorCode::IntegerOverflow);
      }
      return static_cast<int64_t>(Result >> 64);
    } else {
      // unreachable
      ZEN_ABORT();
    }
  }

  template <bool Sign, WASMType Type, BinaryOperator Opr>
  void handleCheckedArithmetic() {
    InterpFrame *Frame = Context.getCurFrame();
    uint32_t *&ValStackPtr = Frame->ValueStackPtr; // must be reference
    if constexpr (Type == WASMType::I8) {
      auto RHS = Frame->valuePop<int32_t>(ValStackPtr);
      auto LHS = Frame->valuePop<int32_t>(ValStackPtr);
      auto Res =
          handleCheckedArithmeticImpl<Sign, Opr, int8_t, uint8_t, int32_t>(LHS,
                                                                           RHS);
      Frame->valuePush<int32_t>(ValStackPtr, Res);
    } else if constexpr (Type == WASMType::I16) {
      auto RHS = Frame->valuePop<int32_t>(ValStackPtr);
      auto LHS = Frame->valuePop<int32_t>(ValStackPtr);
      auto Res =
          handleCheckedArithmeticImpl<Sign, Opr, int16_t, uint16_t, int32_t>(
              LHS, RHS);
      Frame->valuePush<int32_t>(ValStackPtr, Res);
    } else if constexpr (Type == WASMType::I32) {
      auto RHS = Frame->valuePop<int32_t>(ValStackPtr);
      auto LHS = Frame->valuePop<int32_t>(ValStackPtr);
      auto Res =
          handleCheckedArithmeticImpl<Sign, Opr, int32_t, uint32_t, int32_t>(
              LHS, RHS);
      Frame->valuePush<int32_t>(ValStackPtr, Res);
    } else if constexpr (Type == WASMType::I64) {
      auto RHS = Frame->valuePop<int64_t>(ValStackPtr);
      auto LHS = Frame->valuePop<int64_t>(ValStackPtr);
      auto Res =
          handleCheckedArithmeticImpl<Sign, Opr, int64_t, uint64_t, int64_t>(
              LHS, RHS);
      Frame->valuePush<int64_t>(ValStackPtr, Res);
    } else {
      ZEN_ABORT();
    }
  }

  template <bool Sign, BinaryOperator Opr> void handleCheckedI128Arithmetic() {
    InterpFrame *Frame = Context.getCurFrame();
    uint32_t *&ValStackPtr = Frame->ValueStackPtr; // must use reference
    auto RHSHi = Frame->valuePop<int64_t>(ValStackPtr);
    auto RHSLo = Frame->valuePop<int64_t>(ValStackPtr);
    auto LHSHi = Frame->valuePop<int64_t>(ValStackPtr);
    auto LHSLo = Frame->valuePop<int64_t>(ValStackPtr);
    auto Res =
        handleCheckedI128ArithmeticImpl<Sign, Opr>(LHSLo, LHSHi, RHSLo, RHSHi);
    Frame->valuePush<int64_t>(ValStackPtr, Res);
  }

  template <typename T, BinaryOperator Op>
  void binaryOpMath(InterpFrame *Frame, uint32_t *&ValStackPtr) {
    T Val = Frame->valuePop<T>(ValStackPtr);
    switch (Op) {
    case BM_SQRT:
      Frame->valuePush<T>(ValStackPtr, CanonNaN(std::sqrt(Val)));
      break;
    case BM_FLOOR:
      Frame->valuePush<T>(ValStackPtr, CanonNaN(std::floor(Val)));
      break;
    case BM_CEIL:
      Frame->valuePush<T>(ValStackPtr, CanonNaN(std::ceil(Val)));
      break;
    case BM_TRUNC:
      Frame->valuePush<T>(ValStackPtr, CanonNaN(std::trunc(Val)));
      break;
    case BM_NEAREST:
      Frame->valuePush<T>(ValStackPtr, CanonNaN(std::rint(Val)));
      break;
    case BM_ABS:
      Frame->valuePush<T>(ValStackPtr, std::fabs(Val));
      break;
    case BM_NEG_F32: {
      uint32_t U32;
      std::memcpy(&U32, &Val, sizeof(uint32_t));
      uint32_t SignBit = U32 & (((uint32_t)1) << 31);
      if (SignBit) {
        Frame->valuePush<uint32_t>(ValStackPtr, U32 & ~((uint32_t)1 << 31));
      } else {
        Frame->valuePush<uint32_t>(ValStackPtr, U32 | ((uint32_t)1 << 31));
      }
      break;
    }
    case BM_NEG_F64: {
      uint64_t U64;
      std::memcpy(&U64, &Val, sizeof(uint64_t));
      uint64_t SignBit64 = U64 & (((uint64_t)1) << 63);
      if (SignBit64) {
        Frame->valuePush<uint64_t>(ValStackPtr, U64 & ~((uint64_t)1 << 63));
      } else {
        Frame->valuePush<uint64_t>(ValStackPtr, U64 | ((uint64_t)1 << 63));
      }
      break;
    }
    }
    return;
  }

  template <typename DstType, typename SrcType>
  void binaryOpCV(InterpFrame *Frame, uint32_t *&ValStackPtr) {
    SrcType Val = Frame->valuePop<DstType>(ValStackPtr);
    Frame->valuePush<DstType>(ValStackPtr, Val);
    return;
  }

  template <typename T>
  void binaryOpNEZ(InterpFrame *Frame, uint32_t *&ValStackPtr) {
    T Val = Frame->valuePop<T>(ValStackPtr);
    Frame->valuePush<int32_t>(ValStackPtr, Val == 0);
  }

  template <typename T, BinaryOperator Op>
  void binaryOpCount(InterpFrame *Frame, uint32_t *&ValStackPtr) {
    T Val = Frame->valuePop<T>(ValStackPtr);
    uint32_t Num = 0;
    uint32_t TypeBitNum = sizeof(T) << 3;
    // #if defined(__GNUC__)
    //         switch (op) {
    //             case BC_CLZ:
    //                 num = Val == 0             ? type_bit_num
    //                       : type_bit_num == 32 ? __builtin_clz(Val)
    //                                            : __builtin_clzl(Val);
    //                 break;
    //             case BC_CTZ:
    //                 num = Val == 0             ? type_bit_num
    //                       : type_bit_num == 32 ? __builtin_ctz(Val)
    //                                            : __builtin_ctzl(Val);
    //                 break;
    //             case BC_POP_COUNT_I32:
    //                 num = __builtin_popcount(Val);
    //                 break;
    //             case BC_POP_COUNT_I64:
    //                 num = __builtin_popcountl(Val);
    //                 break;
    //             default:
    //                 ZEN_ABORT();
    //         }
    //         frame->valuePush<T>(StackPtr, num);
    // #else
    switch (Op) {
    case BC_CLZ: {
      std::bitset<64> ValBits(Val);
      if (ValBits.none()) {
        Num = TypeBitNum;
      } else {
        uint32_t Idx = (TypeBitNum - 1);
        while (!ValBits.test(Idx)) {
          Num++;
          Idx--;
        }
      }
      Frame->valuePush<T>(ValStackPtr, Num);
      break;
    }
    case BC_CTZ: {
      std::bitset<64> ValBits(Val);
      if (ValBits.none()) {
        Num = TypeBitNum;
      } else {
        uint32_t Idx = 0;
        while (!ValBits.test(Idx) && Idx <= TypeBitNum) {
          Num++;
          Idx++;
        }
      }
      Frame->valuePush<T>(ValStackPtr, Num);
      break;
    }
    case BC_POP_COUNT_I32:
      Frame->valuePush<T>(ValStackPtr, std::bitset<32>(Val).count());
      break;
    case BC_POP_COUNT_I64:
      Frame->valuePush<T>(ValStackPtr, std::bitset<64>(Val).count());
      break;
    default:
      ZEN_ABORT();
    }
    // #endif
  }

  template <typename T>
  void selectOp(InterpFrame *Frame, uint32_t *&ValStackPtr) {
    uint32_t Cond = Frame->valuePop<uint32_t>(ValStackPtr);
    T V1 = Frame->valuePop<T>(ValStackPtr);
    T V2 = Frame->valuePop<T>(ValStackPtr);
    if (Cond) {
      Frame->valuePush<T>(ValStackPtr, V2);
    } else {
      Frame->valuePush<T>(ValStackPtr, V1);
    }
  }

  template <typename T, BinaryOperator Op>
  void binaryOp(InterpFrame *Frame, uint32_t *&ValStackPtr) {
    T RHS = Frame->valuePop<T>(ValStackPtr);
    T LHS = Frame->valuePop<T>(ValStackPtr);

    auto Ret = BinaryOpHelper<T, Op>()(LHS, RHS);
    Frame->valuePush<decltype(Ret)>(ValStackPtr, Ret);
  }

  template <typename SrcType, typename DestType>
  void storeOp(MemoryInstance &Memory, const uint8_t *&Ip, const uint8_t *IpEnd,
               InterpFrame *Frame, uint32_t *&ValStackPtr,
               uint64_t LinearMemSize) {
    uint32_t Align, Offset;
    Ip = readSafeLEBNumber(Ip, Align);
    Ip = readSafeLEBNumber(Ip, Offset);
    SrcType Val = Frame->valuePop<SrcType>(ValStackPtr);
    uint32_t Addr = Frame->valuePop<uint32_t>(ValStackPtr);
    if ((uint64_t)Offset + sizeof(DestType) + Addr > LinearMemSize) {
      throw getError(ErrorCode::OutOfBoundsMemory);
    }
    uint8_t *Start = Memory.MemBase + Offset + Addr;
#ifdef ZEN_ENABLE_DEBUG_INTERP
    ZEN_LOG_DEBUG("StoreOp, addr: %d, offset: %d, value: %llu", Addr, Offset,
                  Val);
#endif
    *(DestType *)Start = Val;
  }

  template <typename DestType, typename SrcType>
  void loadOp(MemoryInstance &Memory, const uint8_t *&Ip, const uint8_t *IpEnd,
              InterpFrame *Frame, uint32_t *&ValStackPtr,
              uint64_t LinearMemSize) {
    uint32_t Align, Offset;
    Ip = readSafeLEBNumber(Ip, Align);
    Ip = readSafeLEBNumber(Ip, Offset);
    uint32_t Addr = Frame->valuePop<uint32_t>(ValStackPtr);
    if ((uint64_t)Offset + sizeof(SrcType) + Addr > LinearMemSize) {
      throw getError(ErrorCode::OutOfBoundsMemory);
    }
    uint8_t *Start = Memory.MemBase + Offset + Addr;
#ifdef ZEN_ENABLE_DEBUG_INTERP
    ZEN_LOG_DEBUG("LoadOp, addr: %d, offset: %d, value: %llu", Addr, Offset,
                  *(SrcType *)Start);
#endif
    Frame->valuePush<DestType>(ValStackPtr, *(SrcType *)Start);
  }

  template <typename TargetType, typename SrcType, bool IsSigned>
  void truncate(InterpFrame *Frame, uint32_t *&ValStackPtr) {
    static_assert(sizeof(TargetType) == 4 || sizeof(TargetType) == 8);
    auto Src = Frame->valuePop<SrcType>(ValStackPtr);
    if (std::isnan(Src)) {
      throw getError(ErrorCode::InvalidConversionToInteger);
    }
    auto Min = FloatAttr<SrcType>::template toIntMin<TargetType, IsSigned>();

    auto Max = FloatAttr<SrcType>::template toIntMax<TargetType, IsSigned>();
    if (Src <= Min || Src >= Max) {
      throw getError(ErrorCode::IntegerOverflow);
    }

    if (IsSigned) {
      Frame->valuePush<TargetType>(
          ValStackPtr, static_cast<TargetType>(static_cast<int64_t>(Src)));
    } else {
      Frame->valuePush<TargetType>(
          ValStackPtr, static_cast<TargetType>(static_cast<uint64_t>(Src)));
    }
  }

  template <typename TargetType, typename SrcType>
  void convert(InterpFrame *Frame, uint32_t *&ValStackPtr) {
    Frame->valuePush<TargetType>(
        ValStackPtr,
        static_cast<TargetType>(Frame->valuePop<SrcType>(ValStackPtr)));
  }
};

void BaseInterpreterImpl::updateFrame(
    const uint8_t *&Ip, const uint8_t *&IpEnd, InterpFrame *&Frame,
    uint32_t *&ValStackPtr, BlockInfo *&ControlStackPtr, uint32_t *&LocalPtr,
    FunctionInstance *&FuncInst, bool IsReturn) {
  // update frame
  Ip = Frame->Ip;
  IpEnd = Frame->FuncInst->CodePtr + Frame->FuncInst->CodeSize;
  ValStackPtr = Frame->ValueStackPtr;
  if (IsReturn) {
    ValStackPtr -= FuncInst->NumParamCells;
    ValStackPtr += FuncInst->NumReturnCells;
  }
  ControlStackPtr = Frame->CtrlStackPtr;

  LocalPtr = (uint32_t *)Frame->LocalPtr;
  FuncInst = Frame->FuncInst;
}

void BaseInterpreterImpl::syncFrame(const uint8_t *Ip, InterpFrame *&Frame,
                                    uint32_t *ValStackPtr,
                                    BlockInfo *ControlStackPtr) {
  Frame->Ip = Ip;
  Frame->ValueStackPtr = ValStackPtr;
  Frame->CtrlStackPtr = ControlStackPtr;
}

void BaseInterpreterImpl::callFuncInst(
    FunctionInstance *Callee, InterpreterExecContext &Context,
    const uint8_t *&Ip, const uint8_t *&IpEnd, InterpFrame *&Frame,
    uint32_t *&ValStackPtr, BlockInfo *&ControlStackPtr, uint32_t *&LocalPtr,
    FunctionInstance *&FuncInst) {

  ZEN_ASSERT(Callee != nullptr);
  if (Callee->Kind == FunctionKind::Native) {
    // Prepare slots to pass arguments
    int32_t ParamCount = Callee->NumParams;
    WASMType *ParamTypes = Callee->getParamTypes();
    std::vector<TypedValue> Args(ParamCount);

    for (int32_t I = ParamCount - 1; I >= 0; --I) {
      WASMType Type = ParamTypes[I];
      Args[I].Type = Type;
      UntypedValue &Value = Args[I].Value;
      switch (Type) {
      case WASMType::I32:
        Value.I32 = Frame->valuePop<int32_t>(ValStackPtr);
        break;
      case WASMType::I64:
        Value.I64 = Frame->valuePop<int64_t>(ValStackPtr);
        break;
      case WASMType::F32:
        Value.F32 = Frame->valuePop<float>(ValStackPtr);
        break;
      case WASMType::F64:
        Value.F64 = Frame->valuePop<double>(ValStackPtr);
        break;
      default:
        ZEN_ASSERT_TODO();
      }
    }

    // Prepare slots to receive the return values.
    size_t ReturnCount = Callee->NumReturns;
    std::vector<TypedValue> Result(ReturnCount);
    for (size_t I = 0; I < ReturnCount; ++I) {
      Result[I].Type = Callee->ReturnTypes[I];
    }

    Instance *Instance = Context.getInstance();
#ifdef ZEN_ENABLE_DWASM
    if (Instance->getStackCost() >= PresetReservedStackSize) {
      // check call stack depth between hostapi call
      throw getError(ErrorCode::DWasmCallStackExceed);
    }
    Instance->setInHostAPI(true);
#endif // ZEN_ENABLE_DWASM

    entrypoint::callNativeGeneral(
        Instance, GenericFunctionPointer(Callee->CodePtr), Args, Result,
        Instance->getRuntime()->getMemAllocator(), true);

#ifdef ZEN_ENABLE_DWASM
    Instance->setInHostAPI(false);
#endif // ZEN_ENABLE_DWASM

    const Error &Err = Instance->getError();
    if (!Err.isEmpty()) {
      throw Err;
    }

    // Extract and push the return values to the stack
    for (size_t I = 0; I < ReturnCount; I++) {
      UntypedValue &Value = Result[I].Value;
      switch (Result[I].Type) {
      case WASMType::I32:
        Frame->valuePush<int32_t>(ValStackPtr, Value.I32);
        break;
      case WASMType::I64:
        Frame->valuePush<int64_t>(ValStackPtr, Value.I64);
        break;
      case WASMType::F32:
        Frame->valuePush<float>(ValStackPtr, Value.F32);
        break;
      case WASMType::F64:
        Frame->valuePush<double>(ValStackPtr, Value.F64);
        break;
      default:
        ZEN_ASSERT_TODO();
      }
    }
  } else if (Callee->Kind == FunctionKind::ByteCode) {

    // sync frames
    syncFrame(Ip, Frame, ValStackPtr, ControlStackPtr);

    Frame = Context.allocFrame((FunctionInstance *)Callee,
                               ValStackPtr - Callee->NumParamCells);
    if (Frame == nullptr) {
      throw getError(ErrorCode::CallStackExhausted);
    }
    // update frame
    updateFrame(Ip, IpEnd, Frame, ValStackPtr, ControlStackPtr, LocalPtr,
                FuncInst, false);

    // init local vars
    std::memset(LocalPtr + FuncInst->NumParamCells, 0,
                ((uint32_t)FuncInst->NumLocalCells) << 2);

    Frame->blockPush(ControlStackPtr, IpEnd - 1, ValStackPtr,
                     FuncInst->NumReturnCells, LABEL_FUNCTION);
  } else {
    ZEN_ASSERT_TODO();
  }
}

void BaseInterpreterImpl::interpret() {
#define DIRECT_DISPATCH 0
#if !DIRECT_DISPATCH
#define SWITCH(Ip) switch (Opcode = *Ip++)
#define CASE(Op) case Op
#define DEFAULT default
#ifdef ZEN_ENABLE_DEBUG_INTERP
#define BREAK                                                                  \
  ZEN_LOG_DEBUG("opcode: %s", getOpcodeString(Opcode));                        \
  break
#else
#define BREAK break
#endif // ZEN_ENABLE_DEBUG_INTERP
#else  // TODO
#define SWITCH(Ip) switch (Opcode = *Ip++)
#define CASE(Op) case Op
#define DEFAULT default
#define BREAK break
#endif
  InterpFrame *Frame = Context.getCurFrame();
  ZEN_ASSERT(Frame != nullptr);
  const uint8_t *Ip = Frame->Ip;
  const uint8_t *IpEnd = Ip + Frame->FuncInst->CodeSize;
  uint32_t *ValStackPtr = Frame->ValueStackPtr;
  BlockInfo *ControlStackPtr = Frame->CtrlStackPtr;
  uint32_t *LocalPtr = (uint32_t *)Frame->LocalPtr;
  FunctionInstance *FuncInst = Frame->FuncInst;
  Instance *ModInst = Context.getInstance();
  const Module *Mod = ModInst->getModule();
  MemoryInstance *Memory = nullptr;
  uint64_t LinearMemSize = 0;
  if (ModInst->hasMemory()) {
    Memory = &(ModInst->getDefaultMemoryInst());
    LinearMemSize = Memory->MemSize;
  }

  WASMType LocalType;
  uint32_t LocalOffset, LocalIdx, FuncIdx, GlobalIdx, Cond, Depth;
  const uint8_t *ElseAddr = nullptr;
  const uint8_t *EndAddr = nullptr;
  uint8_t Opcode;

  Frame->blockPush(ControlStackPtr, IpEnd - 1, ValStackPtr,
                   FuncInst->NumReturnCells, LABEL_FUNCTION);

  // process starting imported function
  if (FuncInst->Kind == FunctionKind::Native) {
    callFuncInst(FuncInst, Context, Ip, IpEnd, Frame, ValStackPtr,
                 ControlStackPtr, LocalPtr,
                 FuncInst); // the last arg is useless
    return;
  }

  while (Ip < IpEnd) {
    SWITCH(Ip) {
      CASE(UNREACHABLE) : { throw getError(ErrorCode::Unreachable); }
      CASE(NOP) : { BREAK; }
      CASE(SELECT) : {
        selectOp<int32_t>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(SELECT_64) : {
        selectOp<int64_t>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(BLOCK) : {
        uint32_t CellNum = getWASMTypeCellNumFromOpcode(*Ip++);

        findBlockAddr(Ip, IpEnd, ElseAddr, EndAddr);
        Frame->blockPush(ControlStackPtr, EndAddr, ValStackPtr, CellNum,
                         LABEL_BLOCK);
        BREAK;
      }
      CASE(LOOP) : {
        uint32_t CellNum = getWASMTypeCellNumFromOpcode(*Ip++);
        Frame->blockPush(ControlStackPtr, Ip, ValStackPtr, CellNum, LABEL_LOOP);
        BREAK;
      }
      CASE(BR) : {
        Ip = readSafeLEBNumber(Ip, Depth);
        Frame->blockPop(ControlStackPtr, ValStackPtr, Ip, Depth);
        BREAK;
      }
      CASE(BR_IF) : {
        Ip = readSafeLEBNumber(Ip, Depth);
        Cond = Frame->valuePop<int32_t>(ValStackPtr);
        if (Cond) {
          Frame->blockPop(ControlStackPtr, ValStackPtr, Ip, Depth);
        }
        BREAK;
      }
      CASE(BR_TABLE) : {
        uint32_t Count;
        Ip = readSafeLEBNumber(Ip, Count);
        uint32_t LabelIdx =
            std::min(Count, Frame->valuePop<uint32_t>(ValStackPtr));
        for (uint32_t I = 0; I < LabelIdx; I++) {
          Ip = skipLEBNumber<uint8_t>(Ip, IpEnd);
        }
        Ip = readSafeLEBNumber(Ip, Depth);
        Frame->blockPop(ControlStackPtr, ValStackPtr, Ip, Depth);
        BREAK;
      }
      CASE(DROP) : {
        Frame->valuePop<int32_t>(ValStackPtr);
        BREAK;
      }
      CASE(DROP_64) : {
        Frame->valuePop<int64_t>(ValStackPtr);
        BREAK;
      }
      CASE(IF) : {
        uint32_t CellNum = getWASMTypeCellNumFromOpcode(*Ip++);

        Cond = Frame->valuePop<int32_t>(ValStackPtr);
        findBlockAddr(Ip, IpEnd, ElseAddr, EndAddr);
        if (Cond) {
          Frame->blockPush(ControlStackPtr, EndAddr, ValStackPtr, CellNum,
                           LABEL_IF);
        } else {
          if (ElseAddr == nullptr) {
            Ip = EndAddr + 1;
          } else {
            Frame->blockPush(ControlStackPtr, EndAddr, ValStackPtr, CellNum,
                             LABEL_IF);
            Ip = ElseAddr + 1;
          }
        }
        BREAK;
      }
      CASE(ELSE) : {
        Ip = (ControlStackPtr - 1)->TargetAddr;
        BREAK;
      }
      CASE(GET_GLOBAL_64) : {
        Ip = readSafeLEBNumber(Ip, GlobalIdx);
        uint8_t *GlobalAddr = ModInst->getGlobalAddr(GlobalIdx);
        Frame->valuePush<int64_t>(ValStackPtr, *(int64_t *)GlobalAddr);
        BREAK;
      }
      CASE(SET_GLOBAL_64) : {
        Ip = readSafeLEBNumber(Ip, GlobalIdx);
        uint8_t *GlobalAddr = ModInst->getGlobalAddr(GlobalIdx);
        *(int64_t *)GlobalAddr = Frame->valuePop<int64_t>(ValStackPtr);
        BREAK;
      }
      CASE(GET_LOCAL) : {
        Ip = readSafeLEBNumber(Ip, LocalIdx);
        LocalType = FuncInst->getLocalType(LocalIdx);
        LocalOffset = FuncInst->getLocalOffset(LocalIdx);

        switch (LocalType) {
        case WASMType::F32:
        case WASMType::I32:
          Frame->valuePush<int32_t>(
              ValStackPtr,
              Frame->valueGet<int32_t>(ValStackPtr, LocalPtr + LocalOffset));
          break;
        case WASMType::F64:
        case WASMType::I64:
          Frame->valuePush<int64_t>(
              ValStackPtr,
              Frame->valueGet<int64_t>(ValStackPtr, LocalPtr + LocalOffset));
          break;
        default:
          ZEN_ASSERT_TODO();
          break;
        }
        BREAK;
      }
      CASE(SET_LOCAL) : {
        Ip = readSafeLEBNumber(Ip, LocalIdx);
        LocalType = FuncInst->getLocalType(LocalIdx);
        LocalOffset = FuncInst->getLocalOffset(LocalIdx);

        switch (LocalType) {
        case WASMType::F32:
        case WASMType::I32:
          Frame->valueSet<int32_t>(ValStackPtr, LocalPtr + LocalOffset,
                                   Frame->valuePop<int32_t>(ValStackPtr));
          break;
        case WASMType::F64:
        case WASMType::I64:
          Frame->valueSet<int64_t>(ValStackPtr, LocalPtr + LocalOffset,
                                   Frame->valuePop<int64_t>(ValStackPtr));
          break;
        default:
          ZEN_ASSERT_TODO();
        }
        BREAK;
      }
      CASE(TEE_LOCAL) : {
        Ip = readSafeLEBNumber(Ip, LocalIdx);
        LocalType = FuncInst->getLocalType(LocalIdx);
        LocalOffset = FuncInst->getLocalOffset(LocalIdx);

        switch (LocalType) {
        case WASMType::F32:
        case WASMType::I32:
          Frame->valueSet<int32_t>(ValStackPtr, LocalPtr + LocalOffset,
                                   Frame->valuePeek<int32_t>(ValStackPtr));
          break;
        case WASMType::F64:
        case WASMType::I64:
          Frame->valueSet<int64_t>(ValStackPtr, LocalPtr + LocalOffset,
                                   Frame->valuePeek<int64_t>(ValStackPtr));
          break;
        default:
          ZEN_ASSERT_TODO();
        }
        BREAK;
      }
      CASE(GET_GLOBAL) : {
        Ip = readSafeLEBNumber(Ip, GlobalIdx);
        uint8_t *GlobalAddr = ModInst->getGlobalAddr(GlobalIdx);
        WASMType GlobalType = ModInst->getGlobalType(GlobalIdx);
        switch (GlobalType) {
        case WASMType::I32:
        case WASMType::F32:
          Frame->valuePush<int32_t>(ValStackPtr, *(int32_t *)GlobalAddr);
          break;
        case WASMType::I64:
        case WASMType::F64:
          Frame->valuePush<int64_t>(ValStackPtr, *(int64_t *)GlobalAddr);
          break;
        default:
          ZEN_ASSERT_TODO();
        }
        BREAK;
      }
      CASE(SET_GLOBAL) : {
        Ip = readSafeLEBNumber(Ip, GlobalIdx);
        uint8_t *GlobalAddr = ModInst->getGlobalAddr(GlobalIdx);
        WASMType GlobalType = ModInst->getGlobalType(GlobalIdx);
        switch (GlobalType) {
        case WASMType::I32:
        case WASMType::F32:
          *(int32_t *)GlobalAddr = Frame->valuePop<int32_t>(ValStackPtr);
          break;
        case WASMType::I64:
        case WASMType::F64:
          *(int64_t *)GlobalAddr = Frame->valuePop<int64_t>(ValStackPtr);
          break;
        default:
          ZEN_ASSERT_TODO();
        }
        BREAK;
      }
      CASE(F32_CONST) : {
        float F32Const;
        Ip = readFixedNumber(Ip, IpEnd, F32Const);
        Frame->valuePush<float>(ValStackPtr, F32Const);
        BREAK;
      }
      CASE(I32_CONST) : {
        int32_t I32Const;
        Ip = readSafeLEBNumber(Ip, I32Const);
        Frame->valuePush<int32_t>(ValStackPtr, I32Const);
        BREAK;
      }
      CASE(F64_CONST) : {
        double F64Const;
        Ip = readFixedNumber(Ip, IpEnd, F64Const);
        Frame->valuePush<double>(ValStackPtr, F64Const);
        BREAK;
      }
      CASE(I64_CONST) : {
        int64_t I64Const;
        Ip = readSafeLEBNumber(Ip, I64Const);
        Frame->valuePush<int64_t>(ValStackPtr, I64Const);
        BREAK;
      }
      CASE(MEMORY_GROW) : {
        Ip = readSafeLEBNumber(Ip, LocalIdx);
        uint32_t GrowOldPageCount = Memory->CurPages;
        uint32_t GrowPageCount = Frame->valuePop<uint32_t>(ValStackPtr);

        if (ModInst->growLinearMemory(0, GrowPageCount)) {
          Frame->valuePush<uint32_t>(ValStackPtr, GrowOldPageCount);
        } else {
          Frame->valuePush<int32_t>(ValStackPtr, -1);
        }
        LinearMemSize = Memory->MemSize;
        BREAK;
      }
      CASE(MEMORY_SIZE) : {
        Ip = readSafeLEBNumber(Ip, LocalIdx);
        Frame->valuePush(ValStackPtr, Memory->CurPages);
        BREAK;
      }
      CASE(F32_STORE) : CASE(I32_STORE) : {
        storeOp<uint32_t, uint32_t>(*Memory, Ip, IpEnd, Frame, ValStackPtr,
                                    LinearMemSize);
        BREAK;
      }
      CASE(F64_STORE) : CASE(I64_STORE) : {
        storeOp<uint64_t, uint64_t>(*Memory, Ip, IpEnd, Frame, ValStackPtr,
                                    LinearMemSize);
        BREAK;
      }
      CASE(I32_STORE8) : {
        storeOp<uint32_t, uint8_t>(*Memory, Ip, IpEnd, Frame, ValStackPtr,
                                   LinearMemSize);
        BREAK;
      }
      CASE(I32_STORE16) : {
        storeOp<uint32_t, uint16_t>(*Memory, Ip, IpEnd, Frame, ValStackPtr,
                                    LinearMemSize);
        BREAK;
      }
      CASE(I64_STORE8) : {
        storeOp<uint64_t, uint8_t>(*Memory, Ip, IpEnd, Frame, ValStackPtr,
                                   LinearMemSize);
        BREAK;
      }
      CASE(I64_STORE16) : {
        storeOp<uint64_t, uint16_t>(*Memory, Ip, IpEnd, Frame, ValStackPtr,
                                    LinearMemSize);
        BREAK;
      }
      CASE(I64_STORE32) : {
        storeOp<uint64_t, uint32_t>(*Memory, Ip, IpEnd, Frame, ValStackPtr,
                                    LinearMemSize);
        BREAK;
      }
      CASE(F32_LOAD) : CASE(I32_LOAD) : {
        loadOp<uint32_t, uint32_t>(*Memory, Ip, IpEnd, Frame, ValStackPtr,
                                   LinearMemSize);
        BREAK;
      }
      CASE(F64_LOAD) : CASE(I64_LOAD) : {
        loadOp<uint64_t, uint64_t>(*Memory, Ip, IpEnd, Frame, ValStackPtr,
                                   LinearMemSize);
        BREAK;
      }
      CASE(I32_LOAD8_S) : {
        loadOp<uint32_t, int8_t>(*Memory, Ip, IpEnd, Frame, ValStackPtr,
                                 LinearMemSize);
        BREAK;
      }
      CASE(I32_LOAD8_U) : {
        loadOp<uint32_t, uint8_t>(*Memory, Ip, IpEnd, Frame, ValStackPtr,
                                  LinearMemSize);
        BREAK;
      }
      CASE(I32_LOAD16_S) : {
        loadOp<uint32_t, int16_t>(*Memory, Ip, IpEnd, Frame, ValStackPtr,
                                  LinearMemSize);
        BREAK;
      }
      CASE(I32_LOAD16_U) : {
        loadOp<uint32_t, uint16_t>(*Memory, Ip, IpEnd, Frame, ValStackPtr,
                                   LinearMemSize);
        BREAK;
      }
      CASE(I64_LOAD8_S) : {
        loadOp<uint64_t, int8_t>(*Memory, Ip, IpEnd, Frame, ValStackPtr,
                                 LinearMemSize);
        BREAK;
      }
      CASE(I64_LOAD8_U) : {
        loadOp<uint64_t, uint8_t>(*Memory, Ip, IpEnd, Frame, ValStackPtr,
                                  LinearMemSize);
        BREAK;
      }
      CASE(I64_LOAD16_S) : {
        loadOp<uint64_t, int16_t>(*Memory, Ip, IpEnd, Frame, ValStackPtr,
                                  LinearMemSize);
        BREAK;
      }
      CASE(I64_LOAD16_U) : {
        loadOp<uint64_t, uint16_t>(*Memory, Ip, IpEnd, Frame, ValStackPtr,
                                   LinearMemSize);
        BREAK;
      }
      CASE(I64_LOAD32_S) : {
        loadOp<uint64_t, int32_t>(*Memory, Ip, IpEnd, Frame, ValStackPtr,
                                  LinearMemSize);
        BREAK;
      }
      CASE(I64_LOAD32_U) : {
        loadOp<uint64_t, uint32_t>(*Memory, Ip, IpEnd, Frame, ValStackPtr,
                                   LinearMemSize);
        BREAK;
      }
      CASE(I64_LT_U) : {
        binaryOp<uint64_t, BO_LT>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_EQZ) : {
        binaryOpNEZ<int32_t>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_EQ) : {
        binaryOp<int32_t, BO_EQ>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_NE) : {
        binaryOp<int32_t, BO_NE>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_NE) : {
        binaryOp<int64_t, BO_NE>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_NE) : {
        binaryOp<float, BO_NE>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_NE) : {
        binaryOp<double, BO_NE>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_LT_S) : {
        binaryOp<int32_t, BO_LT>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_LT_U) : {
        binaryOp<uint32_t, BO_LT>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_GT_S) : {
        binaryOp<int32_t, BO_GT>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_GT_U) : {
        binaryOp<uint32_t, BO_GT>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_LE_S) : {
        binaryOp<int32_t, BO_LE>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_LE_U) : {
        binaryOp<uint32_t, BO_LE>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_GE_S) : {
        binaryOp<int32_t, BO_GE>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_GE_U) : {
        binaryOp<uint32_t, BO_GE>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_EQZ) : {
        binaryOpNEZ<int64_t>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_EQ) : {
        binaryOp<int64_t, BO_EQ>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_LT_S) : {
        binaryOp<int64_t, BO_LT>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_GT_S) : {
        binaryOp<int64_t, BO_GT>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_GT_U) : {
        binaryOp<uint64_t, BO_GT>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_LE_S) : {
        binaryOp<int64_t, BO_LE>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_LE_U) : {
        binaryOp<uint64_t, BO_LE>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_GE_S) : {
        binaryOp<int64_t, BO_GE>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_GE_U) : {
        binaryOp<uint64_t, BO_GE>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_EQ) : {
        binaryOp<float, BO_EQ>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_NEG) : {
        binaryOpMath<float, BM_NEG_F32>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_LT) : {
        binaryOp<float, BO_LT>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_GT) : {
        binaryOp<float, BO_GT>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_LE) : {
        binaryOp<float, BO_LE>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_GE) : {
        binaryOp<float, BO_GE>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_EQ) : {
        binaryOp<double, BO_EQ>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_NEG) : {
        binaryOpMath<double, BM_NEG_F64>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_LT) : {
        binaryOp<double, BO_LT>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_GT) : {
        binaryOp<double, BO_GT>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_LE) : {
        binaryOp<double, BO_LE>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_GE) : {
        binaryOp<double, BO_GE>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_CLZ) : {
        binaryOpCount<uint32_t, BC_CLZ>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_CTZ) : {
        binaryOpCount<uint32_t, BC_CTZ>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_POPCNT) : {
        binaryOpCount<uint32_t, BC_POP_COUNT_I32>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_ADD) : {
        binaryOp<int32_t, BO_ADD>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_SUB) : {
        binaryOp<int32_t, BO_SUB>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_MUL) : {
        binaryOp<int32_t, BO_MUL>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_DIV_S) : {
        binaryOp<int32_t, BO_DIV_S>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_DIV_U) : {
        binaryOp<uint32_t, BO_DIV>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_REM_S) : {
        binaryOp<int32_t, BO_REM_S>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_REM_U) : {
        binaryOp<uint32_t, BO_REM_U>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_AND) : {
        binaryOp<int32_t, BO_AND>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_OR) : {
        binaryOp<int32_t, BO_OR>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_XOR) : {
        binaryOp<int32_t, BO_XOR>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_SHL) : {
        binaryOp<int32_t, BO_SHL>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_SHR_S) : {
        binaryOp<int32_t, BO_SHR>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_SHR_U) : {
        binaryOp<uint32_t, BO_SHR>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_ROTL) : {
        binaryOp<uint32_t, BO_ROTL>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_ROTR) : {
        binaryOp<uint32_t, BO_ROTR>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_CLZ) : {
        binaryOpCount<uint64_t, BC_CLZ>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_CTZ) : {
        binaryOpCount<uint64_t, BC_CTZ>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_POPCNT) : {
        binaryOpCount<uint64_t, BC_POP_COUNT_I64>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_ADD) : {
        binaryOp<int64_t, BO_ADD>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_SUB) : {
        binaryOp<int64_t, BO_SUB>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_MUL) : {
        binaryOp<int64_t, BO_MUL>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_DIV_S) : {
        binaryOp<int64_t, BO_DIV_S>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_DIV_U) : {
        binaryOp<uint64_t, BO_DIV>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_REM_S) : {
        binaryOp<int64_t, BO_REM_S>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_REM_U) : {
        binaryOp<uint64_t, BO_REM_U>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_AND) : {
        binaryOp<int64_t, BO_AND>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_ABS) : {
        binaryOpMath<float, BM_ABS>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_CEIL) : {
        binaryOpMath<float, BM_CEIL>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_FLOOR) : {
        binaryOpMath<float, BM_FLOOR>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_TRUNC) : {
        binaryOpMath<float, BM_TRUNC>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_NEAREST) : {
        binaryOpMath<float, BM_NEAREST>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_SQRT) : {
        binaryOpMath<float, BM_SQRT>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_ADD) : {
        binaryOp<float, BO_ADD>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_SUB) : {
        binaryOp<float, BO_SUB>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_MUL) : {
        binaryOp<float, BO_MUL>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_DIV) : {
        binaryOp<float, BO_DIV>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_MIN) : {
        binaryOp<float, BO_MIN>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_MAX) : {
        binaryOp<float, BO_MAX>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_COPYSIGN) : {
        binaryOp<float, BO_COPYSIGN>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_ABS) : {
        binaryOpMath<double, BM_ABS>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_CEIL) : {
        binaryOpMath<double, BM_CEIL>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_FLOOR) : {
        binaryOpMath<double, BM_FLOOR>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_TRUNC) : {
        binaryOpMath<double, BM_TRUNC>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_NEAREST) : {
        binaryOpMath<double, BM_NEAREST>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_SQRT) : {
        binaryOpMath<double, BM_SQRT>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_ADD) : {
        binaryOp<double, BO_ADD>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_SUB) : {
        binaryOp<double, BO_SUB>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_MUL) : {
        binaryOp<double, BO_MUL>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_DIV) : {
        binaryOp<double, BO_DIV>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_MIN) : {
        binaryOp<double, BO_MIN>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_MAX) : {
        binaryOp<double, BO_MAX>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_COPYSIGN) : {
        binaryOp<double, BO_COPYSIGN>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_WRAP_I64) : {
        Frame->valuePush<int32_t>(
            ValStackPtr, Frame->valuePop<int64_t>(ValStackPtr) & 0xFFFFFFFF);
        BREAK;
      }
      CASE(I32_TRUNC_S_F32) : {
        truncate<int32_t, float, true>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_TRUNC_U_F32) : {
        truncate<int32_t, float, false>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_TRUNC_S_F64) : {
        truncate<int32_t, double, true>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_TRUNC_U_F64) : {
        truncate<int32_t, double, false>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_EXTEND_S_I32) : {
        convert<int64_t, int32_t>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_EXTEND_U_I32) : {
        convert<int64_t, uint32_t>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_TRUNC_S_F32) : {
        truncate<int64_t, float, true>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_TRUNC_U_F32) : {
        truncate<int64_t, float, false>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_TRUNC_S_F64) : {
        truncate<int64_t, double, true>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_TRUNC_U_F64) : {
        truncate<int64_t, double, false>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_CONVERT_S_I32) : {
        convert<float, int32_t>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_CONVERT_U_I32) : {
        convert<float, uint32_t>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_CONVERT_S_I64) : {
        convert<float, int64_t>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_CONVERT_U_I64) : {
        convert<float, uint64_t>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F32_DEMOTE_F64) : {
        convert<float, double>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_CONVERT_S_I32) : {
        convert<double, int32_t>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_CONVERT_U_I32) : {
        convert<double, uint32_t>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_CONVERT_S_I64) : {
        convert<double, int64_t>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_CONVERT_U_I64) : {
        convert<double, uint64_t>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(F64_PROMOTE_F32) : {
        convert<double, float>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_REINTERPRET_F32)
          : CASE(I64_REINTERPRET_F64)
          : CASE(F32_REINTERPRET_I32) : CASE(F64_REINTERPRET_I64) : {
        BREAK;
      }
      CASE(I32_EXTEND8_S) : {
        binaryOpCV<int32_t, int8_t>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_EXTEND8_S) : {
        binaryOpCV<int64_t, int8_t>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I32_EXTEND16_S) : {
        binaryOpCV<int32_t, int16_t>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_EXTEND16_S) : {
        binaryOpCV<int64_t, int16_t>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_EXTEND32_S) : {
        binaryOpCV<int64_t, int32_t>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_OR) : {
        binaryOp<int64_t, BO_OR>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_XOR) : {
        binaryOp<int64_t, BO_XOR>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_SHL) : {
        binaryOp<int64_t, BO_SHL>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_SHR_S) : {
        binaryOp<int64_t, BO_SHR>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_SHR_U) : {
        binaryOp<uint64_t, BO_SHR>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_ROTL) : {
        binaryOp<uint64_t, BO_ROTL>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(I64_ROTR) : {
        binaryOp<uint64_t, BO_ROTR>(Frame, ValStackPtr);
        BREAK;
      }
      CASE(RETURN) : {
        Context.freeFrame(FuncInst, Frame);
        InterpFrame *PrevFrame = Frame->PrevFrame;
        ValStackPtr -= (FuncInst->NumReturnCells);
        std::memcpy(LocalPtr, ValStackPtr, FuncInst->NumReturnCells << 2);
        if (PrevFrame == nullptr || !PrevFrame->Ip) {
          return;
        }
        Frame = PrevFrame;
        Context.setCurFrame(Frame);
        // update frame
        updateFrame(Ip, IpEnd, Frame, ValStackPtr, ControlStackPtr, LocalPtr,
                    FuncInst, true);
        BREAK;
      }
      CASE(CALL) : {
        Ip = readSafeLEBNumber(Ip, FuncIdx);
#ifdef ZEN_ENABLE_DEBUG_INTERP
        ZEN_LOG_DEBUG("fidx: %d", FuncIdx);
#endif
        if (FuncIdx == Mod->getGasFuncIdx()) {
          uint64_t Delta = Frame->valuePop<uint64_t>(ValStackPtr);
          uint64_t GasLeft = ModInst->getGas();
          if (GasLeft < Delta) {
            ModInst->setGas(0);
            throw getError(ErrorCode::GasLimitExceeded);
          }
          ModInst->setGas(GasLeft - Delta);

          BREAK;
        }
#ifdef ZEN_ENABLE_CHECKED_ARITHMETIC
        Frame->ValueStackPtr = ValStackPtr;
#define HANDLE_CHECKED_ARITHMETIC_CALL_POSTHOOK                                \
  ValStackPtr = Frame->ValueStackPtr;

        HANDLE_CHECKED_ARITHMETIC_CALL(Mod, FuncIdx)
#undef HANDLE_CHECKED_ARITHMETIC_CALL_POSTHOOK
#endif // ZEN_ENABLE_CHECKED_ARITHMETIC

        FunctionInstance *FuncInstCallee = ModInst->getFunctionInst(FuncIdx);
        callFuncInst(FuncInstCallee, Context, Ip, IpEnd, Frame, ValStackPtr,
                     ControlStackPtr, LocalPtr, FuncInst);
        BREAK;
      }
      CASE(CALL_INDIRECT) : {

        uint32_t TypeIdx = 0, TableIdx = 0;
        Ip = readSafeLEBNumber(Ip, TypeIdx);
        // Skip the fixed byte for `table 0`
        ++Ip;
        auto *ExpectedFuncType = Mod->getDeclaredType(TypeIdx);

        int32_t IndirectFuncIdx = Frame->valuePop<int32_t>(ValStackPtr);
        TableInstance *Table = ModInst->getTableInst(TableIdx);
        if (IndirectFuncIdx < 0 ||
            (uint32_t)IndirectFuncIdx >= Table->CurSize) {
          throw getError(ErrorCode::UndefinedElement);
        }
        FuncIdx = Table->Elements[IndirectFuncIdx];
#ifdef ZEN_ENABLE_DEBUG_INTERP
        ZEN_LOG_DEBUG("fidx: %d", FuncIdx);
#endif
        if (FuncIdx == (uint32_t)-1) {
          throw getError(ErrorCode::UninitializedElement);
        }
        auto *FuncInstCallee = ModInst->getFunctionInst(FuncIdx);
        ZEN_ASSERT(FuncInstCallee);
        auto *ActualFuncType = FuncInstCallee->FuncType;
        if (!TypeEntry::isEqual(ActualFuncType, ExpectedFuncType)) {
          throw getError(ErrorCode::IndirectCallTypeMismatch);
        }
        callFuncInst(FuncInstCallee, Context, Ip, IpEnd, Frame, ValStackPtr,
                     ControlStackPtr, LocalPtr, FuncInst);
        BREAK;
      }
      CASE(END) : {
        if (ControlStackPtr > Frame->CtrlBasePtr + 1) {
          Frame->blockPop(ControlStackPtr);
        } else {
          // return
          Context.freeFrame(FuncInst, Frame);
          InterpFrame *PrevFrame = Frame->PrevFrame;
          ValStackPtr -= (FuncInst->NumReturnCells);
          // copy return value to value stack of prev_frame, frame may
          // be overwrited
          std::memcpy(LocalPtr, ValStackPtr, FuncInst->NumReturnCells << 2);
          Frame = PrevFrame;
          Context.setCurFrame(Frame);

          if (Frame == nullptr) {
            BREAK;
          }

          // update frame
          updateFrame(Ip, IpEnd, Frame, ValStackPtr, ControlStackPtr, LocalPtr,
                      FuncInst, true);
        }
        BREAK;
      }
    DEFAULT : {
      ZEN_LOG_ERROR("munimplemented opcode: 0x%x", Opcode);
      ZEN_ASSERT_TODO();
    }
    }
    // TODO: write back ValueStackPtr, Ip, CtrlStackPtr to Frame
  }
}

void BaseInterpreter::interpret() {
  BaseInterpreterImpl Impl(Context);
  Impl.interpret();
}

} // namespace zen::action
