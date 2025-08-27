// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/evm_compiler.h"
#include "compiler/cgir/cg_function.h"
#include "compiler/mir/module.h"

#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
#include "llvm/Support/Debug.h"
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
#include "llvm/ADT/SmallVector.h"

namespace COMPILER {

void EVMJITCompiler::compileEVMToMC(EVMFrontendContext &Ctx, MModule &Mod,
                                    uint32_t FuncIdx, bool DisableGreedyRA) {
  if (Ctx.Inited) {
    // Release all memory allocated by previous function compilation
    Ctx.MemPool = CompileMemPool();
    if (Ctx.Lazy) {
      Ctx.reinitialize();
    }
  } else {
    Ctx.initialize();
  }

  // Create MFunction for EVM bytecode compilation
  MFunction MFunc(Ctx, FuncIdx);
  CgFunction CgFunc(Ctx, MFunc);

  // Set up EVM MIR builder
  EVMMirBuilder MIRBuilder(Ctx, MFunc);

  // Set bytecode for compilation
  MFunc.setFunctionType(Mod.getFuncType(FuncIdx));

  // Compile EVM bytecode to MIR
  MIRBuilder.compile(&Ctx);

#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  llvm::DebugFlag = true;
  llvm::dbgs() << "\n########## EVM MIR Dump ##########\n\n";
  MFunc.dump();
#endif

  // Apply MIR optimizations and generate machine code
  // compileMIRToCgIR(Mod, MFunc, CgFunc, DisableGreedyRA);

  // Generate machine code
  // Ctx.getMCLowering().runOnCgFunction(CgFunc);
}

void EagerEVMJITCompiler::compile() {
  EVMFrontendContext Ctx;
  Ctx.setBytecode(reinterpret_cast<const Byte *>(EVMMod->Code),
                  EVMMod->CodeSize);

  // Create MModule for EVM
  MModule Mod(Ctx);

  // Create function type for EVM (only one func in EVM)
  MType *VoidType = &Ctx.VoidType;
  MType *I64Type = &Ctx.I64Type;
  llvm::SmallVector<MType *, 1> Params = {I64Type};
  MFunctionType *FuncType = MFunctionType::create(Ctx, *VoidType, Params);
  Mod.addFuncType(FuncType);

  // Compile the EVM bytecode to MIR and then to machine code
  // 0: func index(only one func in EVM)
  compileEVMToMC(Ctx, Mod, 0, Config.DisableMultipassGreedyRA);
}
} // namespace COMPILER
