// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/evm_compiler.h"
#include "compiler/cgir/cg_function.h"
#include "compiler/mir/module.h"

#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
#include "llvm/Support/Debug.h"
#endif
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
  ZEN_LOG_INFO("Starting eager compilation of EVM module");

  // Create EVM frontend context
  EVMFrontendContext Ctx;
  Ctx.setBytecode(reinterpret_cast<const Byte *>(EVMMod->Code),
                  EVMMod->CodeSize);

  // Create MModule for EVM
  MModule Mod(Ctx);

  // Create function type for EVM (single function for now)
  MType *VoidType = &Ctx.VoidType;
  MType *I64Type = &Ctx.I64Type;
  llvm::SmallVector<MType *, 1> Params = {I64Type};
  MFunctionType *FuncType = MFunctionType::create(Ctx, *VoidType, Params);
  Mod.addFuncType(FuncType);

  // Compile the EVM bytecode to MIR and then to machine code
  compileEVMToMC(Ctx, Mod, 0, Config.DisableMultipassGreedyRA);
}

LazyEVMJITCompiler::LazyEVMJITCompiler(runtime::EVMModule *EVMMod)
    : EVMJITCompiler(EVMMod), StubBuilder(EVMMod->getJITCodeMemPool()) {
  MainContext = new EVMFrontendContext;
  MainContext->Lazy = true;
  MainContext->CodeMPool = &EVMMod->getJITCodeMemPool();
  Mod = MainContext->ThreadMemPool.newObject<MModule>(*MainContext);

  const runtime::RuntimeConfig &Config = EVMMod->getRuntime()->getConfig();

  if (!Config.DisableMultipassMultithread) {
    ThreadPool = std::make_unique<common::ThreadPool<EVMFrontendContext>>(1);
    uint32_t NumThreads = ThreadPool->getThreadCount();
    ZEN_LOG_DEBUG("using %u threads for multipass JIT background compilation",
                  NumThreads);
    std::vector<EVMFrontendContext> Contexts(NumThreads, *MainContext);
    for (uint32_t I = 0; I < NumThreads; ++I) {
      ThreadPool->setThreadContext(I, &Contexts[I]);
    }
    AuxContexts = std::move(Contexts);
    CompileStatuses = std::make_unique<std::atomic<CompileStatus>[]>(1);
    GreedyRACodePtrs = std::make_unique<std::atomic<uint8_t *>[]>(1);
    for (uint32_t I = 0; I < 1; ++I) {
      CompileStatuses[I] = CompileStatus::None;
      GreedyRACodePtrs[I] = nullptr;
    }
  }
}

LazyEVMJITCompiler::~LazyEVMJITCompiler() {
  if (ThreadPool) {
    ThreadPool->interrupt();
  }
  MainContext->ThreadMemPool.deleteObject(Mod);
  delete MainContext;
}

void LazyEVMJITCompiler::precompile() {
  // TODO: Perform pre-compilation setup
  // 1. Initialize compile status arrays
  // 2. Set up function stubs
  // 3. Prepare compilation contexts

  ZEN_LOG_INFO("Performing EVM pre-compilation");
}

uint8_t *LazyEVMJITCompiler::compileFunction(EVMFrontendContext &Ctx,
                                             uint32_t FuncIdx,
                                             bool DisableGreedyRA) {
  ZEN_LOG_INFO("Compiling EVM function %u", FuncIdx);

  // Create MFunction for EVM bytecode compilation
  MFunction MFunc(Ctx, FuncIdx);
  CgFunction CgFunc(Ctx, MFunc);

  // Create MModule for EVM
  MModule Mod(Ctx);
  MType *VoidType = &Ctx.VoidType;
  MType *I64Type = &Ctx.I64Type;
  llvm::SmallVector<MType *, 1> Params = {I64Type};
  MFunctionType *FuncType = MFunctionType::create(Ctx, *VoidType, Params);
  Mod.addFuncType(FuncType);

  // Set up EVM MIR builder
  EVMMirBuilder MIRBuilder(Ctx, MFunc);
  MFunc.setFunctionType(Mod.getFuncType(0));

  Ctx.setBytecode(reinterpret_cast<const Byte *>(EVMMod->Code),
                  EVMMod->CodeSize);

  // Compile EVM bytecode to MIR
  MIRBuilder.compile(&Ctx);

#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  llvm::DebugFlag = true;
  llvm::dbgs() << "\n########## EVM MIR Dump (Function " << FuncIdx
               << ") ##########\n\n";
  MFunc.dump();
#endif

  // Apply MIR optimizations and generate machine code
  compileMIRToCgIR(Mod, MFunc, CgFunc, DisableGreedyRA);

  // For now, return stub address
  return reinterpret_cast<uint8_t *>(0xDEADBEEF);
}

} // namespace COMPILER
