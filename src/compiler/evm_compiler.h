// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_EVM_COMPILER_COMPILER_H
#define ZEN_EVM_COMPILER_COMPILER_H

#include "compiler/compiler.h"
#include "compiler/evm_frontend/evm_mir_compiler.h"
#include "runtime/evm_module.h"

namespace COMPILER {

class EVMJITCompiler : public JITCompilerBase {
protected:
  EVMJITCompiler(runtime::EVMModule *EVMMod)
      : EVMMod(EVMMod), Config(EVMMod->getRuntime()->getConfig()),
        Stats(EVMMod->getRuntime()->getStatistics()) {}

  ~EVMJITCompiler() override = default;

  void compileEVMToMC(EVMFrontendContext &Ctx, MModule &Mod, uint32_t FuncIdx,
                      bool DisableGreedyRA);

  runtime::EVMModule *EVMMod;
  const runtime::RuntimeConfig &Config;
  utils::Statistics &Stats;
};

class EagerEVMJITCompiler final : public EVMJITCompiler {
public:
  EagerEVMJITCompiler(runtime::EVMModule *EVMMod) : EVMJITCompiler(EVMMod) {}

  ~EagerEVMJITCompiler() override = default;

  void compile();
};

class LazyEVMJITCompiler final : public EVMJITCompiler {
public:
  LazyEVMJITCompiler(runtime::EVMModule *EVMMod);

  ~LazyEVMJITCompiler() override;

  void precompile();

  uint8_t *compileFunction(EVMFrontendContext &Ctx, uint32_t FuncIdx,
                           bool DisableGreedyRA);

private:
  enum class CompileStatus : uint8_t {
    None,
    Pending,
    InProgress,
    Done,
  };

  JITStubBuilder StubBuilder;
  EVMFrontendContext *MainContext;
  MModule *Mod;

  // These four fields are only used in multithread lazy compilation mode
  std::vector<EVMFrontendContext> AuxContexts;
  std::unique_ptr<std::atomic<CompileStatus>[]> CompileStatuses;
  std::unique_ptr<std::atomic<uint8_t *>[]> GreedyRACodePtrs;
  std::unique_ptr<common::ThreadPool<EVMFrontendContext>> ThreadPool;
};

} // namespace COMPILER

#endif // ZEN_EVM_COMPILER_COMPILER_H
