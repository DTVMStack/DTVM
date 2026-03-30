// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_COMPILER_COMPILER_H
#define ZEN_COMPILER_COMPILER_H

#include "compiler/common/common_defs.h"
#include "compiler/stub/stub_builder.h"

namespace COMPILER {

class CompileContext;
class CompilerPassTimingSession;
class WasmFrontendContext;
class MModule;
class MFunction;
class CgFunction;

class JITCompilerBase : public NonCopyable {
protected:
  virtual ~JITCompilerBase() = default;

  static void compileMIRToCgIR(MModule &Mod, MFunction &MFunc,
                               CgFunction &CgFunc, bool DisableGreedyRA,
                               CompilerPassTimingSession *PassTiming = nullptr);
  static void emitObjectBuffer(CompileContext *Ctx);
};

class WasmJITCompiler : public JITCompilerBase {
protected:
  WasmJITCompiler(runtime::Module *WasmMod)
      : WasmMod(WasmMod),
        NumInternalFunctions(WasmMod->getNumInternalFunctions()),
        Config(WasmMod->getRuntime()->getConfig()),
        Stats(WasmMod->getRuntime()->getStatistics()) {}

  ~WasmJITCompiler() override = default;

  void compileWasmToMC(WasmFrontendContext &Ctx, MModule &Mod, uint32_t FuncIdx,
                       bool DisableGreedyRA);

  runtime::Module *WasmMod;
  const uint32_t NumInternalFunctions;
  const runtime::RuntimeConfig &Config;
  utils::Statistics &Stats;
};

class EagerJITCompiler final : public WasmJITCompiler {
public:
  EagerJITCompiler(runtime::Module *WasmMod) : WasmJITCompiler(WasmMod) {}

  ~EagerJITCompiler() override = default;

  void compile();
};

class LazyJITCompiler final : public WasmJITCompiler {
public:
  LazyJITCompiler(runtime::Module *WasmMod);

  ~LazyJITCompiler() override;

  void dispatchCompileTask(uint32_t FuncIdx);

  void dispatchCompileTasksDepthFirst(WasmFrontendContext &Ctx);

  void dispatchCompileTasksInOrder(WasmFrontendContext &Ctx);

  void dispatchEntryCompileTasks(WasmFrontendContext &Ctx);

  void precompile();

  uint8_t *compileFunction(WasmFrontendContext &Ctx, uint32_t FuncIdx,
                           bool DisableGreedyRA);

  void compileFunctionInBackgroud(WasmFrontendContext &Ctx, uint32_t FuncIdx);

  uint8_t *compileFunctionOnRequest(uint8_t *FuncStubCodePtr);

private:
  enum class CompileStatus : uint8_t {
    None,
    Pending,
    InProgress,
    Done,
  };

  JITStubBuilder StubBuilder;
  WasmFrontendContext *MainContext;
  MModule *Mod;

  // These four fields are only used in multithread lazy compilation mode
  std::vector<WasmFrontendContext> AuxContexts;
  // must be declared before ThreadPool
  std::unique_ptr<std::atomic<CompileStatus>[]> CompileStatuses;
  // must be declared before ThreadPool
  std::unique_ptr<std::atomic<uint8_t *>[]> GreedyRACodePtrs;
  std::unique_ptr<common::ThreadPool<WasmFrontendContext>> ThreadPool;
};

class MIRTextJITCompiler final : public JITCompilerBase {
public:
  MIRTextJITCompiler() = default;

  ~MIRTextJITCompiler() override = default;

  std::pair<std::unique_ptr<MModule>, std::vector<void *>>
  compile(CompileContext &Context, const char *Ptr, size_t Size);
};

} // namespace COMPILER

#endif // ZEN_COMPILER_COMPILER_H
