// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "action/compiler.h"
#include "common/enums.h"

#ifdef ZEN_ENABLE_SINGLEPASS_JIT
#include "singlepass/singlepass.h"
#endif
#ifdef ZEN_ENABLE_MULTIPASS_JIT
#include "compiler/compiler.h"
#include "compiler/evm_compiler.h"
#endif

namespace zen::action {

void performJITCompile(runtime::Module &Mod) {
  switch (Mod.getRuntime()->getConfig().Mode) {
#ifdef ZEN_ENABLE_SINGLEPASS_JIT
  case common::RunMode::SinglepassMode: {
    singlepass::JITCompiler::compile(&Mod);
    break;
  }
#endif
#ifdef ZEN_ENABLE_MULTIPASS_JIT
  case common::RunMode::MultipassMode: {
    if (Mod.getRuntime()->getConfig().EnableMultipassLazy) {
      auto *LCompiler = Mod.newLazyJITCompiler();
      LCompiler->precompile();
    } else {
      COMPILER::EagerJITCompiler ECompiler(&Mod);
      ECompiler.compile();
    }
    break;
  }
#endif
  default:
    break;
  }
}

void performEVMJITCompile(runtime::EVMModule &Mod) {
  switch (Mod.getRuntime()->getConfig().Mode) {
#ifdef ZEN_ENABLE_SINGLEPASS_JIT
  case common::RunMode::SinglepassMode: {
    // TODO: Implement singlepass JIT for EVM
    ZEN_ASSERT_TODO();
    break;
  }
#endif
#ifdef ZEN_ENABLE_MULTIPASS_JIT
  case common::RunMode::MultipassMode: {
    if (Mod.getRuntime()->getConfig().EnableMultipassLazy) {
      auto *LCompiler = Mod.newLazyEVMJITCompiler();
      LCompiler->precompile();
    } else {
      COMPILER::EagerEVMJITCompiler ECompiler(&Mod);
      ECompiler.compile();
    }
    break;
  }
#endif
  default:
    break;
  }
}

} // namespace zen::action
