// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/context.h"
#include "compiler/mir/function.h"
#include "compiler/mir/pointer.h"
#include "compiler/target/x86/x86_llvm_workaround.h"
#include "compiler/target/x86/x86_mc_lowering.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/Host.h"
#include "llvm/Target/TargetLoweringObjectFile.h"

using namespace COMPILER;

namespace llvm {
// NOLINTBEGIN(readability-identifier-naming)
extern "C" {
#ifdef ZEN_BUILD_TARGET_X86_64
void LLVMInitializeX86TargetInfo();
void LLVMInitializeX86Target();
void LLVMInitializeX86TargetMC();
#endif
}
// NOLINTEND(readability-identifier-naming)
} // namespace llvm

#ifdef ZEN_BUILD_TARGET_X86_64
static std::string getX86FeaturesStr() {
  static std::vector<std::string> RequiredFearures = {
      "64bit", "cmov", "cx8",  "cx16",  "fxsr",   "mmx",
      "sse",   "sse2", "sse3", "ssse3", "sse4.1",
  };
  static std::vector<std::string> OptionalFeatures = {
      "adx", "bmi", "bmi2", "lzcnt", "popcnt",
  };

  llvm::StringMap<bool> HostFeatures;
  if (!llvm::sys::getHostCPUFeatures(HostFeatures)) {
    throw getError(ErrorCode::TargetLookupFailed);
  }

  SubtargetFeatures Features;
  for (const auto &F : RequiredFearures) {
    const auto It = HostFeatures.find(F);
    if (It == HostFeatures.end() || !It->second) {
      throw getError(ErrorCode::TargetLookupFailed);
    }
    Features.AddFeature(F, true);
  }

  for (const auto &F : OptionalFeatures) {
    const auto It = HostFeatures.find(F);
    if (It != HostFeatures.end() && It->second) {
      Features.AddFeature(F, true);
    }
  }

  return Features.getString();
}
#endif

static std::string getCPUName() {
#ifdef ZEN_BUILD_TARGET_X86_64
  return "x86-64";
#else
#error "Unsupported target"
#endif
}

static std::string getFeaturesStr() {
#ifdef ZEN_BUILD_TARGET_X86_64
  return getX86FeaturesStr();
#else
#error "Unsupported target"
#endif
}

static LLVMTargetMachine *createTargetMachine() {
  const std::string &CPUStr = getCPUName();
  const std::string &FeaturesStr = getFeaturesStr();
  std::string Error;
#ifdef ZEN_BUILD_TARGET_X86_64
#ifdef ZEN_BUILD_PLATFORM_LINUX
  const std::string &Triple = "x86_64-unknown-linux-gnu";
#elif defined(ZEN_BUILD_PLATFORM_DARWIN)
  const std::string &Triple = "x86_64-apple-linux";
#else
#error "Unsupported target"
#endif // ZEN_BUILD_PLATFORM_LINUX
#else
#error "Unsupported target"
#endif // ZEN_BUILD_TARGET_X86_64
  const auto *TheTarget = llvm::TargetRegistry::lookupTarget(Triple, Error);
  if (!TheTarget) {
    throw getError(ErrorCode::TargetLookupFailed);
  }
  llvm::TargetOptions Options;
  return static_cast<llvm::LLVMTargetMachine *>(TheTarget->createTargetMachine(
      Triple, CPUStr, FeaturesStr, Options, llvm::None));
}

CompileContext::CompileContext() {
  // Ensure LLVM is initialized only once in the current process
  [[maybe_unused]] static bool _ = []() {
#ifdef ZEN_BUILD_TARGET_X86_64
    llvm::LLVMInitializeX86TargetInfo();
    llvm::LLVMInitializeX86Target();
    llvm::LLVMInitializeX86TargetMC();
#else
#error "Unsupported target"
#endif
    return true;
  }();
}

CompileContext::~CompileContext() {
  if (Inited) {
    ZEN_ASSERT(MCL);
    ThreadMemPool.deleteObject(MCL);
    ZEN_ASSERT(MCCtx);
    ThreadMemPool.deleteObject(MCCtx);
    ZEN_ASSERT(STI);
    ThreadMemPool.deleteObject(STI);
    ZEN_ASSERT(Workaround);
    ThreadMemPool.deleteObject(Workaround);
  }

  /* Only need to delete the following objects when on debug mode or using a
   * SysMemPool */
#ifndef NDEBUG
  for (const auto &[_, MConstFp] : FPConstants) {
    ThreadMemPool.deleteObject(MConstFp);
  }
  for (const auto &[_, MConstInt] : IntConstants) {
    ThreadMemPool.deleteObject(MConstInt);
  }
  /* MainContext's FuncTypeSet and PtrTypeSet will be used by all threads */
  for (MFunctionType *FuncType : FuncTypeSet) {
    ThreadMemPool.deleteObject(FuncType);
  }
  for (MPointerType *PtrType : PtrTypeSet) {
    ThreadMemPool.deleteObject(PtrType);
  }
#endif
}

CompileContext::CompileContext(const CompileContext &OtherCtx) {
  Lazy = OtherCtx.Lazy;
  CodeMPool = OtherCtx.CodeMPool;
}

void CompileContext::initialize() {
  initializeTargetMachine();

  initializeMC();

  Inited = true;
}

void CompileContext::finalize() {
  ZEN_ASSERT(MCL);
  MCL->finalize();
}

/// \warning only used for lazy compilation
void CompileContext::reinitialize() {
  ZEN_ASSERT(MCL);
  ZEN_ASSERT(MCCtx);
  ThreadMemPool.deleteObject(MCL);
  ThreadMemPool.deleteObject(MCCtx);

  // Ensure ObjBuffer is empty for upcoming compilation
  ZEN_ASSERT(ObjBuffer.empty());

  // All sections in object files are created and stored in MCContext, so we
  // need to create a new MCContext
  initializeMC();
}

void CompileContext::initializeTargetMachine() {
#ifdef ZEN_BUILD_TARGET_X86_64
  Workaround = ThreadMemPool.newObject<X86LLVMWorkaround>();
#else
#error "Unsupported target"
#endif

  TM.reset(createTargetMachine());

  STI = Workaround->getSubtargetImpl(*TM, ThreadMemPool);
  if (!STI) {
    throw getError(ErrorCode::UnexpectedSubtarget);
  }

#ifdef ZEN_BUILD_TARGET_X86_64
  const llvm::X86Subtarget *X86STI =
      static_cast<const llvm::X86Subtarget *>(STI);
  if (!X86STI->hasSSE41()) {
    throw getError(ErrorCode::UnexpectedSubtarget);
  }
#else
#error "Unsupported target"
#endif
}

void CompileContext::initializeMC() {
  MCCtx = ThreadMemPool.newObject<llvm::MCContext>(
      TM->getTargetTriple(), TM->getMCAsmInfo(), TM->getMCRegisterInfo(),
      TM->getMCSubtargetInfo(), nullptr, &TM->Options.MCOptions,
      false); // TODO: AutoReset?

  MCCtx->setObjectFileInfo(TM->getObjFileLowering());

#ifdef ZEN_BUILD_TARGET_X86_64
  MCL = ThreadMemPool.newObject<X86MCLowering>(*TM, *MCCtx, ObjBuffer);
  MCL->initialize();
#else
#error "Unsupported target"
#endif
}

FunctionTypeKeyInfo::KeyTy::KeyTy(const MFunctionType *FuncTypes)
    : Result(FuncTypes->getReturnType()),
      Parameters(FuncTypes->getParamTypes()) {}

PointerTypeKeyInfo::KeyTy::KeyTy(const MPointerType *PtrType)
    : ElemType(PtrType->getElemType()),
      AddressSpace(PtrType->getAddressSpace()) {}
