// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_EVM_LAZY_COMPILER_H
#define ZEN_EVM_LAZY_COMPILER_H

#include "common/thread_pool.h"
#include "compiler/evm_compiler.h"
#include "compiler/evm_frontend/evm_mir_compiler.h"
#include "compiler/stub/evm_stub_builder.h"
#include "runtime/evm_module.h"
#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

namespace COMPILER {

/// Represents a segment of EVM bytecode that can be compiled independently.
/// Segments are split at JUMPDEST boundaries, so each segment starts at either
/// PC=0 or a JUMPDEST opcode.
struct EVMSegmentInfo {
  uint32_t SegmentIdx; // Index of this segment
  uint32_t StartPC;    // Start PC of this segment (inclusive)
  uint32_t EndPC;      // End PC of this segment (exclusive)
  bool IsEntry;        // Whether this is the entry segment (PC=0)
  bool IsJumpDest;     // Whether this segment starts with JUMPDEST
};

/// Analyzes EVM bytecode and splits it into segments for lazy compilation.
/// Each segment corresponds to a JUMPDEST-delimited basic block group.
class EVMSegmentAnalyzer {
  using Byte = zen::common::Byte;

public:
  EVMSegmentAnalyzer() = default;

  /// Analyze bytecode and produce segment info.
  /// Returns the list of segments.
  void analyze(const Byte *Code, size_t CodeSize, evmc_revision Rev);

  const std::vector<EVMSegmentInfo> &getSegments() const { return Segments; }

  /// Get segment index for a given PC (JUMPDEST target).
  /// Returns UINT32_MAX if not found.
  uint32_t getSegmentIdxForPC(uint32_t PC) const;

  /// Get segment index for a PC that falls within a segment range.
  /// Uses range lookup: finds segment where StartPC <= PC < EndPC.
  /// Returns UINT32_MAX if not found.
  uint32_t getSegmentIdxContainingPC(uint32_t PC) const;

  /// Get the number of segments.
  uint32_t getNumSegments() const {
    return static_cast<uint32_t>(Segments.size());
  }

private:
  std::vector<EVMSegmentInfo> Segments;
  // Map from PC to segment index for quick lookup
  std::map<uint32_t, uint32_t> PCToSegmentIdx;
};

/// Lazy JIT compiler for EVM bytecode.
///
/// This compiler uses an EVMSegmentAnalyzer to provide a segment-based view
/// of the EVM bytecode (split at JUMPDEST boundaries), but the current
/// implementation compiles the entire bytecode eagerly rather than performing
/// true on-demand or background compilation.
///
/// In particular, all segments are compiled up front and marked as completed;
/// no stubs are generated for deferred compilation, and no background
/// compilation tasks are dispatched at this time.
///
/// This is analogous to the WASM LazyJITCompiler in terms of exposing a
/// segment-oriented interface, but it currently performs eager compilation of
/// the full EVM bytecode.
class LazyEVMJITCompiler final : public EVMJITCompiler {
public:
  LazyEVMJITCompiler(runtime::EVMModule *EVMMod);
  ~LazyEVMJITCompiler() override;

  /// Perform initial precompilation.
  ///
  /// The current implementation:
  /// - Analyzes the bytecode into segments
  /// - Compiles the entire bytecode eagerly (all segments)
  /// - Marks all segments as compiled/ready to execute
  ///
  /// It does not currently create per-segment stubs or dispatch background
  /// compilation tasks.
  void precompile();

  /// Compile a specific segment on demand (called from stub resolver).
  /// Returns the JIT code pointer for the compiled segment.
  uint8_t *compileSegmentOnRequest(uint32_t SegmentIdx);

  /// Get the JIT code pointer for a segment (may be stub or compiled code).
  uint8_t *getSegmentCodePtr(uint32_t SegmentIdx) const;

  /// Get the segment analyzer.
  const EVMSegmentAnalyzer &getSegmentAnalyzer() const {
    return SegmentAnalyzer;
  }

  /// Get the number of segments.
  uint32_t getNumSegments() const { return SegmentAnalyzer.getNumSegments(); }

  /// Check if a segment has been compiled.
  bool isSegmentCompiled(uint32_t SegmentIdx) const;

  /// Get the segment index for a given PC.
  uint32_t getSegmentIdxForPC(uint32_t PC) const {
    return SegmentAnalyzer.getSegmentIdxForPC(PC);
  }

  uint32_t getSegmentIdxContainingPC(uint32_t PC) const {
    return SegmentAnalyzer.getSegmentIdxContainingPC(PC);
  }

  /// Get the stub builder.
  EVMSegmentStubBuilder *getStubBuilder() { return StubBuilder.get(); }

  /// Get the segment jump table.
  uint8_t **getSegmentJumpTable() { return SegmentJumpTable.get(); }

  /// Get the PC to segment index map.
  const std::map<uint32_t, uint32_t> &getPCToSegmentIdxMap() const {
    return PCToSegmentIdx;
  }

private:
  enum class CompileStatus : uint8_t {
    None,       // Not yet scheduled
    Pending,    // Scheduled for background compilation
    InProgress, // Currently being compiled
    Done,       // Compilation complete
  };

  /// Compile a single segment and return its JIT code pointer.
  uint8_t *compileSegment(EVMFrontendContext &Ctx, uint32_t SegmentIdx);

  /// Compile a segment in the background thread.
  void compileSegmentInBackground(EVMFrontendContext &Ctx, uint32_t SegmentIdx);

  /// Dispatch background compilation tasks for non-entry segments.
  void dispatchBackgroundTasks();

  /// Build the segment-level jump table that maps JUMPDEST PCs to
  /// segment code pointers (or stubs).
  void buildSegmentJumpTable();

  EVMSegmentAnalyzer SegmentAnalyzer;

  // Main compilation context (used for foreground/on-request compilation)
  EVMFrontendContext *MainContext = nullptr;
  MModule *Mod = nullptr;

  // Per-segment compilation state
  std::unique_ptr<std::atomic<CompileStatus>[]> CompileStatuses;
  std::unique_ptr<std::atomic<uint8_t *>[]> SegmentCodePtrs;

  // Stub code pointers for each segment
  std::vector<uint8_t *> SegmentStubPtrs;

  // Mutex for foreground compilation (only one thread compiles on-request)
  std::mutex ForegroundMutex;

  // Background thread pool
  std::vector<EVMFrontendContext> AuxContexts;
  std::unique_ptr<zen::common::ThreadPool<EVMFrontendContext>> ThreadPool;

  // The compiled entry segment code pointer
  uint8_t *EntryCodePtr = nullptr;

  // Stub builder for lazy compilation
  std::unique_ptr<EVMSegmentStubBuilder> StubBuilder;

  // Segment jump table: maps segment index to code pointer (stub or compiled)
  std::unique_ptr<uint8_t *[]> SegmentJumpTable;

  // PC to segment index map (populated from SegmentAnalyzer)
  std::map<uint32_t, uint32_t> PCToSegmentIdx;
};

} // namespace COMPILER

#endif // ZEN_EVM_LAZY_COMPILER_H
