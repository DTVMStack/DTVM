set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})

if(LLVM_ENABLE_SHARED_LIBS)
  llvm_map_components_to_libnames(
    llvm_libs
    Support
    X86
    CodeGen
    MC
    Object
    SelectionDAG
    Core
    GlobalISel
    Target
    Analysis
  )
  message(STATUS "Use Shared LLVM Libraries")
else()
  llvm_map_components_to_libnames(
    llvm_libs
    Support
    X86
    CodeGen
    MC
    Object
  )
  message(STATUS "Use Static LLVM Libraries")
endif()

set(COMPILER_SRCS
    compiler.cpp
    context.cpp
    common/llvm_workaround.cpp
    evm_frontend/evm_mir_compiler.cpp
    frontend/parser.cpp
    frontend/lexer.cpp
    wasm_frontend/wasm_mir_compiler.cpp
    mir/function.cpp
    mir/pointer.cpp
    mir/module.cpp
    mir/basic_block.cpp
    mir/instructions.cpp
    mir/type.cpp
    mir/constants.cpp
    mir/opcode.cpp
    mir/pass/verifier.cpp
    cgir/cg_basic_block.cpp
    cgir/cg_instruction.cpp
    cgir/cg_function.cpp
    cgir/cg_operand.cpp
    target/x86/x86lowering.cpp
    target/x86/x86lowering_fallback.cpp
    target/x86/x86lowering_wasm.cpp
    target/x86/x86_mc_inst_lower.cpp
    target/x86/x86_llvm_workaround.cpp
    target/x86/x86_cg_peephole.cpp
    cgir/pass/fast_ra.cpp
    cgir/pass/cg_register_info.cpp
    cgir/pass/cg_frame_info.cpp
    cgir/pass/cg_register_class_info.cpp
    cgir/pass/prolog_epilog_inserter.cpp
    cgir/pass/expand_post_ra_pseudos.cpp
    cgir/pass/virt_reg_map.cpp
    cgir/pass/cg_dominators.cpp
    cgir/pass/cg_loop_info.cpp
    cgir/pass/cg_branch_probability_info.cpp
    cgir/pass/cg_block_frequency_info.cpp
    cgir/pass/calc_spill_weights.cpp
    cgir/pass/live_range_calc.cpp
    cgir/pass/live_interval_calc.cpp
    cgir/pass/live_interval.cpp
    cgir/pass/live_interval_union.cpp
    cgir/pass/live_intervals.cpp
    cgir/pass/live_reg_matrix.cpp
    cgir/pass/live_range_edit.cpp
    cgir/pass/live_stacks.cpp
    cgir/pass/cg_split_kit.cpp
    cgir/pass/cg_inline_spiller.cpp
    cgir/pass/register_coalescer.cpp
    cgir/pass/reg_alloc_base.cpp
    cgir/pass/reg_alloc_basic.cpp
    cgir/pass/dead_cg_instruction_elim.cpp
    cgir/pass/allocation_order.cpp
    cgir/pass/slot_indexes.cpp
    cgir/pass/interference_cache.cpp
    cgir/pass/edge_bundles.cpp
    cgir/pass/spill_placement.cpp
    cgir/pass/reg_alloc_eviction_advisor.cpp
    cgir/pass/reg_alloc_greedy.cpp
    stub/stub_x86_64.S
    stub/stub_builder.cpp
    cgir/pass/llvm_utils.cpp
)

if(ZEN_ENABLE_JIT_LOGGING)
  list(APPEND COMPILER_SRCS utils/asm_dump.cpp)
endif()

set_property(
  DIRECTORY
  APPEND
  PROPERTY COMPILE_OPTIONS -Wno-unused-variable -Wno-misleading-indentation
)

add_library(compiler STATIC ${COMPILER_SRCS} $<TARGET_OBJECTS:utils>)
target_link_libraries(compiler PRIVATE ${llvm_libs})

add_executable(ircompiler ircompiler.cpp)
target_link_libraries(ircompiler PRIVATE compiler dtvmcore CLI11::CLI11)
