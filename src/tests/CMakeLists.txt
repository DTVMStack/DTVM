# Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

function(PROCESS_SPEC_FILES SPEC_CATEGORY_DIR)
  get_filename_component(CATEGORY ${SPEC_CATEGORY_DIR} NAME)
  file(GLOB SPEC_FILE_PATHS "${SPEC_CATEGORY_DIR}/*.wast")
  foreach(SPEC_FILE_PATH ${SPEC_FILE_PATHS})
    get_filename_component(SPEC_NAME ${SPEC_FILE_PATH} NAME_WE)
    set(OUTPUT_SPEC_SUBDIR "${CMAKE_BINARY_DIR}/wast/${CATEGORY}/${SPEC_NAME}")
    set(OUTPUT_SPEC_JSON "${OUTPUT_SPEC_SUBDIR}/${SPEC_NAME}.json")
    add_custom_command(
      OUTPUT ${OUTPUT_SPEC_JSON}
      COMMAND mkdir -vp ${OUTPUT_SPEC_SUBDIR}
      COMMAND wast2json --disable-bulk-memory -o ${OUTPUT_SPEC_JSON}
              ${SPEC_FILE_PATH}
      DEPENDS ${SPEC_FILE_PATH}
      VERBATIM
    )
    list(APPEND SPEC_JSONS ${OUTPUT_SPEC_JSON})
    set(SPEC_JSONS
        ${SPEC_JSONS}
        PARENT_SCOPE
    )
  endforeach()
endfunction()

if(ZEN_ENABLE_SPEC_TEST)
  set(SPEC_DIR "${CMAKE_SOURCE_DIR}/tests/wast")

  if(ZEN_ENABLE_DWASM)
    set(SPEC_CATEGORIES "dwasm")
  else()
    set(SPEC_CATEGORIES "spec/test/core" "proposals")
    if(ZEN_ENABLE_CHECKED_ARITHMETIC)
      list(APPEND SPEC_CATEGORIES "chain")
    endif()
    list(APPEND SPEC_CATEGORIES "gas")
    if(ZEN_ENABLE_CPU_EXCEPTION)
      list(APPEND SPEC_CATEGORIES "exception")
    endif()
    if(ZEN_ENABLE_MULTIPASS_JIT)
      list(APPEND SPEC_CATEGORIES "multipass")
    endif()
  endif()

  list(APPEND SPEC_CATEGORIES "spec_extra")

  foreach(SPEC_CATEGORY ${SPEC_CATEGORIES})
    process_spec_files("${SPEC_DIR}/${SPEC_CATEGORY}")
  endforeach()

  add_custom_target(spec_jsons DEPENDS ${SPEC_JSONS})

  add_executable(mempoolTests mempool_tests.cpp)
  add_executable(cAPITests c_api_tests.cpp)
  target_include_directories(
    mempoolTests PRIVATE ${googletest_SOURCE_DIR}/googletest/include
  )

  if(ZEN_ENABLE_EVM)
    add_subdirectory(mpt)
    add_executable(evmInterpTests evm_interp_tests.cpp)
    add_executable(evmCacheTests evm_cache_tests.cpp)
    # Build-only target: never receives ASan even in ASan builds so its
    # wall-clock measurement is not distorted by sanitizer overhead.
    add_executable(evmCacheComplexityDemo evm_cache_complexity_demo.cpp)
    target_link_libraries(evmCacheComplexityDemo PRIVATE dtvmcore)
    if(ZEN_ENABLE_MULTIPASS_JIT)
      add_executable(
        evmJitFrontendTests evm_jit_frontend_tests.cpp
                            evm_terminating_memory_tests.cpp
      )
      add_executable(evmRangeAnalyzerTests evm_range_analyzer_tests.cpp)
      add_executable(evmDifferentialTests evm_differential_tests.cpp)
      target_sources(evmJitFrontendTests PRIVATE evm_call_memory_tests.cpp)
      add_executable(
        evmMemoryExecuteOnlyBench evm_memory_execute_only_bench.cpp
      )
    endif()
    add_executable(
      solidityContractTests evm_precompiles.hpp solidity_contract_tests.cpp
                            solidity_test_helpers.cpp
    )
    add_executable(
      evmStateTests evm_precompiles.hpp evm_state_tests.cpp
                    evm_test_fixtures.cpp evm_test_helpers.cpp
    )
    # Only build evmFallbackExecutionTests if dtvmapi library is available
    if(ZEN_ENABLE_LIBEVM)
      add_executable(evmFallbackExecutionTests evm_fallback_execution_tests.cpp)
      add_executable(evmModuleCacheTests evm_module_cache_tests.cpp)
      add_executable(evmProfileGuidedJITTests evm_profile_guided_jit_tests.cpp)
    endif()
    add_executable(mptCompareCpp mpt_compare_cpp.cpp)
  else()
    add_executable(
      specUnitTests spec_unit_tests.cpp spectest.cpp test_utils.cpp
    )

    target_link_libraries(
      specUnitTests
      PRIVATE dtvmcore rapidjson gtest_main CLI11::CLI11
      PUBLIC ${GTEST_BOTH_LIBRARIES}
    )

    if(ZEN_BUILD_PLATFORM_LINUX)
      target_link_libraries(specUnitTests PRIVATE stdc++fs)
    endif()
  endif()

  # Top-level CMakeLists skips -fsanitize=address when VIRTUAL_STACK is on (ASan
  # cannot instrument the alternate stack). Per-test ASan flags must match, or
  # instrumented tests mix with uninstrumented compiler/runtime objects and
  # segfault (same class as DTVMStack#629).
  set(ZEN_TEST_ENABLE_ASAN OFF)
  if(ZEN_ENABLE_ASAN AND NOT ZEN_ENABLE_VIRTUAL_STACK)
    set(ZEN_TEST_ENABLE_ASAN ON)
  endif()

  if(ZEN_TEST_ENABLE_ASAN)
    target_compile_options(mempoolTests PRIVATE -fsanitize=address)
    target_compile_options(cAPITests PRIVATE -fsanitize=address)

    if(ZEN_ENABLE_EVM)
      target_compile_options(evmInterpTests PRIVATE -fsanitize=address)
      target_compile_options(evmCacheTests PRIVATE -fsanitize=address)
      if(ZEN_ENABLE_MULTIPASS_JIT)
        target_compile_options(evmJitFrontendTests PRIVATE -fsanitize=address)
        target_compile_options(evmRangeAnalyzerTests PRIVATE -fsanitize=address)
        target_compile_options(evmDifferentialTests PRIVATE -fsanitize=address)
      endif()
      target_compile_options(solidityContractTests PRIVATE -fsanitize=address)
      target_compile_options(mptCompareCpp PRIVATE -fsanitize=address)
    endif()

    if(ZEN_BUILD_PLATFORM_DARWIN)
      target_link_libraries(
        mempoolTests
        PRIVATE dtvmcore gtest_main -fsanitize=address
        PUBLIC ${GTEST_BOTH_LIBRARIES}
      )
      target_link_libraries(
        cAPITests
        PRIVATE dtvmcore gtest_main -fsanitize=address
        PUBLIC ${GTEST_BOTH_LIBRARIES}
      )

      if(ZEN_ENABLE_EVM)
        target_link_libraries(
          evmInterpTests
          PRIVATE dtvmcore rapidjson yaml-cpp gtest_main -fsanitize=address
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
        target_link_libraries(
          evmCacheTests
          PRIVATE dtvmcore gtest_main -fsanitize=address
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
        if(ZEN_ENABLE_MULTIPASS_JIT)
          target_link_libraries(
            evmJitFrontendTests
            PRIVATE compiler dtvmcore gtest_main -fsanitize=address
            PUBLIC ${GTEST_BOTH_LIBRARIES}
          )
          target_link_libraries(
            evmRangeAnalyzerTests
            PRIVATE compiler dtvmcore gtest_main -fsanitize=address
            PUBLIC ${GTEST_BOTH_LIBRARIES}
          )
          target_link_libraries(
            evmDifferentialTests
            PRIVATE dtvmcore gtest_main -fsanitize=address
            PUBLIC ${GTEST_BOTH_LIBRARIES}
          )
          target_link_libraries(
            evmMemoryExecuteOnlyBench PRIVATE dtvmcore CLI11::CLI11
                                              -fsanitize=address
          )
        endif()
        target_link_libraries(
          solidityContractTests
          PRIVATE dtvmcore rapidjson mpt gtest_main -fsanitize=address
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
        target_link_libraries(
          evmStateTests
          PRIVATE dtvmcore rapidjson mpt gtest_main -fsanitize=address
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
        if(ZEN_ENABLE_LIBEVM)
          target_link_libraries(
            evmFallbackExecutionTests
            PRIVATE dtvmapi gtest_main -fsanitize=address
            PUBLIC ${GTEST_BOTH_LIBRARIES}
          )
          target_link_libraries(
            evmModuleCacheTests
            PRIVATE dtvmapi gtest_main -fsanitize=address
            PUBLIC ${GTEST_BOTH_LIBRARIES}
          )
          target_link_libraries(
            evmProfileGuidedJITTests
            PRIVATE dtvmapi gtest_main -fsanitize=address
            PUBLIC ${GTEST_BOTH_LIBRARIES}
          )
        endif()
        target_link_libraries(
          mptCompareCpp PRIVATE dtvmcore rapidjson mpt -fsanitize=address
        )
      endif()
    else()
      target_link_libraries(
        mempoolTests
        PRIVATE dtvmcore gtest_main -fsanitize=address -static-libasan
        PUBLIC ${GTEST_BOTH_LIBRARIES}
      )
      target_link_libraries(
        cAPITests
        PRIVATE dtvmcore gtest_main -fsanitize=address -static-libasan
        PUBLIC ${GTEST_BOTH_LIBRARIES}
      )

      if(ZEN_ENABLE_EVM)
        target_link_libraries(
          evmInterpTests
          PRIVATE dtvmcore
                  rapidjson
                  yaml-cpp
                  gtest_main
                  -fsanitize=address
                  -static-libasan
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
        target_link_libraries(
          evmCacheTests
          PRIVATE dtvmcore gtest_main -fsanitize=address -static-libasan
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
        if(ZEN_ENABLE_MULTIPASS_JIT)
          target_link_libraries(
            evmJitFrontendTests
            PRIVATE compiler dtvmcore gtest_main -fsanitize=address
                    -static-libasan
            PUBLIC ${GTEST_BOTH_LIBRARIES}
          )
          target_link_libraries(
            evmRangeAnalyzerTests
            PRIVATE compiler dtvmcore gtest_main -fsanitize=address
                    -static-libasan
            PUBLIC ${GTEST_BOTH_LIBRARIES}
          )
          target_link_libraries(
            evmDifferentialTests
            PRIVATE dtvmcore gtest_main -fsanitize=address -static-libasan
            PUBLIC ${GTEST_BOTH_LIBRARIES}
          )
          target_link_libraries(
            evmMemoryExecuteOnlyBench
            PRIVATE dtvmcore CLI11::CLI11 -fsanitize=address -static-libasan
          )
        endif()
        target_link_libraries(
          solidityContractTests
          PRIVATE dtvmcore
                  rapidjson
                  mpt
                  gtest_main
                  CLI11::CLI11
                  -fsanitize=address
                  -static-libasan
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
        target_link_libraries(
          evmStateTests
          PRIVATE dtvmcore
                  rapidjson
                  mpt
                  gtest_main
                  -fsanitize=address
                  -static-libasan
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
        if(ZEN_ENABLE_LIBEVM)
          target_link_libraries(
            evmFallbackExecutionTests
            PRIVATE dtvmapi gtest_main -fsanitize=address -static-libasan
            PUBLIC ${GTEST_BOTH_LIBRARIES}
          )
          target_link_libraries(
            evmModuleCacheTests
            PRIVATE dtvmapi gtest_main -fsanitize=address -static-libasan
            PUBLIC ${GTEST_BOTH_LIBRARIES}
          )
          target_link_libraries(
            evmProfileGuidedJITTests
            PRIVATE dtvmapi gtest_main -fsanitize=address -static-libasan
            PUBLIC ${GTEST_BOTH_LIBRARIES}
          )
        endif()
        target_link_libraries(
          mptCompareCpp PRIVATE dtvmcore rapidjson mpt -fsanitize=address
                                -static-libasan
        )
      endif()
    endif()
  else()
    target_link_libraries(
      mempoolTests
      PRIVATE dtvmcore gtest_main
      PUBLIC ${GTEST_BOTH_LIBRARIES}
    )
    target_link_libraries(
      cAPITests
      PRIVATE dtvmcore gtest_main
      PUBLIC ${GTEST_BOTH_LIBRARIES}
    )

    if(ZEN_ENABLE_EVM)
      target_link_libraries(
        evmInterpTests
        PRIVATE dtvmcore rapidjson yaml-cpp gtest_main
        PUBLIC ${GTEST_BOTH_LIBRARIES}
      )
      target_link_libraries(
        evmCacheTests
        PRIVATE dtvmcore gtest_main
        PUBLIC ${GTEST_BOTH_LIBRARIES}
      )
      if(ZEN_ENABLE_MULTIPASS_JIT)
        target_link_libraries(
          evmJitFrontendTests
          PRIVATE compiler dtvmcore gtest_main
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
        target_link_libraries(
          evmRangeAnalyzerTests
          PRIVATE compiler dtvmcore gtest_main
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
        target_link_libraries(
          evmDifferentialTests
          PRIVATE dtvmcore gtest_main
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
        target_link_libraries(
          evmMemoryExecuteOnlyBench PRIVATE dtvmcore CLI11::CLI11
        )
      endif()
      target_link_libraries(
        solidityContractTests
        PRIVATE dtvmcore rapidjson mpt gtest_main CLI11::CLI11
        PUBLIC ${GTEST_BOTH_LIBRARIES}
      )
      target_link_libraries(
        evmStateTests
        PRIVATE dtvmcore rapidjson mpt gtest_main
        PUBLIC ${GTEST_BOTH_LIBRARIES}
      )
      if(ZEN_ENABLE_LIBEVM)
        target_link_libraries(
          evmFallbackExecutionTests
          PRIVATE dtvmapi gtest_main
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
        target_link_libraries(
          evmModuleCacheTests
          PRIVATE dtvmapi gtest_main
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
        target_link_libraries(
          evmProfileGuidedJITTests
          PRIVATE dtvmapi gtest_main
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
      endif()
      target_link_libraries(mptCompareCpp PRIVATE dtvmcore rapidjson mpt)
    endif()
  endif()

  if(NOT ZEN_ENABLE_EVM)
    add_dependencies(specUnitTests spec_jsons)

    add_test(
      NAME specUnitTests
      COMMAND ${CMAKE_COMMAND} -DTEST_EXECUTABLE=$<TARGET_FILE:specUnitTests>
              -P ${CMAKE_CURRENT_SOURCE_DIR}/RunSpecTests.cmake
    )
  endif()
  add_test(NAME mempoolTests COMMAND mempoolTests)
  add_test(NAME cAPITests COMMAND cAPITests)

  if(ZEN_BUILD_TARGET_X86_64)
    add_executable(lazyJitStubTests lazy_jit_stub_tests.cpp)
    target_include_directories(
      lazyJitStubTests PRIVATE ${googletest_SOURCE_DIR}/googletest/include
    )
    if(ZEN_TEST_ENABLE_ASAN)
      target_compile_options(lazyJitStubTests PRIVATE -fsanitize=address)
      if(ZEN_BUILD_PLATFORM_DARWIN)
        target_link_libraries(
          lazyJitStubTests
          PRIVATE dtvmcore gtest_main Threads::Threads -fsanitize=address
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
      else()
        target_link_libraries(
          lazyJitStubTests
          PRIVATE dtvmcore gtest_main Threads::Threads -fsanitize=address
                  -static-libasan
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
      endif()
    else()
      target_link_libraries(
        lazyJitStubTests
        PRIVATE dtvmcore gtest_main Threads::Threads
        PUBLIC ${GTEST_BOTH_LIBRARIES}
      )
    endif()
    add_test(NAME lazyJitStubTests COMMAND lazyJitStubTests)
  endif()

  if(ZEN_ENABLE_MULTIPASS_JIT AND ZEN_BUILD_TARGET_X86_64)
    add_executable(
      mirPeepholeTests mir_peephole_tests.cpp x86_cg_lowering_tests.cpp
    )
    target_include_directories(
      mirPeepholeTests PRIVATE ${googletest_SOURCE_DIR}/googletest/include
    )
    set(PEEP_MOD_WAT
        "${CMAKE_SOURCE_DIR}/tests/wast/multipass/peephole_mod.wat"
    )
    set(PEEP_MOD_WASM "${CMAKE_CURRENT_BINARY_DIR}/peephole_mod.wasm")
    add_custom_command(
      OUTPUT ${PEEP_MOD_WASM}
      COMMAND wat2wasm ${PEEP_MOD_WAT} -o ${PEEP_MOD_WASM}
      DEPENDS ${PEEP_MOD_WAT}
      VERBATIM
    )
    add_custom_target(peephole_mod_wasm DEPENDS ${PEEP_MOD_WASM})
    add_dependencies(mirPeepholeTests peephole_mod_wasm)
    target_compile_definitions(
      mirPeepholeTests PRIVATE PEEP_WASM_PATH="${PEEP_MOD_WASM}"
    )
    # Keep the long call chains generated, so the spill-stress fixture stays
    # readable without hundreds of duplicated statements in source control.
    string(REPEAT "(local.set $s (i32.add (local.get $s) (call $one)))\n" 512
           REGMASK_I32_CHAIN
    )
    string(REPEAT "(local.set $s (f64.add (local.get $s) (call $fp)))\n" 512
           REGMASK_F64_CHAIN
    )
    string(
      CONCAT REGMASK_MIXED_STEP
             "(local.set $a (i32.add (local.get $a) (call $one)))\n"
             "(local.set $x (f64.add (local.get $x) (call $fp)))\n"
             "(local.set $b (i32.add (local.get $b) (local.get $a)))\n"
             "(local.set $y (f64.add (local.get $y) (local.get $x)))\n"
    )
    string(REPEAT "${REGMASK_MIXED_STEP}" 512 REGMASK_MIXED_CHAIN)
    set(REGMASK_STRESS_WAT "${CMAKE_CURRENT_BINARY_DIR}/regmask_stress.wat")
    set(REGMASK_STRESS_WASM "${CMAKE_CURRENT_BINARY_DIR}/regmask_stress.wasm")
    file(
      WRITE ${REGMASK_STRESS_WAT}
      "(module (func $one (result i32) i32.const 1)\n"
      "(func $fp (result f64) f64.const 1.25)\n"
      "(func (export \"i32_calls\") (result i32) (local $s i32)\n"
      "${REGMASK_I32_CHAIN}(local.get $s))\n"
      "(func (export \"f64_calls\") (result f64) (local $s f64)\n"
      "${REGMASK_F64_CHAIN}(local.get $s))\n"
      "(func (export \"mixed_calls\") (result i32)\n"
      "(local $a i32) (local $b i32) (local $x f64) (local $y f64)\n"
      "${REGMASK_MIXED_CHAIN}"
      "(local.get $a) i32.const 3 i32.mul\n"
      "(local.get $b) i32.const 5 i32.mul i32.add\n"
      "(local.get $x) i32.trunc_f64_s i32.const 7 i32.mul i32.add\n"
      "(local.get $y) i32.trunc_f64_s i32.const 11 i32.mul i32.add))\n"
    )
    add_custom_command(
      OUTPUT ${REGMASK_STRESS_WASM}
      COMMAND wat2wasm ${REGMASK_STRESS_WAT} -o ${REGMASK_STRESS_WASM}
      DEPENDS ${REGMASK_STRESS_WAT}
      VERBATIM
    )
    add_custom_target(regmask_stress_wasm DEPENDS ${REGMASK_STRESS_WASM})
    add_dependencies(mirPeepholeTests regmask_stress_wasm)
    target_compile_definitions(
      mirPeepholeTests
      PRIVATE REGMASK_STRESS_WASM_PATH="${REGMASK_STRESS_WASM}"
    )
    if(ZEN_TEST_ENABLE_ASAN)
      target_compile_options(mirPeepholeTests PRIVATE -fsanitize=address)
      if(ZEN_BUILD_PLATFORM_DARWIN)
        target_link_libraries(
          mirPeepholeTests
          PRIVATE compiler dtvmcore gtest_main Threads::Threads
                  -fsanitize=address
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
      else()
        target_link_libraries(
          mirPeepholeTests
          PRIVATE compiler
                  dtvmcore
                  gtest_main
                  Threads::Threads
                  -fsanitize=address
                  -static-libasan
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
      endif()
    else()
      target_link_libraries(
        mirPeepholeTests
        PRIVATE compiler dtvmcore gtest_main Threads::Threads
        PUBLIC ${GTEST_BOTH_LIBRARIES}
      )
    endif()
    add_test(NAME mirPeepholeTests COMMAND mirPeepholeTests)

    add_executable(statisticsTests statistics_tests.cpp)
    target_include_directories(
      statisticsTests PRIVATE ${googletest_SOURCE_DIR}/googletest/include
    )
    if(ZEN_TEST_ENABLE_ASAN)
      target_compile_options(statisticsTests PRIVATE -fsanitize=address)
      if(ZEN_BUILD_PLATFORM_DARWIN)
        target_link_libraries(
          statisticsTests
          PRIVATE compiler dtvmcore gtest_main Threads::Threads
                  -fsanitize=address
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
      else()
        target_link_libraries(
          statisticsTests
          PRIVATE compiler
                  dtvmcore
                  gtest_main
                  Threads::Threads
                  -fsanitize=address
                  -static-libasan
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
      endif()
    else()
      target_link_libraries(
        statisticsTests
        PRIVATE compiler dtvmcore gtest_main Threads::Threads
        PUBLIC ${GTEST_BOTH_LIBRARIES}
      )
    endif()
    add_test(NAME statisticsTests COMMAND statisticsTests)

    add_executable(
      lazyJitGreedyOndemandTests lazy_jit_greedy_ondemand_tests.cpp
    )
    target_include_directories(
      lazyJitGreedyOndemandTests
      PRIVATE ${googletest_SOURCE_DIR}/googletest/include
    )
    set(FIB_ITER_ONEFN_WAT
        "${CMAKE_SOURCE_DIR}/tests/wast/multipass/fib_iter_onefn.wat"
    )
    set(FIB_ITER_ONEFN_WASM "${CMAKE_CURRENT_BINARY_DIR}/fib_iter_onefn.wasm")
    set(FIB_ITER_TWOFN_WAT
        "${CMAKE_SOURCE_DIR}/tests/wast/multipass/fib_iter_twofn.wat"
    )
    set(FIB_ITER_TWOFN_WASM "${CMAKE_CURRENT_BINARY_DIR}/fib_iter_twofn.wasm")
    set(LAZY_ENTRY_SEEDS_WAT
        "${CMAKE_SOURCE_DIR}/tests/wast/multipass/lazy_entry_seeds.wat"
    )
    set(LAZY_ENTRY_SEEDS_WASM
        "${CMAKE_CURRENT_BINARY_DIR}/lazy_entry_seeds.wasm"
    )
    add_custom_command(
      OUTPUT ${FIB_ITER_ONEFN_WASM}
      COMMAND wat2wasm ${FIB_ITER_ONEFN_WAT} -o ${FIB_ITER_ONEFN_WASM}
      DEPENDS ${FIB_ITER_ONEFN_WAT}
      VERBATIM
    )
    add_custom_command(
      OUTPUT ${FIB_ITER_TWOFN_WASM}
      COMMAND wat2wasm ${FIB_ITER_TWOFN_WAT} -o ${FIB_ITER_TWOFN_WASM}
      DEPENDS ${FIB_ITER_TWOFN_WAT}
      VERBATIM
    )
    add_custom_target(
      fib_iter_lazy_wasm DEPENDS ${FIB_ITER_ONEFN_WASM} ${FIB_ITER_TWOFN_WASM}
    )
    add_custom_command(
      OUTPUT ${LAZY_ENTRY_SEEDS_WASM}
      COMMAND wat2wasm ${LAZY_ENTRY_SEEDS_WAT} -o ${LAZY_ENTRY_SEEDS_WASM}
      DEPENDS ${LAZY_ENTRY_SEEDS_WAT}
      VERBATIM
    )
    add_custom_target(lazy_entry_seeds_wasm DEPENDS ${LAZY_ENTRY_SEEDS_WASM})
    add_dependencies(lazyJitGreedyOndemandTests fib_iter_lazy_wasm)
    add_dependencies(lazyJitGreedyOndemandTests lazy_entry_seeds_wasm)
    target_compile_definitions(
      lazyJitGreedyOndemandTests
      PRIVATE FIB_ITER_ONEFN_WASM_PATH="${FIB_ITER_ONEFN_WASM}"
              FIB_ITER_TWOFN_WASM_PATH="${FIB_ITER_TWOFN_WASM}"
              LAZY_ENTRY_SEEDS_WASM_PATH="${LAZY_ENTRY_SEEDS_WASM}"
    )
    if(ZEN_TEST_ENABLE_ASAN)
      target_compile_options(
        lazyJitGreedyOndemandTests PRIVATE -fsanitize=address
      )
      if(ZEN_BUILD_PLATFORM_DARWIN)
        target_link_libraries(
          lazyJitGreedyOndemandTests
          PRIVATE compiler dtvmcore gtest_main Threads::Threads
                  -fsanitize=address
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
      else()
        target_link_libraries(
          lazyJitGreedyOndemandTests
          PRIVATE compiler
                  dtvmcore
                  gtest_main
                  Threads::Threads
                  -fsanitize=address
                  -static-libasan
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
      endif()
    else()
      target_link_libraries(
        lazyJitGreedyOndemandTests
        PRIVATE compiler dtvmcore gtest_main Threads::Threads
        PUBLIC ${GTEST_BOTH_LIBRARIES}
      )
    endif()
    set(PRIVATE_TIER_WAT
        "${CMAKE_SOURCE_DIR}/tests/wast/multipass/private_tiering.wat"
    )
    set(PRIVATE_TIER_WASM "${CMAKE_CURRENT_BINARY_DIR}/private_tiering.wasm")
    add_custom_command(
      OUTPUT ${PRIVATE_TIER_WASM}
      COMMAND wat2wasm ${PRIVATE_TIER_WAT} -o ${PRIVATE_TIER_WASM}
      DEPENDS ${PRIVATE_TIER_WAT}
      VERBATIM
    )
    add_custom_target(private_tier_wasm DEPENDS ${PRIVATE_TIER_WASM})
    add_dependencies(lazyJitGreedyOndemandTests private_tier_wasm)
    target_sources(
      lazyJitGreedyOndemandTests PRIVATE lazy_private_tiering_tests.cpp
    )
    target_compile_definitions(
      lazyJitGreedyOndemandTests
      PRIVATE PRIVATE_TIER_WASM_PATH="${PRIVATE_TIER_WASM}"
    )
    set(NUMERIC_LOOP_WAT
        "${CMAKE_SOURCE_DIR}/tests/wast/multipass/lazy_numeric_loops.wat"
    )
    set(NUMERIC_LOOP_WASM "${CMAKE_CURRENT_BINARY_DIR}/lazy_numeric_loops.wasm")
    add_custom_command(
      OUTPUT ${NUMERIC_LOOP_WASM}
      COMMAND wat2wasm ${NUMERIC_LOOP_WAT} -o ${NUMERIC_LOOP_WASM}
      DEPENDS ${NUMERIC_LOOP_WAT}
      VERBATIM
    )
    add_custom_target(lazy_numeric_loop_wasm DEPENDS ${NUMERIC_LOOP_WASM})
    add_dependencies(lazyJitGreedyOndemandTests lazy_numeric_loop_wasm)
    target_compile_definitions(
      lazyJitGreedyOndemandTests
      PRIVATE NUMERIC_LOOP_WASM_PATH="${NUMERIC_LOOP_WASM}"
    )
    add_test(NAME lazyJitGreedyOndemandTests COMMAND lazyJitGreedyOndemandTests)
  endif()

  if(ZEN_ENABLE_EVM)
    add_test(NAME evmInterpTests COMMAND evmInterpTests)
    add_test(NAME evmCacheTests COMMAND evmCacheTests)
    if(ZEN_ENABLE_MULTIPASS_JIT)
      add_test(NAME evmJitFrontendTests COMMAND evmJitFrontendTests)
      add_test(NAME evmRangeAnalyzerTests COMMAND evmRangeAnalyzerTests)
      add_test(NAME evmDifferentialTests COMMAND evmDifferentialTests)
    endif()
    add_test(
      NAME solidityContractTests
      COMMAND
        ${CMAKE_COMMAND} -DTEST_EXECUTABLE=$<TARGET_FILE:solidityContractTests>
        -P ${CMAKE_CURRENT_SOURCE_DIR}/RunSpecTests.cmake
    )
    add_test(NAME evmStateTests COMMAND evmStateTests)
    if(ZEN_ENABLE_LIBEVM)
      add_test(NAME evmFallbackExecutionTests COMMAND evmFallbackExecutionTests)
      add_test(NAME evmModuleCacheTests COMMAND evmModuleCacheTests)
      add_test(NAME evmProfileGuidedJITTests COMMAND evmProfileGuidedJITTests)
    endif()
  endif()
endif()
