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
  if(ZEN_ENABLE_MULTIPASS_JIT)
    add_executable(x86CgPeepholeTests x86_cg_peephole_tests.cpp)
    add_executable(dmirValidationTests dmir_validation_tests.cpp)
    if(ZEN_ENABLE_DMIR_SHADOW_AUDIT)
      add_executable(dmirShadowRuntimeTests dmir_shadow_runtime_tests.cpp)
    endif()
  endif()
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
      add_executable(evmJitFrontendTests evm_jit_frontend_tests.cpp)
      add_executable(evmRangeAnalyzerTests evm_range_analyzer_tests.cpp)
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

  if(ZEN_ENABLE_ASAN)
    target_compile_options(mempoolTests PRIVATE -fsanitize=address)
    target_compile_options(cAPITests PRIVATE -fsanitize=address)

    if(ZEN_ENABLE_EVM)
      target_compile_options(evmInterpTests PRIVATE -fsanitize=address)
      target_compile_options(evmCacheTests PRIVATE -fsanitize=address)
      if(ZEN_ENABLE_MULTIPASS_JIT)
        target_compile_options(evmJitFrontendTests PRIVATE -fsanitize=address)
        target_compile_options(evmRangeAnalyzerTests PRIVATE -fsanitize=address)
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
      if(ZEN_ENABLE_MULTIPASS_JIT)
        target_link_libraries(
          x86CgPeepholeTests
          PRIVATE compiler dtvmcore gtest_main -fsanitize=address
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
      endif()

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
      if(ZEN_ENABLE_MULTIPASS_JIT)
        target_link_libraries(
          x86CgPeepholeTests
          PRIVATE compiler dtvmcore gtest_main -fsanitize=address
                  -static-libasan
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
        target_link_libraries(
          dmirValidationTests
          PRIVATE compiler dtvmcore gtest_main -fsanitize=address
                  -static-libasan
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
        if(ZEN_ENABLE_DMIR_SHADOW_AUDIT)
          target_link_libraries(
            dmirShadowRuntimeTests
            PRIVATE compiler dtvmcore gtest_main -fsanitize=address
                    -static-libasan
            PUBLIC ${GTEST_BOTH_LIBRARIES}
          )
        endif()
      endif()

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
    if(ZEN_ENABLE_MULTIPASS_JIT)
      target_link_libraries(
        x86CgPeepholeTests
        PRIVATE compiler dtvmcore gtest_main
        PUBLIC ${GTEST_BOTH_LIBRARIES}
      )
      target_link_libraries(
        dmirValidationTests
        PRIVATE compiler dtvmcore gtest_main
        PUBLIC ${GTEST_BOTH_LIBRARIES}
      )
      if(ZEN_ENABLE_DMIR_SHADOW_AUDIT)
        target_link_libraries(
          dmirShadowRuntimeTests
          PRIVATE compiler dtvmcore gtest_main
          PUBLIC ${GTEST_BOTH_LIBRARIES}
        )
      endif()
    endif()

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
  if(ZEN_ENABLE_MULTIPASS_JIT)
    add_test(NAME x86CgPeepholeTests COMMAND x86CgPeepholeTests)
    add_test(NAME dmirValidationTests COMMAND dmirValidationTests)
    if(ZEN_ENABLE_DMIR_SHADOW_AUDIT)
      add_test(NAME dmirShadowRuntimeTests COMMAND dmirShadowRuntimeTests)
    endif()
    add_test(
      NAME x86CgPeepholeRuleGen
      COMMAND
        ${Python3_EXECUTABLE}
        ${CMAKE_SOURCE_DIR}/tools/test_x86_cg_peephole_generator.py
        ${CMAKE_SOURCE_DIR}
    )
    add_test(
      NAME x86CgPeepholeValidationMeta
      COMMAND
        ${Python3_EXECUTABLE}
        ${CMAKE_SOURCE_DIR}/tools/test_x86_cg_peephole_validation.py
        ${CMAKE_SOURCE_DIR} $<TARGET_FILE:x86CgPeepholeTests>
    )
    add_test(
      NAME x86CgPeepholeValidationReport
      COMMAND
        ${Python3_EXECUTABLE}
        ${CMAKE_SOURCE_DIR}/tools/test_report_x86_cg_peephole_validation.py
        ${CMAKE_SOURCE_DIR} $<TARGET_FILE:x86CgPeepholeTests>
    )
    add_test(
      NAME dmirRewriteRuleMeta
      COMMAND
        ${Python3_EXECUTABLE}
        ${CMAKE_SOURCE_DIR}/tools/test_check_dmir_rewrite_rules.py
        ${CMAKE_SOURCE_DIR} $<TARGET_FILE:dmirValidationTests>
    )
    add_test(
      NAME dmirRewriteRuleReport
      COMMAND
        ${Python3_EXECUTABLE}
        ${CMAKE_SOURCE_DIR}/tools/test_report_dmir_rewrite_rules.py
        ${CMAKE_SOURCE_DIR} $<TARGET_FILE:dmirValidationTests>
    )
    add_test(
      NAME dmirSeedRuleMiner
      COMMAND
        ${Python3_EXECUTABLE}
        ${CMAKE_SOURCE_DIR}/tools/test_mine_dmir_seed_rules.py
        ${CMAKE_SOURCE_DIR}
    )
    add_test(
      NAME dmirBootstrapMinerConfig
      COMMAND
        ${Python3_EXECUTABLE}
        ${CMAKE_SOURCE_DIR}/tools/test_mine_dmir_bootstrap_config.py
        ${CMAKE_SOURCE_DIR}
    )
    add_test(
      NAME dmirNovelRuleMiner
      COMMAND
        ${Python3_EXECUTABLE}
        ${CMAKE_SOURCE_DIR}/tools/test_mine_dmir_novel_rules.py
        ${CMAKE_SOURCE_DIR}
    )
    if(ZEN_ENABLE_EVM)
      add_test(
        NAME compilerPassTimingTool
        COMMAND
          ${Python3_EXECUTABLE}
          ${CMAKE_SOURCE_DIR}/tools/test_collect_compiler_pass_timings.py
          ${CMAKE_SOURCE_DIR} $<TARGET_FILE:dtvm>
      )
      add_test(
        NAME compilerPassTimingBudgetTool
        COMMAND
          ${Python3_EXECUTABLE}
          ${CMAKE_SOURCE_DIR}/tools/test_check_compiler_pass_timing_budget.py
          ${CMAKE_SOURCE_DIR}
      )
      add_test(
        NAME compilerPassTimingBudgetRefreshTool
        COMMAND
          ${Python3_EXECUTABLE}
          ${CMAKE_SOURCE_DIR}/tools/test_update_compiler_pass_timing_budget.py
          ${CMAKE_SOURCE_DIR}
      )
    endif()
  endif()

  if(ZEN_ENABLE_EVM)
    add_test(NAME evmInterpTests COMMAND evmInterpTests)
    add_test(NAME evmCacheTests COMMAND evmCacheTests)
    if(ZEN_ENABLE_MULTIPASS_JIT)
      add_test(NAME evmJitFrontendTests COMMAND evmJitFrontendTests)
      add_test(NAME evmRangeAnalyzerTests COMMAND evmRangeAnalyzerTests)
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
