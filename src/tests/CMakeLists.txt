# Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
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

  add_subdirectory(mpt)

  add_executable(specUnitTests spec_unit_tests.cpp spectest.cpp test_utils.cpp)
  add_executable(mempoolTests mempool_tests.cpp)
  add_executable(cAPITests c_api_tests.cpp)
  add_executable(evmInterpTests evm_interp_tests.cpp)
  add_executable(solidityContractTests solidity_contract_tests.cpp)
  add_executable(
    evmStateTests evm_state_tests.cpp evm_test_fixtures.cpp
                  evm_test_helpers.cpp
  )
  add_executable(mptCompareCpp mpt_compare_cpp.cpp)

  target_link_libraries(
    specUnitTests
    PRIVATE dtvmcore rapidjson gtest_main CLI11::CLI11
    PUBLIC ${GTEST_BOTH_LIBRARIES}
  )
  if(ZEN_BUILD_PLATFORM_LINUX)
    target_link_libraries(specUnitTests PRIVATE stdc++fs)
  endif()

  if(ZEN_ENABLE_ASAN)
    target_compile_options(mempoolTests PRIVATE -fsanitize=address)
    target_compile_options(cAPITests PRIVATE -fsanitize=address)
    target_compile_options(evmInterpTests PRIVATE -fsanitize=address)
    target_compile_options(solidityContractTests PRIVATE -fsanitize=address)
    target_compile_options(mptCompareCpp PRIVATE -fsanitize=address)

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
      target_link_libraries(
        evmInterpTests
        PRIVATE dtvmcore rapidjson yaml-cpp gtest_main -fsanitize=address
        PUBLIC ${GTEST_BOTH_LIBRARIES}
      )
      target_link_libraries(
        solidityContractTests
        PRIVATE dtvmcore rapidjson mpt gtest_main -fsanitize=address
        PUBLIC ${GTEST_BOTH_LIBRARIES}
      )
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
      target_link_libraries(
        mptCompareCpp PRIVATE dtvmcore rapidjson mpt -fsanitize=address
      )
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
        solidityContractTests
        PRIVATE dtvmcore
                rapidjson
                mpt
                gtest_main
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
      target_link_libraries(
        mptCompareCpp PRIVATE dtvmcore rapidjson mpt -fsanitize=address
                              -static-libasan
      )
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
    target_link_libraries(
      evmInterpTests
      PRIVATE dtvmcore rapidjson yaml-cpp gtest_main
      PUBLIC ${GTEST_BOTH_LIBRARIES}
    )
    target_link_libraries(
      solidityContractTests
      PRIVATE dtvmcore rapidjson mpt gtest_main
      PUBLIC ${GTEST_BOTH_LIBRARIES}
    )
    target_link_libraries(
      evmStateTests
      PRIVATE dtvmcore rapidjson mpt gtest_main
      PUBLIC ${GTEST_BOTH_LIBRARIES}
    )
    target_link_libraries(mptCompareCpp PRIVATE dtvmcore rapidjson mpt)
  endif()

  add_dependencies(specUnitTests spec_jsons)

  add_test(
    NAME specUnitTests
    COMMAND ${CMAKE_COMMAND} -DTEST_EXECUTABLE=$<TARGET_FILE:specUnitTests> -P
            ${CMAKE_CURRENT_SOURCE_DIR}/RunSpecTests.cmake
  )
  add_test(NAME mempoolTests COMMAND mempoolTests)
  add_test(NAME cAPITests COMMAND cAPITests)
  add_test(NAME evmInterpTests COMMAND evmInterpTests)
  add_test(NAME solidityContractTests COMMAND solidityContractTests)
  add_test(NAME evmStateTests COMMAND evmStateTests)
endif()
