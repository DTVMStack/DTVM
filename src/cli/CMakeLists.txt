# Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_executable(dtvm dtvm.cpp)
target_link_libraries(dtvm PRIVATE dtvmcore CLI11::CLI11)

if(ZEN_ENABLE_EVM)
  target_link_libraries(dtvm PUBLIC evmc::evmc evmc::instructions)
  add_executable(dtvm_evm_code_cache_bench evm_code_cache_bench.cpp)
  target_link_libraries(
    dtvm_evm_code_cache_bench
    PRIVATE dtvmcore CLI11::CLI11 rapidjson evmc::evmc evmc::instructions
  )
endif()

if(ZEN_ENABLE_PROFILER)
  target_link_libraries(dtvm PRIVATE profiler)
endif()
