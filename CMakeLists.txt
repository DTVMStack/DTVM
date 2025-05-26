# Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.16)

project(ZetaEngine LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})

# Component options
option(ZEN_ENABLE_SINGLEPASS_JIT "Enable singlepass JIT" ON)
option(ZEN_ENABLE_MULTIPASS_JIT "Enable multipass JIT" OFF)
option(ZEN_ENABLE_CLI "Enable command line interface" ON)
option(ZEN_ENABLE_BUILTIN_WASI "Enable builtin wasi" ON)
option(ZEN_ENABLE_BUILTIN_LIBC "Enable builtin libc (partial)" ON)

# Feature options
option(ZEN_ENABLE_CPU_EXCEPTION "Enable cpu trap to implement wasm trap" ON)
option(ZEN_ENABLE_VIRTUAL_STACK "Enable virtual stack(no system stack)" OFF)
option(ZEN_ENABLE_DUMP_CALL_STACK "Enable exception call stack dump" OFF)

# Blockchain options
option(ZEN_ENABLE_CHECKED_ARITHMETIC "Enable checked arithmetic" OFF)
option(ZEN_ENABLE_DWASM "Enable DWasm spec" OFF)

# Library options
option(ZEN_ENABLE_SGX "Enable SGX" OFF)

# Debug options
option(ZEN_ENABLE_ASAN "Enable Asan" OFF)
option(ZEN_ENABLE_DEBUG_INTERP "Enable debug interpreter" OFF)
option(ZEN_ENABLE_JIT_LOGGING "Enable logging in JIT" OFF)
option(ZEN_ENABLE_DEBUG_GREEDY_RA "Enable debug greedy ra" OFF)

# Profiling options
option(ZEN_ENABLE_PROFILER "Enable profiler" OFF)
option(ZEN_ENABLE_LINUX_PERF "Enable linux perf" OFF)

# Test options
option(ZEN_ENABLE_SPEC_TEST "Enable spec test" OFF)
option(ZEN_ENABLE_ASSEMBLYSCRIPT_TEST "Enable AssemblyScript test" OFF)
option(ZEN_ENABLE_MOCK_CHAIN_TEST "Enable mock chain hostapis for test" OFF)
option(ZEN_ENABLE_EVMABI_TEST "Enable evmabi test" OFF)
option(ZEN_ENABLE_COVERAGE "Enable coverage test" OFF)

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
  set(ZEN_BUILD_TARGET_X86_64 ON)
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64" OR CMAKE_SYSTEM_PROCESSOR
                                                  STREQUAL "aarch64"
)
  set(ZEN_BUILD_TARGET_AARCH64 ON)
else()
  message(FATAL_ERROR "Unsupported CPU Architecture: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(ZEN_BUILD_PLATFORM_LINUX ON)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  set(ZEN_BUILD_PLATFORM_DARWIN ON)
else()
  message(FATAL_ERROR "Unsupported OS: ${CMAKE_SYSTEM_NAME}")
endif()

if(ZEN_ENABLE_SGX)
  set(ZEN_DISABLE_CXX17_STL ON)
  message(STATUS "Disable C++17 STL for SGX")
  set(ZEN_ENABLE_SPDLOG OFF)
  message(STATUS "Disable spdlog for SGX")
else()
  set(ZEN_DISABLE_CXX17_STL OFF)
  set(ZEN_ENABLE_SPDLOG ON)
  message(STATUS "Enable spdlog")
endif()

if(ZEN_ENABLE_ASAN)
  if(NOT ZEN_ENABLE_VIRTUAL_STACK)
    add_compile_options(-fsanitize=address)
    if(ZEN_BUILD_PLATFORM_DARWIN)
      add_link_options(-fsanitize=address)
    else()
      add_link_options(-fsanitize=address -static-libasan)
    endif()
  endif()
endif()

if(ZEN_ENABLE_MOCK_CHAIN_TEST)
  if(ZEN_ENABLE_BUILTIN_LIBC)
    set(ZEN_ENABLE_BUILTIN_LIBC OFF)
    message(WARNING "Disable builtin libc for mock chain test")
  endif()
  if(ZEN_ENABLE_ASSEMBLYSCRIPT_TEST)
    set(ZEN_ENABLE_ASSEMBLYSCRIPT_TEST OFF)
    message(WARNING "Disable AssemblyScript test for mock chain test")
  endif()
endif()

if(ZEN_ENABLE_BUILTIN_LIBC
   OR ZEN_ENABLE_MOCK_CHAIN_TEST
   OR ZEN_ENABLE_ASSEMBLYSCRIPT_TEST
)
  set(ZEN_ENABLE_BUILTIN_ENV ON)
endif()

if(ZEN_ENABLE_EVMABI_TEST)
  set(ZEN_ENABLE_EVMABI_TEST ON)
endif()

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/third_party")

include(AddDeps)

add_compile_options(
  -Wall -Wextra -Wno-unused-parameter $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>
  $<$<COMPILE_LANGUAGE:CXX>:-Wno-invalid-offsetof>
)

if(ZEN_ENABLE_COVERAGE)
  add_compile_options(--coverage)
  add_link_options(--coverage)
endif()

if(ZEN_ENABLE_SPEC_TEST)
  enable_testing()
endif()

include_directories(src)

add_subdirectory(src)
