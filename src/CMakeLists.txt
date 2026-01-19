# Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

if(ZEN_BUILD_PLATFORM_LINUX)
  add_definitions(-DZEN_BUILD_PLATFORM_LINUX -DZEN_BUILD_PLATFORM_POSIX)
elseif(ZEN_BUILD_PLATFORM_DARWIN)
  add_definitions(-DZEN_BUILD_PLATFORM_DARWIN -DZEN_BUILD_PLATFORM_POSIX)
endif()

if(ZEN_BUILD_TARGET_X86_64)
  add_definitions(-DZEN_BUILD_TARGET_X86_64)
elseif(ZEN_BUILD_TARGET_AARCH64)
  add_definitions(-DZEN_BUILD_TARGET_AARCH64)
endif()

if(ZEN_ENABLE_BUILTIN_WASI)
  add_definitions(-DZEN_ENABLE_BUILTIN_WASI)
endif()

if(ZEN_ENABLE_BUILTIN_ENV)
  add_definitions(-DZEN_ENABLE_BUILTIN_ENV)
endif()

if(ZEN_ENABLE_EVMABI_TEST)
  add_definitions(-DZEN_ENABLE_EVMABI_TEST)
endif()

if(ZEN_ENABLE_CHECKED_ARITHMETIC)
  add_definitions(-DZEN_ENABLE_CHECKED_ARITHMETIC)
endif()

if(ZEN_ENABLE_SPEC_TEST)
  add_definitions(-DZEN_ENABLE_SPEC_TEST)
endif()

if(ZEN_ENABLE_DWASM)
  add_definitions(-DZEN_ENABLE_DWASM)
endif()

if(ZEN_ENABLE_VIRTUAL_STACK)
  add_definitions(-DZEN_ENABLE_VIRTUAL_STACK)
endif()

if(ZEN_ENABLE_PROFILER)
  add_definitions(-DZEN_ENABLE_PROFILER)
endif()

if(ZEN_ENABLE_DEBUG_INTERP)
  add_definitions(-DZEN_ENABLE_DEBUG_INTERP)
endif()

if(ZEN_ENABLE_LINUX_PERF)
  add_definitions(-DZEN_ENABLE_LINUX_PERF)
endif()

if(ZEN_DISABLE_CXX17_STL)
  add_definitions(-DZEN_DISABLE_CXX17_STL)
endif()

if(ZEN_ENABLE_SPDLOG)
  add_definitions(-DZEN_ENABLE_SPDLOG)
endif()

if(ZEN_ENABLE_EVM)
  add_definitions(-DZEN_ENABLE_EVM)
endif()

if(ZEN_ENABLE_CPU_EXCEPTION)
  if(ZEN_ENABLE_SINGLEPASS_JIT OR ZEN_ENABLE_MULTIPASS_JIT)
    add_definitions(-DZEN_ENABLE_CPU_EXCEPTION)
  endif()

  if(NOT ZEN_ENABLE_VIRTUAL_STACK AND NOT ZEN_ENABLE_DWASM)
    add_definitions(-DZEN_ENABLE_STACK_CHECK_CPU)
  endif()
endif()

if(ZEN_ENABLE_SINGLEPASS_JIT)
  add_definitions(-DZEN_ENABLE_JIT)
  add_definitions(-DZEN_ENABLE_SINGLEPASS_JIT)

  if(ZEN_ENABLE_JIT_LOGGING)
    add_definitions(-DZEN_ENABLE_SINGLEPASS_JIT_LOGGING)
  endif()

  if(ZEN_ENABLE_DUMP_CALL_STACK)
    add_compile_options(-fno-omit-frame-pointer)
    add_definitions(-DZEN_ENABLE_DUMP_CALL_STACK)
  endif()
endif()

if(ZEN_ENABLE_MULTIPASS_JIT)
  find_package(LLVM 15 REQUIRED CONFIG)
  message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
  message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
  include_directories(
    ${LLVM_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/compiler/llvm-prebuild/Target/X86
    ${CMAKE_CURRENT_SOURCE_DIR}/compiler
  )
  add_definitions(${LLVM_DEFINITIONS})

  add_definitions(-DZEN_ENABLE_JIT)
  add_definitions(-DZEN_ENABLE_MULTIPASS_JIT)

  if(ZEN_ENABLE_JIT_LOGGING)
    add_definitions(-DLLVM_ENABLE_DUMP -DZEN_ENABLE_MULTIPASS_JIT_LOGGING)
  endif()

  if(ZEN_ENABLE_DEBUG_GREEDY_RA)
    add_definitions(-DZEN_ENABLE_DEBUG_GREEDY_RA)
  endif()

  if(ZEN_ENABLE_DUMP_CALL_STACK)
    add_compile_options(-fno-omit-frame-pointer)
    add_definitions(-DZEN_ENABLE_DUMP_CALL_STACK)
  endif()

  if(ZEN_ENABLE_EVM_GAS_REGISTER AND ZEN_BUILD_TARGET_X86_64)
    add_definitions(-DZEN_ENABLE_EVM_GAS_REGISTER)
  endif()
endif()

if(ZEN_ENABLE_SGX)
  add_definitions(-DZEN_ENABLE_SGX)
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -nostdlib")
  add_compile_options(-Wl,nostdlib -Wl,nostdinc++ -Wl,nodefaultlibs)
  add_compile_options(-nostdlib -nostdinc++)
  list(REMOVE_ITEM CMAKE_CXX_IMPLICIT_LINK_LIBRARIES stdc++)
  include_directories(/opt/intel/sgxsdk/include)
  include_directories(/opt/intel/sgxsdk/include/libcxx)
  include_directories(/opt/intel/sgxsdk/include/stdc++)
  include_directories(/opt/intel/sgxsdk/include/tlibc)
  include_directories(/opt/intel/sgxsdk/include/tlibc/linux)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(common)
add_subdirectory(platform)
add_subdirectory(action)
add_subdirectory(entrypoint)
add_subdirectory(runtime)
add_subdirectory(utils)
if(ZEN_ENABLE_EVM)
  add_subdirectory(evm)
  if(ZEN_ENABLE_LIBEVM)
    add_subdirectory(vm)
  endif()
endif()

add_library(
  dtvmcore STATIC
  $<$<BOOL:${ZEN_ENABLE_EVM}>:$<TARGET_OBJECTS:evm>>
  $<TARGET_OBJECTS:action>
  $<TARGET_OBJECTS:common>
  $<TARGET_OBJECTS:entrypoint>
  $<TARGET_OBJECTS:platform>
  $<TARGET_OBJECTS:runtime>
  $<TARGET_OBJECTS:utils>
  zetaengine-c.cpp
)
if(ZEN_ENABLE_EVM)
  target_link_libraries(dtvmcore PUBLIC evmc::instructions)
endif()
if(NOT ZEN_ENABLE_SGX)
  target_link_libraries(dtvmcore PRIVATE Threads::Threads)
endif()
if(ZEN_ENABLE_SPDLOG)
  target_link_libraries(dtvmcore PRIVATE spdlog::spdlog)
endif()

if(ZEN_ENABLE_SINGLEPASS_JIT)
  add_subdirectory(singlepass)
  target_link_libraries(dtvmcore PRIVATE singlepass)
endif()

if(ZEN_ENABLE_MULTIPASS_JIT)
  add_subdirectory(compiler)
  target_link_libraries(dtvmcore PRIVATE compiler)
endif()

if(NOT ZEN_ENABLE_SGX)
  add_subdirectory(host)
  target_link_libraries(dtvmcore PRIVATE $<TARGET_NAME_IF_EXISTS:host>)

  if(ZEN_ENABLE_CLI)
    add_subdirectory(cli)
  endif()

  if(ZEN_ENABLE_SPEC_TEST)
    add_subdirectory(tests)
  endif()
endif()
