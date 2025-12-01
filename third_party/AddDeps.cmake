# Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)

include(FetchContent)

if(ZEN_ENABLE_SINGLEPASS_JIT)
  set(ASMJIT_STATIC ON)
  set(ASMJIT_NO_FOREIGN ON)
  set(ASMJIT_NO_DEPRECATED ON)
  set(ASMJIT_NO_BUILDER ON)
  set(ASMJIT_NO_COMPILER ON)
  set(ASMJIT_NO_JIT ON)
  if(NOT ZEN_ENABLE_JIT_LOGGING)
    set(ASMJIT_NO_LOGGING ON)
  endif()
  set(ASMJIT_NO_INTROSPECTION ON)
  if(ZEN_ENABLE_SGX)
    set(PATCH_CMD
        git apply
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/asmjit/sgx_asmjit.patch
    )
  endif()
  FetchContent_Declare(
    asmjit
    URL https://github.com/asmjit/asmjit/archive/3577608cab0bc509f856ebf6e41b2f9d9f71acc4.zip
    URL_HASH
      SHA256=4845eb9d9e6e8da34694c451a00bc3a4c02fe1f60e12dbde9f09ae5ecb690528
    PATCH_COMMAND ${PATCH_CMD}
  )
  # FetchContent_Declare( asmjit GIT_REPOSITORY
  # https://github.com/asmjit/asmjit.git GIT_COMMIT
  # 3577608cab0bc509f856ebf6e41b2f9d9f71acc4 GIT_SHALLOW TRUE PATCH_COMMAND
  # ${PATCH_CMD} )
  FetchContent_MakeAvailable(asmjit)
endif()

if(ZEN_ENABLE_SPDLOG)
  FetchContent_Declare(
    spdlog
    URL https://github.com/gabime/spdlog/archive/v1.4.2.tar.gz
    URL_HASH
      SHA256=821c85b120ad15d87ca2bc44185fa9091409777c756029125a02f81354072157
  )
  FetchContent_MakeAvailable(spdlog)
  include_directories(${spdlog_SOURCE_DIR}/include)
endif()

FetchContent_Declare(
  CLI11
  GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
  GIT_TAG v2.3.2
  GIT_SHALLOW TRUE
)
set(CLI11_SINGLE_FILE OFF)
set(CLI11_PRECOMPILED ON)
set(CLI11_BUILD_DOCS OFF)
set(CLI11_BUILD_EXAMPLES OFF)
set(CLI11_BUILD_EXAMPLES_JSON OFF)
set(CLI11_INSTALL OFF)
set(CLI11_BUILD_TESTS OFF)
FetchContent_MakeAvailable(CLI11)

FetchContent_Declare(
  intx
  GIT_REPOSITORY https://github.com/chfast/intx.git
  GIT_TAG v0.9.3
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(intx)
include_directories(${intx_SOURCE_DIR}/include)

FetchContent_Declare(
  boost
  URL https://sourceforge.net/projects/boost/files/boost/1.67.0/boost_1_67_0.tar.bz2/download
  DOWNLOAD_NAME boost_1_67_0.tar.bz2
  URL_HASH
    SHA256=2684c972994ee57fc5632e03bf044746f6eb45d4920c343937a465fd67a5adba
)
FetchContent_GetProperties(boost)
if(NOT boost_POPULATED)
  FetchContent_Populate(boost)
endif()
include_directories(${boost_SOURCE_DIR})

if(ZEN_ENABLE_SPEC_TEST)
  FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.11.0
    GIT_SHALLOW TRUE
  )
  set(BUILD_GMOCK OFF)
  set(INSTALL_GTEST OFF)
  FetchContent_MakeAvailable(googletest)

  FetchContent_Declare(
    rapidjson
    URL https://github.com/Tencent/rapidjson/archive/06d58b9e848c650114556a23294d0b6440078c61.zip
    URL_HASH
      SHA256=05562af69b62d0a203ae1ecd914bf8e501cde630078bf82384485e9b85e7bf55
    # GIT_REPOSITORY https://github.com/Tencent/rapidjson.git GIT_COMMIT
    # 06d58b9e848c650114556a23294d0b6440078c61 GIT_SHALLOW TRUE
  )
  set(RAPIDJSON_BUILD_DOC OFF)
  set(RAPIDJSON_BUILD_EXAMPLES OFF)
  set(RAPIDJSON_BUILD_TESTS OFF)
  set(RAPIDJSON_BUILD_CXX11 OFF)
  set(RAPIDJSON_BUILD_CXX17 ON)
  FetchContent_MakeAvailable(rapidjson)
  add_library(rapidjson INTERFACE)
  target_include_directories(
    rapidjson INTERFACE ${rapidjson_SOURCE_DIR}/include
  )

  FetchContent_Declare(
    yaml-cpp
    GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
    GIT_TAG 0.8.0
    GIT_SHALLOW TRUE
  )
  set(YAML_CPP_BUILD_TESTS OFF)
  set(YAML_CPP_BUILD_TOOLS OFF)
  set(YAML_CPP_BUILD_CONTRIB OFF)
  set(YAML_CPP_INSTALL OFF)
  FetchContent_MakeAvailable(yaml-cpp)
endif()
