# Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set(UTILS_SRCS
    backtrace.cpp
    others.cpp
    wasm.cpp
    safe_map.cpp
    logging.cpp
    unicode.cpp
    statistics.cpp
)

if(ZEN_ENABLE_VIRTUAL_STACK)
  list(APPEND UTILS_SRCS virtual_stack.cpp)
endif()

if(ZEN_ENABLE_LINUX_PERF)
  list(APPEND UTILS_SRCS perf.cpp)
endif()

if(ZEN_ENABLE_EVM)
  list(APPEND UTILS_SRCS evm.cpp rlp_encoding.cpp)
endif()

add_library(utils OBJECT ${UTILS_SRCS})

if(ZEN_ENABLE_EVM)
  target_include_directories(utils PRIVATE ${rapidjson_SOURCE_DIR}/include)
endif()
