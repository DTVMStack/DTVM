# Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set(COMMON_SRCS const_string_pool.cpp errors.cpp traphandler.cpp)

if(ZEN_ENABLE_EVM)
  list(APPEND COMMON_SRCS evm_traphandler.cpp)
endif()

add_library(common OBJECT ${COMMON_SRCS})
