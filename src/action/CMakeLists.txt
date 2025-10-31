# Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set(ACTION_SRCS instantiator.cpp interpreter.cpp compiler.cpp module_loader.cpp
                function_loader.cpp
)

add_library(action OBJECT ${ACTION_SRCS})

if(ZEN_ENABLE_EVM)
  target_link_libraries(action PUBLIC evmc::evmc)
endif()
