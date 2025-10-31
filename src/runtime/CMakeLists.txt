# Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set(RUNTIME_SRCS
    vnmi.cpp
    wni.cpp
    runtime.cpp
    isolation.cpp
    module.cpp
    instance.cpp
    codeholder.cpp
    destroyer.cpp
    memory.cpp
)

if(ZEN_ENABLE_EVM)
  list(APPEND RUNTIME_SRCS evm_module.cpp evm_instance.cpp)
endif()

add_library(runtime OBJECT ${RUNTIME_SRCS})
