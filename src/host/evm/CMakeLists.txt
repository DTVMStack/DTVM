# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set(HOST_EVM_SRCS crypto.cpp keccak/keccak.c)

add_library(host_evm OBJECT ${HOST_EVM_SRCS})

target_include_directories(host_evm PRIVATE ${CMAKE_SOURCE_DIR}/src)
