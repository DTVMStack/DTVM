# Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

if(ZEN_ENABLE_BUILTIN_WASI)
  add_subdirectory(wasi)
  list(APPEND HOST_OBJECTS $<TARGET_OBJECTS:host_wasi>)
endif()

if(ZEN_ENABLE_BUILTIN_ENV)
  add_subdirectory(env)
  list(APPEND HOST_OBJECTS $<TARGET_OBJECTS:host_env>)
endif()

if(ZEN_ENABLE_SPEC_TEST)
  add_subdirectory(spectest)
  list(APPEND HOST_OBJECTS $<TARGET_OBJECTS:host_spectest>)
endif()

if(ZEN_ENABLE_EVMABI_TEST)
  add_subdirectory(evmabimock)
  list(APPEND HOST_OBJECTS $<TARGET_OBJECTS:host_evmabimock>)
endif()

if(HOST_OBJECTS)
  add_library(host STATIC ${HOST_OBJECTS})
endif()
