# Copyright (C) 2025-2026 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Only build EVMC VM interface if EVM support is enabled
if(ZEN_ENABLE_EVM)
  set(VM_SRCS dt_evmc_vm.cpp)

  add_library(dtvmapi SHARED ${VM_SRCS})

  target_link_libraries(dtvmapi PRIVATE dtvmcore CLI11::CLI11)

  set(PROJECT_VERSION 0.18.0)

  string(REGEX MATCH "([0-9]+)\\.([0-9]+)" _ ${PROJECT_VERSION})
  set(PROJECT_VERSION_MAJOR ${CMAKE_MATCH_1})
  set(PROJECT_VERSION_MINOR ${CMAKE_MATCH_2})

  set(PROJECT_SOVERSION ${PROJECT_VERSION_MAJOR})
  if(PROJECT_VERSION_MAJOR EQUAL 0)
    set(PROJECT_SOVERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR})
  endif()

  set(PROJECT_VERSION 0.1.0)

  string(REGEX MATCH "([0-9]+)\\.([0-9]+)" _ ${PROJECT_VERSION})
  set(PROJECT_VERSION_MAJOR ${CMAKE_MATCH_1})
  set(PROJECT_VERSION_MINOR ${CMAKE_MATCH_2})

  set(PROJECT_SOVERSION ${PROJECT_VERSION_MAJOR})
  if(PROJECT_VERSION_MAJOR EQUAL 0)
    set(PROJECT_SOVERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR})
  endif()

  # Configure export symbols and linking options
  set_target_properties(
    dtvmapi
    PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
               # Export only the EVMC interface symbols
               CXX_VISIBILITY_PRESET hidden
               VISIBILITY_INLINES_HIDDEN ON
               # Set proper SONAME for shared library
               VERSION ${PROJECT_VERSION}
               SOVERSION ${PROJECT_SOVERSION}
  )

  # Define EVMC_EXPORT for proper symbol visibility

  target_compile_options(dtvmapi PRIVATE "-fvisibility=hidden")
  target_link_options(dtvmapi PRIVATE "-Wl,--exclude-libs,ALL")

  # Link with EVMC library if available
  if(TARGET evmc::evmc)
    target_link_libraries(dtvmapi PRIVATE evmc::evmc evmc::instructions)
  endif()

  # Configure static linking for cross-environment compatibility This ensures
  # the library can run on different Linux distributions without requiring
  # specific libstdc++ versions
  target_link_options(dtvmapi PRIVATE -static-libstdc++ -static-libgcc)

  # Install the library
  install(
    TARGETS dtvmapi
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
  )

  # Install the header file
  install(FILES dt_evmc_vm.h DESTINATION include/dtvm)
endif()
