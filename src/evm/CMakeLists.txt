set(EVM_SRCS interpreter.cpp opcode_handlers.cpp gas_storage_cost.cpp
             evm_cache.cpp
)

add_library(evm_arith_profile STATIC arith_profile.cpp)
add_library(evm OBJECT ${EVM_SRCS})

if(ZEN_EVM_CACHE_PROFILE)
  target_compile_definitions(evm PRIVATE ZEN_EVM_CACHE_PROFILE)
endif()

# ZEN_ENABLE_EVM_ARITH_PROFILE is applied at directory scope in
# src/CMakeLists.txt so the evm, vm, and runtime targets share one definition of
# class EVMResource.
