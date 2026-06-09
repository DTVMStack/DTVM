set(EVM_SRCS interpreter.cpp opcode_handlers.cpp gas_storage_cost.cpp
             evm_cache.cpp arith_profile.cpp
)

add_library(evm OBJECT ${EVM_SRCS})

if(ZEN_EVM_CACHE_PROFILE)
  target_compile_definitions(evm PRIVATE ZEN_EVM_CACHE_PROFILE)
endif()

if(ZEN_ENABLE_EVM_ARITH_PROFILE)
  target_compile_definitions(evm PRIVATE ZEN_ENABLE_EVM_ARITH_PROFILE)
endif()
