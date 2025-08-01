set(EVM_SRCS interpreter.cpp opcode_handlers.cpp gas_storage_cost.cpp)

add_library(evm OBJECT ${EVM_SRCS})
