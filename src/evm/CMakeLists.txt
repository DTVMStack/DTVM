set(EVM_SRCS interpreter.cpp opcode_handlers.cpp crypto.cpp)

add_library(evm OBJECT ${EVM_SRCS})
