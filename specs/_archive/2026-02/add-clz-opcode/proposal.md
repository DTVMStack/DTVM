# Add CLZ Opcode for EVM Osaka Revision

## Summary
Add the CLZ (Count Leading Zeros) opcode (0x1e) to DTVM's EVM implementation, supporting EIP-7939 for the Osaka revision and above.

## Motivation
EIP-7939 introduces the CLZ opcode to the EVM instruction set starting from the Osaka revision. This opcode counts the number of leading zero bits in a 256-bit unsigned integer, which is useful for:

1. **Efficient bit manipulation**: Provides a native way to determine the position of the most significant set bit
2. **Gas optimization**: Replaces expensive loop-based implementations with a single opcode
3. **Protocol compliance**: Required for Osaka revision compatibility

## What Changes
- Add CLZ opcode handler in the interpreter (`src/evm/opcode_handlers.h/cpp`)
- Add CLZ support in the EVM JIT compiler via runtime call (`evm_bytecode_visitor.h`, `evm_mir_compiler.h/cpp`, `evm_imported.h/cpp`)
- Integrate with existing revision-based opcode availability checks

## Impact
- Affected specs: `evm-execution`, `evm-jit`
- Affected code:
  - `src/evm/opcode_handlers.h` - Add CLZ handler definition
  - `src/evm/opcode_handlers.cpp` - Add CLZ handler implementation
  - `src/action/evm_bytecode_visitor.h` - Add CLZ case in bytecode visitor
  - `src/compiler/evm_frontend/evm_mir_compiler.h` - Add CLZ handler method
  - `src/compiler/evm_frontend/evm_mir_compiler.cpp` - Add CLZ handler implementation
  - `src/compiler/evm_frontend/evm_imported.h` - Add CLZ runtime function declaration
  - `src/compiler/evm_frontend/evm_imported.cpp` - Add CLZ runtime function implementation

## Success Criteria
- CLZ opcode returns EVMC_UNDEFINED_INSTRUCTION for revisions before Osaka
- CLZ opcode correctly counts leading zeros for all 256-bit inputs
- CLZ opcode consumes 5 gas (as per EIP-7939)
- All existing EVM tests continue to pass
- New CLZ-specific tests pass for both interpreter and JIT modes
