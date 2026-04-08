# EVM JIT Fallback Design

## Architecture Overview

The fallback mechanism involves three main components:

1. **EVMMirBuilder Fallback Interface**: Generates MIR instructions to capture state and call runtime
2. **Runtime Fallback Function**: Transfers execution state and creates interpreter instance
3. **Interpreter State Restoration**: Resumes execution from provided EVM state

## State Transfer Design

### EVM State Components
The following state must be preserved during fallback:

- **Program Counter (PC)**: Current bytecode position
- **Stack State**: Complete evaluation stack contents and size
- **Memory State**: Memory contents and size
- **Storage State**: Already handled by EVMInstance (no transfer needed)
- **Gas State**: Remaining gas and gas costs
- **Call Context**: Caller, value, calldata (already in EVMInstance)

### State Capture Mechanism

```cpp
// In EVMMirBuilder
void fallbackToInterpreter(uint64_t targetPC) {
  // 1. Save current PC
  // 2. Sync gas
  // 3. Flush stack state to EVMInstance
  // 4. Sync memory state
  // 5. Call runtime fallback function
  callRuntimeFor(RuntimeFunctions.HandleFallback, targetPC);
}
```

### Runtime Interface Design

```cpp
// New runtime function signature
using FallbackFn = void (*)(zen::runtime::EVMInstance *, uint64_t);

// Implementation
void evmHandleFallback(zen::runtime::EVMInstance *Instance, uint64_t PC);
```

## Interpreter Integration

### State Restoration
The interpreter must be enhanced to accept initial state:

```cpp
class EVMInterpreter {
  // New method for state-based execution
  evmc_result executeFromState(EVMInstance* instance, uint64_t startPC);

  // Restore stack from EVMInstance
  void restoreStackState(EVMInstance* instance);

  // Memory is already accessible via EVMInstance
};
```

### Execution Flow

1. **JIT Execution**: Normal compiled execution until fallback trigger
2. **State Capture**: EVMMirBuilder saves all volatile state to EVMInstance
3. **Runtime Transition**: Call evmHandleFallback with target PC
4. **Interpreter Creation**: Runtime creates new interpreter instance
5. **State Restoration**: Interpreter loads state from EVMInstance
6. **Continued Execution**: Interpreter resumes from specified PC

## Implementation Phases

### Phase 1: Basic Infrastructure
- Add fallbackToInterpreter method to EVMMirBuilder
- Implement evmHandleFallback runtime function
- Add executeFromState method to interpreter

### Phase 2: State Management
- Implement stack state synchronization
- Add memory state consistency checks
- Handle gas accounting across transition

### Phase 3: Integration & Testing
- Add fallback triggers for unsupported opcodes when block begins
- Use an undefined opcode to trigger fallback when testing macro defined
- Write unit tests for fallback mechanism

## Error Handling

### Fallback Triggers

The fallback mechanism will be triggered when the next JIT execution block has more than one of the following exceptions:

#### 1. Undefined Opcodes
- **Invalid instructions**: When encountering opcodes that are not defined in the current EVM revision
- **Unimplemented opcodes**: Instructions that exist in the specification but are not yet implemented in the JIT compiler

#### 2. Stack Overflow/Underflow
- **Stack overflow**: When stack operations would exceed the maximum stack size (1024 elements)
- **Stack underflow**: When attempting to pop from an empty stack or access stack elements that don't exist

#### 3. Out of Gas
- **Insufficient gas**: When remaining gas is not sufficient to complete the current operation
- **Gas limit exceeded**: When the total gas consumption would exceed the transaction gas limit

#### 4. Testing Triggers (Test Only)
- **FALLBACK opcode**: A specific undefined opcode designated as FALLBACK to trigger fallback mechanism during testing
- **Debug mode**: When testing macros are defined to force fallback for validation purposes

### Error Conditions
- Invalid PC values (must point to valid instruction boundary)
- Stack overflow/underflow during state transfer
- Memory inconsistencies between JIT and interpreter views
- Gas exhaustion during fallback process

## Performance Considerations

### Optimization Strategies
- Minimize state synchronization overhead
- Use efficient stack flushing mechanisms
- Avoid unnecessary memory copies
- Batch state updates when possible

### Performance Monitoring
- Track fallback frequency and triggers
- Measure state transfer overhead
- Monitor interpreter performance post-fallback
- Identify optimization opportunities

## Security & Determinism

### Deterministic Execution
- Ensure identical results across JIT/interpreter boundary
- Maintain consistent gas accounting
- Preserve exact stack and memory semantics
- Handle edge cases identically

### Security Considerations
- Validate all transferred state for consistency
- Prevent state corruption during transition
- Ensure proper error propagation
- Maintain execution context isolation
