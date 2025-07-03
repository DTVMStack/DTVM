This document describes how to make DTVM a multi-bytecode virtual machine that supports EVM and other bytecodes, enabling support for different contract ecosystems on the same underlying architecture, providing high-performance, secure, and deterministic contract execution environments for multiple ecosystems.

# Differences Between EVM and WASM Bytecode

## Execution Model
1. EVM: Stack-based virtual machine

## Instruction Set Differences
1. WASM instruction set: Register/local variable-based instruction set, such as `local.get`, `local.set`, [https://webassembly.github.io/spec/core/appendix/index-instructions.html](https://webassembly.github.io/spec/core/appendix/index-instructions.html)

2. EVM instruction set: Stack-based instruction set, such as `PUSH1`, `DUP1`, `SWAP1` and other stack element operations.

    1. [https://www.ethervm.io/](https://www.ethervm.io/)

    2. [https://www.evm.codes/](https://www.evm.codes/)

    3. [https://ethereum.github.io/yellowpaper/paper.pdf](https://ethereum.github.io/yellowpaper/paper.pdf)

3. Control Flow Structure

    1. WASM: Uses structured control flow (`block`, `loop`, `if`)

    2. EVM: Uses `JUMP` and `JUMPI` for jumps ==> Arbitrary jumps in DMIR basic blocks

4. Memory instructions, such as mstore, need to consider EVM memory auto-growth during design, and gas consumption, with growth size limited by gas amount.

## Function Differences
EVM has no functions, so the entire program is a whole, with non-sequential access implemented through jump instructions internally.

## Data Type Differences

1. WASM: i32, i64, f32, f64

2. EVM: The basic type operated by opcodes is u256

## Gas Differences
1. WASM itself has no gas concept, typically charged by basic block for contracts; EVM deducts gas at instruction granularity.

# Basic Modifications

## Command Line Interface Extension

Extend compilation parameter options in `src/cli/dtvm.cpp`, support command line parameter `--format` to configure whether to parse file format as `wasm` bytecode or `evm` bytecode, and choose different file loading and parsing methods based on specific bytecode type.

```cpp
// src/cli/dtvm.cpp
enum class InputFormat {
    WASM,
    EVM
};

int main(int argc, char *argv[]) {
    /*...*/
    CLIParser->add_option("INPUT_FILE", Filename, "input filename")
        ->required();

    CLIParser->add_option("--format", ...);
    /*...*/
}
```

## EVM-Compatible Compilation Interface

```cpp
// src/compiler/compiler.h
class JITCompilerBase {
public:
    // Add EVM compilation support
    void compileEVMModule(runtime::Module& module);
protected:
    // Internal implementation
    void compileEVMFunction(EVMFrontendContext& context, uint32_t func_idx);
};
```

## Context Parsing

Current architecture: WASM bytecode → WASMByteCodeVisitor → FunctionMirBuilder → dMIR

Extended support architecture: EVM bytecode → EVMByteCodeVisitor → (EVM has no function concept, only construct one main function) → dMIR

### Loading EVM Bytecode

Extend runtime-related interfaces to be compatible with EVM bytecode.

```cpp
// src/runtime/codeholder.h
// Extend class CodeHolder, add related methods
class CodeHolder : public RuntimeObject<CodeHolder> {
public:
    enum class HolderKind {
        kFile,
        kRawData,
        kEVMBytecode  // EVM bytecode holder type
    };

    // Add EVM-specific constructor
    static CodeHolderUniquePtr newEVMBytecodeHolder(Runtime &RT, const void *Data, size_t Size);

    // Check if it's EVM bytecode
    bool isEVMBytecode() const { return Kind == HolderKind::kEVMBytecode; }

private:
    void releaseEVMBytecodeHolder();
};
```

```cpp
// src/runtime/module.h
struct EVMMetadata {
    std::vector<uint8_t> bytecode;
    std::unordered_set<size_t> jump_targets;
    std::vector<action::EVMInstruction> instructions;
    bool is_evm_module = false;
};

class Module {
public:
    // Add EVM support
    void setEVMMetadata(const EVMMetadata& metadata) {
        evm_metadata = metadata;
        evm_metadata.is_evm_module = true;
    }

    const EVMMetadata& getEVMMetadata() const {
        return evm_metadata;
    }

    bool isEVMModule() const {
        return evm_metadata.is_evm_module;
    }

private:
    EVMMetadata evm_metadata;
};
```

```cpp
// src/runtime/runtime.h
class Runtime {
public:
    MayBe<Module *> loadEVMModule(const std::string &Filename, common::RunMode mode = common::RunMode::MultipassJIT) noexcept;

    MayBe<Module *> loadEVMModule(const std::string &ModName, const void *Data, size_t Size, common::RunMode mode = common::RunMode::MultipassJIT) noexcept;
};
```

### Parsing EVM Bytecode

The implementation in `src/action/module_loader.h` parses `wasm` binary bytecode. Based on EVM binary bytecode characteristics, we need to add EVMModuleLoader type to parse EVM bytecode.

```cpp
// src/action/evm_module_loader.h
// EVM instruction structure
struct EVMInstruction {
    uint8_t opcode;
    std::vector<uint8_t> data;
    size_t pc;
    size_t size;
};

class EVMModuleLoader {
public:
    using Byte = common::Byte;

    explicit EVMModuleLoader(runtime::Module &mod, const Byte *data, size_t size)
        : mod(mod), data(data), size(size), ptr(data), end(data + size) {}

    void load();

private:
    uint8_t readByte() {
        if (ptr >= end) {
            throw common::getError(common::ErrorCode::UnexpectedEnd);
        }
        return *ptr++;
    }

    std::vector<uint8_t> readBytes(size_t n) {
        if (ptr + n > end) {
            throw common::getError(common::ErrorCode::UnexpectedEnd);
        }
        std::vector<uint8_t> result(ptr, ptr + n);
        ptr += n;
        return result;
    }

    // EVM bytecode parsing methods
    EVMInstruction parseInstruction();
    void parseAllInstructions();
    void analyzeJumpTargets();
    void createMainFunction();

    runtime::Module &mod;
    const Byte *data;
    size_t size;
    const Byte *ptr;
    const Byte *end;
    std::vector<EVMInstruction> instructions;
    std::unordered_set<size_t> jump_targets;
};
```

### Visiting EVM Bytecode

Reference `template <typename IRBuilder> class WASMByteCodeVisitor` in `src/action/bytecode_visitor.h`

```cpp
// src/action/evm_bytecode_visitor.h
// EVM stack management
template <typename Operand>
class EVMEvalStack {
public:
    void push(Operand op) { stack_impl.push(op); }

    Operand pop() {
        ZEN_ASSERT(!stack_impl.empty());
        Operand top = stack_impl.top();
        stack_impl.pop();
        return top;
    }

    Operand peek(size_t depth = 0) const {
        ZEN_ASSERT(depth < stack_impl.size());
        auto it = stack_impl._Get_container().rbegin() + depth;
        return *it;
    }

    size_t size() const { return stack_impl.size(); }

    bool empty() const { return stack_impl.empty(); }

private:
    std::stack<Operand> stack_impl;
};

// EVM bytecode visitor
template <typename IRBuilder>
class EVMByteCodeVisitor {
    typedef typename IRBuilder::CompilerContext CompilerContext;
    typedef typename IRBuilder::Operand Operand;
    typedef EVMEvalStack<Operand> EvalStack;

public:
    EVMByteCodeVisitor(IRBuilder& builder, CompilerContext* ctx)
        : builder(builder), ctx(ctx) {}

    bool compile() {
        builder.initFunction(ctx);
        bool ret = processInstructions();
        builder.finalizeFunctionBase();
        return ret;
    }

private:
    void push(Operand opnd) { stack.push(opnd); }

    Operand pop() {
        Operand opnd = stack.pop();
        builder.releaseOperand(opnd);
        return opnd;
    }

    bool processInstructions() {
        const auto& instructions = ctx->getEVMInstructions();
        const auto& jump_targets = ctx->getEVMJumpTargets();

        // Create entry basic block
        builder.createBasicBlock(0);

        // Create basic block for each jump target
        for (size_t pc : jump_targets) {
            builder.createBasicBlock(pc);
        }

        // Process all instructions
        for (const auto& inst : instructions) {
            // Check if it's a jump target
            if (jump_targets.count(inst.pc) > 0) {
                builder.setInsertBlock(inst.pc);
            }

            // Process instruction
            processInstruction(inst);
        }

        return true;
    }

    void processInstruction(const zen::action::EVMInstruction& inst) {
        switch (inst.opcode) {
            case 0x00: handleStop(); break;   // STOP
            case 0x01: handleAdd(); break;    // ADD
            // ... other arithmetic instructions ...
            // ... other comparison instructions ...
            // ... other memory instructions ...
            // PUSH instructions (0x60-0x7f)
            // DUP instructions (0x80-0x8f)
            // SWAP instructions (0x90-0x9f)
            // ... other instructions ...

            default:
                handleUnsupportedOpcode(inst.opcode);
        }
    }

    // Instruction handling functions
    void handleStop() {
        builder.handleStop();
    }
    // ... other instruction handling functions ...

private:
    IRBuilder& builder;
    CompilerContext* ctx;
    EvalStack stack;
};
```

### Parsing Validation and Exception Handling

1. Bytecode size not exceeding 24KB: If bytecode is too large, fallback to interpreter mode to avoid overly large dMIR functions that are difficult to test boundaries.
2. Opcode validity (0x00-0xff): Invalid opcodes need prompts but don't affect subsequent bytecode parsing.
3. Operand completeness (PUSH1-PUSH32 must have sufficient subsequent bytes): Record incomplete operands but don't exit abnormally. Parse needs to consider cases where there aren't enough subsequent parameters.
4. JUMP/JUMPI instruction jump targets must be JUMPDEST opcodes, otherwise report errors during execution phase.
5. Jump targets or after JUMPDEST must be at instruction beginning, not in the middle of instructions: Invalid jump targets fallback to interpreter mode.
6. Overly simple instructions or bytecode with frequent Host calls can fallback to interpreter mode to avoid JIT overhead of saving and restoring state when calling Host functions.

```cpp
// src/action/evm_bytecode_validator.h
// EVM validation result
enum class EVMValidationResult {
    Valid,                  // Bytecode valid
    TooLarge,               // Bytecode too large
    InvalidOpcode,          // Invalid opcode
    IncompleteOperand,      // Incomplete operand
    InvalidJumpTarget,      // Invalid jump target
    CompilationError        // Compilation error
};

// EVM instruction structure
struct EVMInstruction {
    uint8_t opcode;
    std::vector<uint8_t> data;
    size_t pc;
    size_t size;
};

class EVMBytecodeValidator {
public:
    using Byte = common::Byte;
    using RunMode = common::RunMode;

    EVMBytecodeValidator(const Byte* data, size_t size)
        : data(data), size(size), ptr(data), end(data + size),
          run_mode(RunMode::InterpMode) {}

    // Execute all validations
    EVMValidationResult validate();

    // Get validated jump targets
    const std::unordered_set<size_t>& getJumpTargets() const { return jump_targets; }

    // Get validated instruction list
    const std::vector<EVMInstruction>& getInstructions() const { return instructions; }

private:
    // Various validation methods
    EVMValidationResult validateSize();
    EVMValidationResult validateOpcodes();
    EVMValidationResult validateOperands();
    EVMValidationResult validateJumpTargets();

    // Parse instructions
    bool parseInstructions();

    // Member variables
    const Byte* data;
    size_t size;
    const Byte* ptr;
    const Byte* end;
    std::vector<EVMInstruction> instructions;
    std::unordered_set<size_t> jump_targets;
    std::unordered_set<size_t> jump_destinations;  // JUMPDEST positions
    RunMode run_mode;  // Run mode: interpreter/singlepass/multipass
};
```

### Adding Context Content

```cpp
// src/compiler/evm_frontend/evm_mir_compiler.h
class EVMFrontendContext final : public CompileContext {
public:
    EVMFrontendContext(const runtime::Module& mod)
        : CompileContext(), module(mod) {}

    const std::vector<zen::action::EVMInstruction>& getEVMInstructions() const;
    const std::unordered_set<size_t>& getEVMJumpTargets() const;
    const std::vector<uint8_t>& getEVMBytecode() const;

private:
    const runtime::Module& module;
};
```

### Implementing EVM IR Builder

Compare `class FunctionMirBuilder` in `src/compiler/wasm_frontend/wasm_mir_compiler.h`, implement `EVMMirBuilder`. Consider differences between `wasm` bytecode and `EVM` bytecode in data types, control flow instructions, stack operations, etc., and create new `EVMMirBuilder`.

Additionally, considering the gas calculation mechanism, to reuse gas instructions in current dMIR as much as possible, we need to insert gas checking and gas deduction instructions when generating dMIR.

```cpp
// src/compiler/evm_frontend/evm_mir_builder.h
class EVMMirBuilder {
public:
    typedef EVMFrontendContext CompilerContext;

    // Operand definition
    class Operand {
    public:
        Operand() = default;

        Operand(MInstruction* instr, MType* type)
            : instr(instr), type(type) {}

        Operand(MConstant* constant, MType* type)
            : constant(constant), type(type) {}

        MInstruction* getInstr() const { return instr; }
        MConstant* getConstant() const { return constant; }
        MType* getType() const { return type; }

        bool isEmpty() const { return !instr && !constant && !type; }
        bool isConstant() const { return constant != nullptr; }

    private:
        MInstruction* instr = nullptr;
        MConstant* constant = nullptr;
        MType* type = nullptr;
    };

    EVMMirBuilder(CompilerContext& context, MFunction& mfunc);

    void initFunction(CompilerContext* context);
    void finalizeFunctionBase();

    // Basic block management
    void createBasicBlock(size_t pc);
    void setInsertBlock(size_t pc);

    // Instruction handling
    void handleStop();
    Operand handleAdd(Operand lhs, Operand rhs);
    Operand handleMul(Operand lhs, Operand rhs);
    // ... other instruction handling ...
    Operand handlePush(const uint256_t& value);
    Operand handleDup(Operand opnd);
    void handleSwap(Operand top, Operand target);
    // ... other instruction handling ...

    // Helper functions
    void releaseOperand(Operand opnd) {} // Empty implementation, compatible interface

private:
    // Helper methods
    MInstruction* extractOperand(const Operand& opnd);
    Operand createTempOperand(MType* type);

    CompilerContext& context;
    MFunction& mfunc;
    MBasicBlock* current_block;
    std::unordered_map<size_t, MBasicBlock*> pc_to_block; // Map for handling EVM jump targets
};
```

## Instruction Support

MIR's handling of wasm instruction set is located in `src/compiler/mir/instruction.h` and `src/compiler/mir/instructions.h`. Extend support for evm-related instructions, therefore add `src/compiler/mir/evm_opcodes.def` to add EVM opcode support.

```plain
// src/compiler/mir/evm_opcodes.def
// EVM opcode definitions
// Format: DEFINE_EVM_OPCODE(operation_name)

// 0x00: Stop and arithmetic operations
DEFINE_EVM_OPCODE(stop)    // Stop execution
DEFINE_EVM_OPCODE(add)    // Addition operation
// Other arithmetic instructions

// 0x10: Comparison and bitwise operations
// 0x20: SHA3
// 0x30: Environment information address, balance, origin, caller, callvalue
// 0x50-0x5f: Stack, memory, storage and flow control: pop, mload, mstore, mstore8, sload, sstore, jump, jumpi, pc, msize, gas, jumpdest
// 0x60-0x7f: PUSH operations (PUSH1-PUSH32)
// 0x80-0x8f: DUP operations (DUP1-DUP16)
// 0x90-0x9f: SWAP operations (SWAP1-SWAP16)
// 0xa0-0xa4: Log operations (LOG0-LOG4)
// 0xf0-0xff: System operations: create, call, callcode, return, deleagatecall, create2, staticcall, revert, invalid, selfdestruct
```

## Memory and Storage Model
1. EVM's three-level model: stack, memory, storage
2. Memory and storage mapping: Implement efficient memory structures suitable for u256 key-value pairs
3. ABI modification: Manage registers, stack frames, etc.

### EVMModule Interface Design
`EVMModule` is responsible for representing the static structure of EVM contracts and bytecode instructions.

```cpp
class EVMModule {
public:
    // Construction and initialization
    explicit EVMModule(runtime::Runtime& runtime);
    ~EVMModule();

    // Load bytecode information
    bool loadBytecode(const Byte* data, size_t size);

private:
    // Bytecode storage
    std::vector<Byte> bytecode;
};
```

### EVMInstance Interface Design

`EVMInstance` is responsible for executing EVM bytecode and managing execution state

```cpp
class EVMInstance {
public:
    // Construction and initialization
    explicit EVMInstance(EVMModule& module, uint64_t gasLimit);
    ~EVMInstance();

    // Execution related
    ExecutionResult execute(const std::string& functionName,
                           const std::vector<TypedValue>& args);
    ExecutionResult executeRaw(const Bytes& calldata, uint256 value = 0);

    // State queries
    uint64_t getGasRemaining() const;
    uint64_t getGasUsed() const;
    bool hasError() const;
    Error getLastError() const;

    // Result retrieval
    std::vector<TypedValue> getReturnData() const;

    // Memory management interface - EVM memory model related
    // Linear memory management: write, read
    void memoryStore(uint32_t offset, const Bytes& data);
    Bytes memoryLoad(uint32_t offset, uint32_t size);

    // Storage management: write, read, check
    void storageStore(const uint256& key, const uint256& value);
    uint256 storageLoad(const uint256& key);
    bool hasStorageKey(const uint256& key) const;

    // Stack operations
    void stackPush(const uint256& value);
    uint256 stackPop();
    uint256 stackPeek(uint32_t depth = 0) const;
    uint32_t getStackSize() const;

    // Call related
    ExecutionResult call(Address target, uint256 value, const Bytes& calldata, uint64_t gas);
    ExecutionResult delegateCall(Address target, const Bytes& calldata, uint64_t gas);
    ExecutionResult staticCall(Address target, const Bytes& calldata, uint64_t gas);
    void returnData(const Bytes& data);
    void revert(const Bytes& data);
    void stop();

    // Transaction context information
    Address getAddress() const;
    Address getCaller() const;
    uint256 getCallValue() const;
    uint64_t getBlockNumber() const;
    uint64_t getTimestamp() const;

private:
    // Execution state
    enum class ExecutionState {
        Running,
        Returned,
        Reverted,
        Error
    };

    ExecutionState state;

    // EVM memory model components
    std::vector<uint8_t> memory;
    std::unordered_map<uint256, uint256> storage;
    std::vector<uint256> stack;

    // Execution environment
    struct CallContext {
        Address caller;
        Address address;
        uint256 value;
        uint32_t pc;
        std::vector<uint256> stack;
        std::vector<uint8_t> memory;
        std::vector<uint8_t> returnData;
        uint64_t gasLimit;
        uint64_t gasUsed;
    };

    std::vector<CallContext> callStack;
    CallContext& currentContext();

    // Gas management
    uint64_t gasLimit;
    uint64_t gasUsed;
    bool consumeGas(uint64_t amount);

    // Instruction execution
    void executeNextInstruction();
    void executeInstruction(uint8_t opcode);
};
```

## Gas Calculation Mechanism

1. Gas metering system:
    1. Calculate gas consumption at instruction granularity, including fixed gas and dynamic gas consumption calculation
    2. When EVM opcodes generate dMIR, insert gas checking and gas deduction instructions, reusing gas instructions in current dMIR

```plain
// Example dMIR pseudo-code generated by EVM addition
// EVM stack operation: pop two operands, add them, push result back to stack
// Assume current dMIR builder instance is 'builder', stack simulator is 'stack'

// 1. Pop two values from stack top. Should actually pop multiple 64-bit values, but simplified as one 256-bit value in pseudo-code
MOperand op2 = builder.createPopOp(); // Second operand (stack top)
MOperand op1 = builder.createPopOp(); // First operand (second from top)

// 2. Create multiple dMIR instructions to implement 256-bit addition
MInstruction *addInstr = builder.createInstruction<BinaryInstruction>(
    ...
);

// 3. Push result back to stack
builder.createPushOp(addInstr);

// 4. Consume gas
// Create a constant representing gas consumption (G_verylow = 3)
MInstruction *gasCost = builder.createIntConstInstruction(
    &builder.I64Type,  // Gas represented as 64-bit integer
    3  // G_verylow = 3
);

// Create gas consumption instruction
builder.createInstruction<GasInstruction>(
    /*isTerminator=*/false,
    /*opcode=*/OP_evm_gasuse,
    /*gasAmount=*/gasCost
);

// Update stack simulation state (for subsequent instruction analysis)
stack.pop();  // Pop two values
stack.pop();
stack.push(addInstr);  // Push result
```

# Other Parts

## JIT Implementation in trace RPC Interface

The trace RPC interface needs some data during execution, but if it only needs storage/event/sub-call changes, this interface might also be usable with JIT.