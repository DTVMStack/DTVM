# compiler 模块规范

> 目录: `src/compiler/`

## 边界与职责

compiler 模块负责 DTVM 的多遍 JIT 编译流水线，将 **WASM** 或 **EVM** 字节码编译为 x86-64 机器码。

### 职责范围

- **WASM 前端**：将 WASM 字节码转为 dMIR（`wasm_frontend/`、`frontend/`）
- **EVM 前端**：将 EVM 字节码转为 dMIR（`evm_frontend/`、`evm_compiler.*`）
- **dMIR 层**：中间表示（`mir/`），支持常量、变量、基本块、指令（含 EVM 专用指令如 `EvmUmul128Instruction`）
- **CgIR 层**：面向代码生成 IR（`cgir/`），含基本块、指令、寄存器
- **MIR→CgIR  lowering**：`target/x86/x86lowering*.cpp`、`cgir/lowering.h`
- **寄存器分配**：FastRA（`fast_ra`）与 Greedy RA（`reg_alloc_greedy`）
- **x86 后端**：机器码生成（`target/x86/x86_mc_lowering.cpp`、`x86_mc_inst_lower.*`）、ELF 输出
- **EVM JIT 适用性分析**：编译前检测 RA-expensive 模式，决定是否回退到解释器

### 不负责内容

- 解释器执行（由 `evm/`、`runtime/` 提供）
- Singlepass JIT（位于 `src/singlepass/`）
- 模块加载、实例创建（由 `runtime/` 提供）

---

## 核心概念

### 多遍编译流水线

1. **前端→dMIR**：`WasmMirBuilder` / `EVMMirBuilder` 将源码/字节码转为 `MModule` + `MFunction`（dMIR）
2. **dMIR 优化**：`DeadMBasicBlockElim`、`MVerifier`
3. **dMIR→CgIR**：`X86CgLowering`、`X86CgPeephole`
4. **寄存器分配**：`FastRA` 或 `CgRAGreedy` + `CgRegisterCoalescer`、`CgVirtRegMap`、`CgLiveIntervals` 等
5. **后 RA 处理**：`PrologEpilogInserter`、`ExpandPostRAPseudos`
6. **机器码发射**：`X86MCLowering` → ELF `.text` 段
7. **链接与内存保护**：`emitObjectBuffer`、`mprotect`

### 前端上下文

- **WasmFrontendContext**：WASM 模块引用、线程上下文
- **EVMFrontendContext**：EVM 字节码、Gas 计费开关、Gas chunk 元数据、`evmc_revision`

### 编译入口

- **EagerJITCompiler**：WASM 全量编译
- **LazyJITCompiler**：WASM 按需编译（支持多线程）
- **EagerEVMJITCompiler**：EVM 全量编译（仅 Multipass）
- **MIRTextJITCompiler**：从 MIR 文本编译（测试/调试）

---

## 外部契约

### 上游依赖

| 模块 | 用途 |
|------|------|
| `runtime/` | `Module`、`Instance`、`EVMModule`、`CodeEntry`、`CodeMemPool` |
| `action/` | `vm_eval_stack`、`vm_eval_stack.h`（EVM 栈） |
| `evm/`、`evmc/` | EVM 语义、指令表、`evmc_opcode` |
| `common/` | `ErrorCode`、`WASMType`、`MemPool`、`ThreadPool` |
| `platform/` | `mprotect`、内存分配 |
| `utils/` | `Statistics`、`JitDumpWriter`（perf 集成） |
| LLVM | `TargetMachine`、`MCContext`、`TargetInstrInfo`、`TargetRegisterInfo` |

### 下游使用者

| 模块 | 调用方式 |
|------|----------|
| `action/` | `performMultipassJITCompile` / `performEVMJITCompile` 调用 `EagerJITCompiler::compile()` / `EagerEVMJITCompiler::compile()` |
| `vm/` | 通过 action 层间接使用 |

---

## 权限与不变量

### 编译上下文不变量

- `CompileContext::Inited == true` 时，`MemPool`、`CodePtr`、`FuncOffsetMap` 等处于有效状态
- `EVMFrontendContext` 在 `compile()` 前必须设置 `Bytecode`、`BytecodeSize`、`GasMeteringEnabled`、`GasChunkInfo`（若启用 chunk 计费）

### dMIR 不变量

- `MFunction` 中 `MBasicBlock` 按控制流连接，`MInstruction` 归属 `MBasicBlock` 或作为表达式嵌入另一 `MInstruction`
- `MVerifier` 校验通过后才能进入 CgIR lowering

### EVM JIT 不变量

- 仅支持 Multipass 模式；Singlepass 不提供 EVM JIT
- 编译前应执行 JIT 适用性分析；不通过则回退解释器

---

## 错误码

来自 `common/errors.h`，compiler 模块使用：

| 错误码 | 含义 |
|--------|------|
| `MIRVerifyingFailed` | dMIR 校验失败 |
| `ObjectFileCreationFailed` | ELF 对象文件创建失败 |
| `UnexpectedObjectFileFormat` | 非 ELF 格式 |
| `ObjectFileResolvingFailed` | 无法解析 .text 段或重定位 |
| `NoMatchedInstruction` | 无匹配目标指令 |
| `MmapFailed` | JIT 代码内存分配失败 |

---

## 兼容性策略

### EVM JIT 与 Multipass-only

- **Multipass-only EVM JIT**：EVM 字节码仅在 Multipass JIT 模式下编译；若运行模式为 Singlepass，应报错并拒绝 EVM JIT
- **Lazy 不支持**：EVM 当前仅支持 Eager 编译；请求 Lazy 时发出警告并跳过

### JIT 适用性分析（融入 openspec evm-jit）

编译前必须运行 `EVMAnalyzer::analyze()`，检测以下模式并决定是否回退解释器：

| 阈值 | 说明 |
|------|------|
| `MAX_JIT_BYTECODE_SIZE` (0x6000) | 字节码大小超限 |
| `MAX_JIT_MIR_ESTIMATE` (50000) | 线性 MIR 估计超限 |
| `MAX_CONSECUTIVE_RA_EXPENSIVE` (128) | 连续 RA-expensive opcode 超限 |
| `MAX_BLOCK_RA_EXPENSIVE` (256) | 单基本块 RA-expensive 数量超限 |
| `MAX_DUP_FEEDBACK_PATTERN` (64) | DUPn + RA-expensive 模式超限 |

**RA-expensive opcode 分类**：SHL (0x1b)、SHR (0x1c)、SAR (0x1d)、MUL (0x02)、SIGNEXTEND (0x0b)。

### EVM 前端上下文与 Gas

- 根据运行时配置启用/关闭 Gas metering（`setGasMeteringEnabled`）
- 提供 bytecode、gas chunk end/cost 数组供 chunk-based 计费
- 支持 `ZEN_ENABLE_EVM_GAS_REGISTER` 时使用寄存器持有 gas

### 机器码与模块绑定

- 机器码写入 `EVMModule::getJITCodeMemPool()` 或 `Module` 对应池
- 入口为 FuncIdx 0 对应代码指针
- 代码段经 `mprotect(JITCode, size, PROT_READ | PROT_EXEC)` 保护

### JIT 统计与 perf

- 编译起止时间计入 `utils::StatisticPhase::JITCompilation`
- `ZEN_ENABLE_LINUX_PERF` 时，为生成的块输出 perf JIT dump 符号（如 `EVMBB*`）

---

## 交叉引用

| 依赖 | 说明 |
|------|------|
| [evm](../evm/) | EVM 语义、指令表、evmc_opcode |
| [runtime](../runtime/) | Module、EVMModule、CodeMemPool、Instance |
| [action](../action/) | performMultipassJITCompile、performEVMJITCompile、vm_eval_stack |
| [common](../common/) | ErrorCode、WASMType、MemPool、ThreadPool |
| [platform](../platform/) | mprotect、内存分配 |
| [utils](../utils/) | Statistics、JitDumpWriter |

| 被依赖 | 说明 |
|--------|------|
| action | performJITCompile、performEVMJITCompile 调用 |
| vm-interface | EVMAnalyzer、JIT fallback 决策 |

- [openspec evm-jit](../../openspec/specs/evm-jit/spec.md)：EVM JIT 需求（Multipass-only、适用性分析、RA-expensive 分类）
