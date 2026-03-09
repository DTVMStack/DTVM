# DTVM 模块索引

本目录是所有模块规范的 SSOT (Single Source of Truth)。每个模块包含 `spec.md`（边界与契约）和 `data-model.md`（数据模型）。

**划分原则：严格按目录划分。** 每个模块对应一个（或少数紧密关联的）目录，spec 只描述该目录下的代码。跨模块的功能链路通过交叉引用描述。

## 模块清单

### 基础能力层 (Foundation)

| 模块 | 目录 | 职责 |
|------|------|------|
| [common](common/) | `src/common/` | 共享类型、错误体系、内存池、操作码定义、trap 处理 |
| [platform](platform/) | `src/platform/` | OS/硬件抽象层 (POSIX 内存映射、SGX enclave 支持) |
| [utils](utils/) | `src/utils/` | 日志、回溯、线程安全容器、统计、perf 集成、WASM/EVM 工具函数 |

### 核心运行时层 (Core Runtime)

| 模块 | 目录 | 职责 |
|------|------|------|
| [runtime](runtime/) | `src/runtime/` + `src/entrypoint/` | 核心运行时 (Runtime/Instance/Module/Memory/Isolation/VNMI/WNI)，含 EVMModule/EVMInstance 生命周期管理、JIT 原生调用桥接 |

### 执行引擎层 (Execution Engines)

| 模块 | 目录 | 职责 |
|------|------|------|
| [action](action/) | `src/action/` | 模块/函数加载（WASM + EVM）、WASM 解释器、JIT 编排入口、EVM 字节码遍历 |
| [evm](evm/) | `src/evm/` | EVM 解释器核心：操作码处理、Gas 计算、字节码缓存、EVM 常量与修订版本定义 |
| [singlepass](singlepass/) | `src/singlepass/` | 单遍 JIT 编译器 (AsmJit，x64/AArch64 后端) |
| [compiler](compiler/) | `src/compiler/` | 多遍编译流水线：WASM 前端 + EVM 前端 -> dMIR -> CgIR -> 寄存器分配 -> x86 后端 |

### 宿主接口层 (Host Interface)

| 模块 | 目录 | 职责 |
|------|------|------|
| [host](host/) | `src/host/` + `src/wni/` | 宿主模块 (WASI, env, spectest, EVM ABI mock, EVM 密码学/Keccak, WNI 接口) |

### 应用集成层 (Application and Integration)

| 模块 | 目录 | 职责 | spec 粒度 |
|------|------|------|-----------|
| [cli](cli/) | `src/cli/` | dtvm 命令行工具 | spec + data-model |
| [vm-interface](vm-interface/) | `src/vm/` + `evmc/` | EVMC 共享库接口 (dtvmapi.so)，WrappedHost 桥接 | spec + data-model |
| [rust-bindings](rust-bindings/) | `rust_crate/` | Rust FFI 绑定和 Rust API | spec + data-model |
| [tests](tests/) | `src/tests/` + `tests/` | 测试基础设施 (WAST spec/EVM state/Solidity/MIR/C API) | spec + data-model |
| [tools](tools/) | `tools/` | 开发辅助脚本 (格式化、编译、性能检查等) | 仅 spec |

## 模块间依赖关系

依赖方向: 下层 -> 上层

```
common, platform, utils (基础)
    -> runtime (核心)
        -> action, evm (执行)
            -> singlepass, compiler (JIT)
        -> host (宿主)
    -> cli, vm-interface, rust-bindings (应用)
```

## EVM 执行全链路（跨模块）

EVM 的完整执行流程跨越多个模块，各 spec 通过交叉引用描述：

1. **vm-interface**: EVMC execute() 入口
2. **runtime**: EVMModule/EVMInstance 生命周期
3. **action**: EVMModuleLoader 加载、performEVMJITCompile 编排
4. **evm**: BaseInterpreter 解释执行、操作码处理、Gas 计算
5. **compiler**: evm_frontend/ EVM->dMIR 编译、evm_compiler.* JIT 编排
