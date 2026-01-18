# DTVM Coding Style Guide

This document defines the coding style guidelines for the DTVM project. Consistency in code style improves readability, maintainability, and collaboration.

## Language Standards

- **C++ Standard**: C++17
- **C Standard**: C11 (for C API bindings)
- **Code Style**: [LLVM Coding Standards](https://llvm.org/docs/CodingStandards.html)

## Formatting

### Automatic Formatting

Use the project's formatting tools:

```bash
# Format code
./tools/format.sh

# Run clang-tidy checks
python3 ./tools/run-clang-tidy.py
```

Configuration files:
- `.clang-format` - Code formatting rules
- `.clang-tidy` - Static analysis checks

### Indentation and Line Limits

- **Indentation**: 2 spaces (no tabs)
- **Line Limit**: 80 characters
- **Brace Style**: Attach braces to control statements

```cpp
// Good
if (condition) {
  doSomething();
} else {
  doSomethingElse();
}

// Bad
if (condition)
{
  doSomething();
}
```

## Naming Conventions

### Types, Classes, Enums, and Variables

Use **PascalCase**:

```cpp
class ModuleLoader;
struct ExecutionContext;
enum class RuntimeMode;
const int MaxStackSize = 1024;
Module *CurrentModule;
```

### Functions

Use **camelCase**:

```cpp
void loadModule();
bool validateBytecode();
Instance *createInstance();
```

### Private Members

Use prefix or suffix conventions consistent with surrounding code:

```cpp
class Module {
private:
  uint32_t CodeSize;    // Member variables use PascalCase
  void *CodeBuffer;
};
```

### Macros and Constants

Use **UPPER_SNAKE_CASE** for macros:

```cpp
#define ZEN_ENABLE_LOGGING
#define MAX_MEMORY_PAGES 65536
```

### File Names

- Use **snake_case** for file names
- Header files: `.h` extension
- Implementation files: `.cpp` extension

```
module_loader.h
module_loader.cpp
evm_instance.h
evm_instance.cpp
```

## Header Guards

Use `#ifndef` / `#define` / `#endif` style:

```cpp
#ifndef ZEN_RUNTIME_MODULE_H
#define ZEN_RUNTIME_MODULE_H

// ... content ...

#endif // ZEN_RUNTIME_MODULE_H
```

## Includes

### Order

1. Corresponding header file (for .cpp files)
2. C system headers
3. C++ standard library headers
4. Third-party library headers
5. Project headers

```cpp
#include "module_loader.h"  // Corresponding header

#include <cstdint>          // C system
#include <cstring>

#include <memory>           // C++ standard
#include <vector>

#include "spdlog/spdlog.h"  // Third-party

#include "common/errors.h"  // Project
#include "runtime/module.h"
```

### Path Style

Use quoted includes with relative paths from `src/`:

```cpp
#include "runtime/module.h"
#include "common/errors.h"
```

## Error Handling

### Using Project Error System

Errors are defined in `src/common/errors.def`:

```cpp
// Throwing errors
if (invalidCondition) {
  throw getError(ErrorCode::INVALID_MODULE);
}

// With extra context
throw getErrorWithPhase(ErrorCode::VALIDATION_FAILED, "parse");
throw getErrorWithExtraMessage(ErrorCode::LOAD_FAILED, "file not found");
```

### Exception Safety

- Use RAII for resource management
- Clean up resources in destructors
- Use smart pointers when appropriate

## Memory Management

### Memory Pool Usage

Use the project's memory pool mechanism to prevent leaks:

```cpp
MemPool MPool;
void *Buffer = MPool->allocate(size);
// Use buffer...
MPool->deallocate(Buffer);
```

### Smart Pointers

Prefer smart pointers for dynamic allocation outside memory pools:

```cpp
std::unique_ptr<Module> Mod = std::make_unique<Module>();
std::shared_ptr<Runtime> RT = std::make_shared<Runtime>();
```

## Logging

### Setup

Enable logging with `ZEN_ENABLE_LOGGING` macro and configure logger:

```cpp
#include "utils/logging.h"

// Use logging macros
ZEN_LOG_TRACE("Entering function {}", funcName);
ZEN_LOG_DEBUG("Loading module with {} functions", count);
ZEN_LOG_INFO("Runtime initialized");
ZEN_LOG_WARN("Deprecated feature used");
ZEN_LOG_ERROR("Failed to load module: {}", error);
ZEN_LOG_FATAL("Unrecoverable error");
```

## Comments

### Documentation Comments

Use `///` for documentation:

```cpp
/// Creates a new runtime instance with the specified configuration.
/// @param config Runtime configuration options
/// @return Pointer to the new runtime, or nullptr on failure
Runtime *createRuntime(const RuntimeConfig &config);
```

### Implementation Comments

Use `//` for inline comments:

```cpp
// Calculate gas cost for memory expansion
uint64_t gasCost = calculateMemoryCost(newSize);
```

## Namespaces

### Project Namespace

Use `zen` as the root namespace:

```cpp
namespace zen {
namespace runtime {

class Module { ... };

} // namespace runtime
} // namespace zen
```

### Namespace Aliases

Avoid `using namespace` in headers. Use aliases sparingly in implementation:

```cpp
// In .cpp files only
using namespace zen::common;
```

## Best Practices

1. **Const Correctness**: Mark read-only parameters and methods as `const`
2. **Explicit**: Use `explicit` for single-argument constructors
3. **Override**: Use `override` for virtual method overrides
4. **Nullptr**: Use `nullptr` instead of `NULL` or `0`
5. **Auto**: Use `auto` when the type is obvious from context
6. **Range-based For**: Prefer range-based for loops when iterating

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`

Scopes: `core`, `runtime`, `compiler`, `evm`, `test`, `docs`, etc.

See `docs/COMMIT_CONVENTION.md` for details.

