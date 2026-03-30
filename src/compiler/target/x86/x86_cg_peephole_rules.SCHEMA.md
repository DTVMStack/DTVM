# x86 CgIR Peephole DSL Schema

This document describes every field accepted by
`x86_cg_peephole_rules.json` and the constraints that must hold for the
generator (`tools/generate_x86_cg_peephole.py`) to accept the file and
produce valid C++ code.

---

## 1. Top-level structure

```json
{
  "version": 1,
  "rules": [ /* array of rule objects */ ]
}
```

| Field     | Type    | Required | Notes                              |
|-----------|---------|----------|------------------------------------|
| `version` | integer | yes      | Must be `1`.                       |
| `rules`   | array   | yes      | Ordered list of rule objects.      |

---

## 2. Rule object

```json
{
  "name":     "my-rule",
  "stage":    "instruction",
  "priority": 100,
  "pattern":  [ /* pattern entries */ ],
  "when":     [ /* optional conditions */ ],
  "action":   { /* action object */ },
  "validation": { /* validation object */ }
}
```

| Field        | Type    | Required | Notes                                                        |
|--------------|---------|----------|--------------------------------------------------------------|
| `name`       | string  | yes      | Must be unique across all rules in the file.                 |
| `stage`      | string  | yes      | `"instruction"` or `"block_end"`.                            |
| `priority`   | integer | yes      | Higher value fires first within the same stage. Two rules with the same priority and identical normalised pattern are a generator error. |
| `pattern`    | array   | yes      | Sequence of pattern entries. See section 3.                  |
| `when`       | array   | no       | Optional extra conditions. See section 6. Only used with `block_end` stage currently. |
| `action`     | object  | yes      | Describes what to do when the pattern matches. See section 7. |
| `validation` | object  | yes      | Describes how the rule is validated. See section 8.          |

---

## 3. Pattern entry

Each element of `pattern` describes one CgIR instruction that must match
in program order.

```json
{
  "bind":      "inst_name",
  "opcode":    "CMP64rr",
  "capture":   [ /* capture entries */ ],
  "require":   [ /* require entries */ ]
}
```

| Field       | Type   | Required | Notes                                                       |
|-------------|--------|----------|-------------------------------------------------------------|
| `bind`      | string | yes      | Local variable name for this instruction in the generated code. Used in `action` to refer to the instruction. |
| `opcode`    | string | no*      | Exact x86 opcode name (without the `X86::` prefix). Exactly one of `opcode`, `opcode_any`, or `predicate` must be present. |
| `opcode_any`| array  | no*      | List of opcode strings. The instruction matches if its opcode equals any element. |
| `predicate` | string | no*      | A predicate method name called on the instruction object (e.g., `isCompare`, `isConditionalBranch`, `isUnconditionalBranch`). |
| `capture`   | array  | no       | List of capture entries. See section 4.                     |
| `require`   | array  | no       | List of requirement entries. See section 5.                 |

\* Exactly one of `opcode`, `opcode_any`, or `predicate` must be present in each pattern entry.

---

## 4. Capture entry

A capture reads an operand field from the bound instruction into a named
variable that can be referenced in later `require` entries.

```json
{
  "name":    "dst_reg",
  "operand": 0,
  "field":   "reg"
}
```

| Field     | Type    | Required | Notes                                                        |
|-----------|---------|----------|--------------------------------------------------------------|
| `name`    | string  | yes      | Identifier used in `equals_capture` requirements and in `set_imm` actions. |
| `operand` | integer | yes      | Zero-based operand index. A negative value `-N` selects the Nth-from-last explicit operand (counting from 1). |
| `field`   | string  | yes      | `"reg"` to capture a register, `"imm"` to capture an immediate. |

---

## 5. Require entry variants

A require entry constrains an operand of the bound instruction. All
require entries for a given pattern element must hold for the match to
succeed.

### 5.1 `equals_capture`

The operand's register value must equal a previously captured register.

```json
{
  "operand": 1,
  "field":   "reg",
  "equals_capture": "dst_reg"
}
```

| Field            | Type    | Notes                                                   |
|------------------|---------|---------------------------------------------------------|
| `operand`        | integer | Operand index (same semantics as in capture).           |
| `field`          | string  | Must be `"reg"`.                                        |
| `equals_capture` | string  | Name of a previously declared capture.                  |

### 5.2 `equals_int`

The operand's immediate value must equal the given integer constant.

```json
{
  "operand":   -1,
  "field":     "imm",
  "equals_int": 0
}
```

| Field        | Type    | Notes                                                   |
|--------------|---------|---------------------------------------------------------|
| `operand`    | integer | Operand index.                                          |
| `field`      | string  | Must be `"imm"`.                                        |
| `equals_int` | integer | The exact immediate value to match.                     |

### 5.3 `equals_enum`

The operand's immediate value must equal a named x86 `CondCode` constant.

```json
{
  "operand":     1,
  "field":       "imm",
  "equals_enum": "COND_NE"
}
```

| Field         | Type   | Notes                                                     |
|---------------|--------|-----------------------------------------------------------|
| `operand`     | integer| Operand index.                                            |
| `field`       | string | Must be `"imm"`.                                          |
| `equals_enum` | string | A constant name from `X86::CondCode` (without the `X86::CondCode::` prefix). |

### 5.4 `equals_bool`

The operand's `isMBB()` predicate must equal the given boolean.

```json
{
  "operand":     0,
  "field":       "is_mbb",
  "equals_bool": true
}
```

| Field         | Type    | Notes                                                  |
|---------------|---------|--------------------------------------------------------|
| `operand`     | integer | Operand index.                                         |
| `field`       | string  | Must be `"is_mbb"`.                                    |
| `equals_bool` | boolean | `true` requires `isMBB()` to hold; `false` requires it not to hold. |

---

## 6. When conditions

The `when` array holds conditions checked after the pattern has matched.
Currently only `block_end` rules use `when`.

### 6.1 `target_is_next_block`

The MBB operand at `operand` must point to the basic block that
immediately follows the current block in the function's block list.

```json
{
  "kind":    "target_is_next_block",
  "inst":    "jmp",
  "operand": 0
}
```

| Field     | Type    | Notes                                                     |
|-----------|---------|-----------------------------------------------------------|
| `kind`    | string  | Must be `"target_is_next_block"`.                         |
| `inst`    | string  | The `bind` name of the instruction whose operand to test. |
| `operand` | integer | Zero-based operand index holding the target MBB.          |

---

## 7. Action object

The action object specifies what transformations to apply when all
pattern entries and when conditions have matched. Multiple primitives may
appear in the same action.

```json
{
  "erase":   [ "setcc", "test" ],
  "set_imm": [
    { "inst": "jcc", "operand": 1, "from_capture": "setcc_cc" }
  ]
}
```

### 7.1 `erase`

A list of `bind` names. Each named instruction is erased from the basic
block. If the first instruction in the pattern (`pattern[0]`) is in the
erase list, the generator advances `MII` to the next instruction before
erasing so that the caller's iterator remains valid.

### 7.2 `set_imm`

A list of immediate-mutation entries. Each entry overwrites one immediate
operand of a bound instruction with the value stored in a named capture.

| Field          | Type    | Notes                                                 |
|----------------|---------|-------------------------------------------------------|
| `inst`         | string  | `bind` name of the instruction to mutate.             |
| `operand`      | integer | Zero-based operand index of the immediate to overwrite. |
| `from_capture` | string  | Name of a previously declared `"imm"` capture.        |

### 7.3 `custom` (not yet implemented)

Reserved for future use. When present, the action requires a hand-written
C++ helper function in `x86_cg_peephole.cpp`. The current generator does
not emit calls to custom handlers; rules that require transformations
beyond `erase` and `set_imm` (e.g., inverting a condition code) must wait
until generator support is added.

---

## 8. Validation object

Every rule must carry a `validation` block.

```json
{
  "modes":    [ "structural", "execution" ],
  "coverage": [ "X86CgPeephole.MyTestName" ]
}
```

| Field      | Type   | Required | Notes                                                           |
|------------|--------|----------|-----------------------------------------------------------------|
| `modes`    | array  | yes      | Non-empty list of mode strings. See 8.1.                        |
| `coverage` | array  | yes      | Non-empty list of gtest name strings. See 8.2.                  |

### 8.1 Validation modes

| Mode              | Meaning                                                                 |
|-------------------|-------------------------------------------------------------------------|
| `structural`      | Pattern is verified to match or not match a manually-constructed CgIR fixture. |
| `execution`       | Before/after instruction sequences are executed with hardware and compared. |
| `semantics_model` | A software model (e.g., flag evaluator) verifies semantic equivalence.  |

Rules with `stage: "instruction"` must include at least one of
`"execution"` or `"semantics_model"`. A `"structural"`-only instruction
rule is rejected by `check_x86_cg_peephole_validation.py`. `block_end`
rules may use `"structural"` and `"execution"` only.

### 8.2 Coverage entries

Each string must be a fully-qualified gtest name in the form
`Suite.TestName`. The checker (`check_x86_cg_peephole_validation.py`)
verifies that every coverage entry exists in the gtest binary when
`--gtest-binary` is supplied.

---

## 9. Priority and conflict detection

Rules are applied in descending priority order within each stage. The
generator normalises each rule to a canonical signature (stage, pattern
opcodes/predicates, require constraints, when conditions) and checks for
duplicate `(signature, priority)` pairs. If two rules produce the same
signature with the same priority the generator exits with a non-zero
status and prints a conflict report.

Rules with the same priority but different normalised signatures are
legal and both are emitted into the dispatch function in the order they
appear in the `rules` array.

---

## 10. DSL limits

The following are intentionally outside the scope of the current DSL.
They require either a new DSL feature or a `custom` action with a C++
helper.

- **No operand creation.** Actions may only erase instructions or mutate
  existing immediate values. Creating new instructions or new operands is
  not supported.
- **No cross-block patterns.** All pattern entries must match within a
  single basic block. `block_end` rules are a special case that look only
  at the last instruction of a block and may inspect the successor list
  via `target_is_next_block`.
- **No register-class or liveness reasoning.** The DSL has no access to
  register class information or live-range data. Patterns that are only
  safe when a specific register is dead (e.g., flag-liveness after AND or
  ADD with an identity immediate) are not expressible and must be
  implemented as hand-coded passes.
- **No arithmetic on captures.** The `set_imm` action copies a captured
  value verbatim. Transformations such as inverting a condition code
  (`cc ^ 1`) cannot be expressed; they require `custom`.
- **Single-opcode window.** Pattern entries are matched strictly in
  sequential order with no gaps. Patterns that need to skip intervening
  instructions are not supported.

---

## 11. Examples

### Instruction stage — remove redundant consecutive TEST64rr

```json
{
  "name": "remove-redundant-test64rr",
  "stage": "instruction",
  "priority": 105,
  "pattern": [
    {
      "bind": "test1",
      "opcode": "TEST64rr",
      "capture": [
        { "name": "test1_op0", "operand": 0, "field": "reg" },
        { "name": "test1_op1", "operand": 1, "field": "reg" }
      ]
    },
    {
      "bind": "test2",
      "opcode": "TEST64rr",
      "require": [
        { "operand": 0, "field": "reg", "equals_capture": "test1_op0" },
        { "operand": 1, "field": "reg", "equals_capture": "test1_op1" }
      ]
    }
  ],
  "action": { "erase": [ "test1" ] },
  "validation": {
    "modes": [ "structural", "execution" ],
    "coverage": [
      "X86CgPeephole.RemovesRedundantTest64rr",
      "X86CgPeephole.KeepsNonRedundantTest64rr",
      "X86CgPeephole.ExecutionHarnessRemoveRedundantTest64rr"
    ]
  }
}
```

Safety note: `TEST64rr` does not modify any register value; it only sets
flags. Two consecutive identical TEST instructions produce identical flag
state. Removing the first leaves the second to set the same flags, so the
transformation is correct without any liveness information.

### Block-end stage — remove fallthrough unconditional jump

```json
{
  "name": "remove-fallthrough-jump",
  "stage": "block_end",
  "priority": 100,
  "pattern": [
    {
      "bind": "jmp",
      "predicate": "isUnconditionalBranch",
      "require": [
        { "operand": 0, "field": "is_mbb", "equals_bool": true }
      ]
    }
  ],
  "when": [
    { "kind": "target_is_next_block", "inst": "jmp", "operand": 0 }
  ],
  "action": { "erase": [ "jmp" ] },
  "validation": {
    "modes": [ "structural", "execution" ],
    "coverage": [
      "X86CgPeephole.RemovesFallthroughJump",
      "X86CgPeephole.ExecutionHarnessRemoveFallthroughJump"
    ]
  }
}
```
