#!/usr/bin/env python3
"""
WS2.A spike generator: produces dmir_rewrite_generated.inc from a DSL v2
rules JSON. MINIMAL version covering the 3 spike rules:

1. dmir_double_not: (not (not x)) -> x           — pure nesting
2. dmir_add_zero_const_fold: (add x 0:i64) -> x  — guard + commutative
3. dmir_add_self_to_shl1: (add x x) -> (shl x 1:i64) — structural eq + RHS construct

Output is C++ matcher functions + dispatch, to be #included by dmir_rewrite.h.
Intentionally does NOT: handle select/adc/sbb, multi-instruction LHS, type
polymorphism, hooks — those are WS2.B+ expansions.
"""

import argparse
import json
import pathlib
import re
import sys
from typing import Any


# --- s-expression parser (same format as mine_dmir_seed_rules.parse_expr) ---
def tokenize(s: str):
    return re.findall(r"\(|\)|[^\s()]+", s)


def parse(tokens, i=0):
    if tokens[i] == "(":
        op, i = tokens[i + 1], i + 2
        args = []
        while tokens[i] != ")":
            a, i = parse(tokens, i)
            args.append(a)
        return (op, tuple(args)), i + 1
    return tokens[i], i + 1


def parse_sexpr(s: str):
    tree, _ = parse(tokenize(s.strip()), 0)
    return tree


def is_atom(n):
    return isinstance(n, str)


def is_const_atom(n):
    # Forms: "0:i64", "1:i64", "all_ones:i64", "-1:i64", "0xFF:i64"
    return isinstance(n, str) and ":" in n


def is_var_atom(n):
    return isinstance(n, str) and ":" not in n and not n.isdigit()


def const_value_and_type(atom: str):
    value, type_ = atom.split(":")
    return value, type_


# --- Guard parser ---
GUARD_RE = re.compile(r"(\w+)\(([^)]*)\)")


def parse_guard(g: str):
    m = GUARD_RE.match(g.strip())
    if not m:
        raise ValueError(f"malformed guard: {g}")
    name = m.group(1)
    args = [a.strip() for a in m.group(2).split(",") if a.strip()]
    return name, args


GUARD_CPP = {
    "is_integer_const": "isIntegerConst(*{0})",
    "is_zero_const":    "isZeroConst(*{0})",
    "is_one_const":     "isOneConst(*{0})",
    "is_all_ones_const": "isAllOnesConst(*{0})",
    "is_nonzero_int_const": "isNonZeroIntConst(*{0})",
    "is_neg":           "isNeg(*{0})",
    "is_not_of":        "isNotOf(*{0}, *{1})",
    "has_one_use":      "MRI.hasOneNonDBGUse({0})",
    "same_type":        "({0}->getType() == {1}->getType())",
}


# --- Opcode name mapping ---
OP_ENUM = {
    "add": "OP_add", "sub": "OP_sub", "mul": "OP_mul",
    "and": "OP_and", "or": "OP_or", "xor": "OP_xor",
    "not": "OP_not", "shl": "OP_shl", "sshr": "OP_sshr", "ushr": "OP_ushr",
    "select": "OP_select", "adc": "OP_adc", "sbb": "OP_sbb",
}


# Commutative op set (for "commutative: lhs_root" swap)
COMMUTATIVE_OPS = {"add", "mul", "and", "or", "xor"}


# Which dispatch a given op belongs to (Inst cast target)
BINARY_OPS = {"add", "sub", "mul", "and", "or", "xor", "shl", "sshr", "ushr"}
UNARY_OPS = {"not"}


def dispatch_type_for(root_op: str | None) -> str:
    """Return the C++ Instruction subclass the per-opcode dispatch casts to."""
    if root_op in BINARY_OPS:
        return "BinaryInstruction"
    if root_op in UNARY_OPS:
        return "NotInstruction" if root_op == "not" else "UnaryInstruction"
    if root_op == "select":
        return "SelectInstruction"
    if root_op == "adc":
        return "AdcInstruction"
    if root_op == "sbb":
        return "SbbInstruction"
    return "MInstruction"


# status string -> RuleClass enum value. Unknown status falls back to Hand,
# matching the prior STATUS_COUNTER → g_dmirHandRuleHits default.
STATUS_RULE_CLASS = {
    "synthesized": "RuleClass::Synth",
    "pattern_synth": "RuleClass::PatternSynth",
}


def rule_class_for(status: str | None) -> str:
    return STATUS_RULE_CLASS.get(status, "RuleClass::Hand")


def rule_id_for(base_name: str, swap_root: bool) -> str:
    return base_name + ("_swap" if swap_root else "")


def has_swap_variant(rule: dict, root_op: str | None) -> bool:
    return rule.get("commutative") == "lhs_root" and root_op in COMMUTATIVE_OPS


# --- Matcher emitter ---
class MatchEmitter:
    def __init__(self, rule_name: str):
        self.rule_name = rule_name
        self.bindings: dict[str, str] = {}  # var -> C++ expr
        self.lines: list[str] = []
        self.counter = 0

    def fresh(self, prefix: str) -> str:
        self.counter += 1
        return f"{prefix}{self.counter}"

    def emit(self, line: str):
        self.lines.append(line)

    def match_root(self, expr, cpp_inst: str, indent: int = 2):
        """Match expr against Inst.

        The root opcode is guaranteed by the per-opcode dispatch in
        DMirRewritePass::tryRewrite, so we skip the redundant check here and
        go straight to binding operands.
        """
        if is_atom(expr):
            raise ValueError(f"LHS root cannot be an atom: {expr}")
        _op, args = expr
        for i, arg in enumerate(args):
            operand_cpp = f"{cpp_inst}.getOperand({i})"
            self.match_sub(arg, operand_cpp, indent)

    def match_sub(self, expr, cpp_expr: str, indent: int):
        """Match a subtree. cpp_expr is a C++ expression yielding MInstruction*."""
        pad = " " * indent
        if is_atom(expr):
            if is_const_atom(expr):
                value, type_ = const_value_and_type(expr)
                # Determine const matcher. Treat uint64 all-ones literal as
                # all_ones for stable dispatch across hand-written and synth rules.
                if value == "0":
                    check = f"isZeroConst(*{cpp_expr})"
                elif value == "1":
                    check = f"isOneConst(*{cpp_expr})"
                elif value == "all_ones" or value == "18446744073709551615":
                    check = f"isAllOnesConst(*{cpp_expr})"
                else:
                    check = f"isIntegerConstWithValue(*{cpp_expr}, {value}ULL)"
                self.emit(f"{pad}if (!{check}) return nullptr;")
            else:  # variable
                var_name = expr
                if var_name in self.bindings:
                    # same-var second occurrence: structural equality
                    prior = self.bindings[var_name]
                    self.emit(f"{pad}if (!structurallyEqual(*{prior}, *{cpp_expr})) return nullptr;")
                else:
                    # fresh bind
                    local = self.fresh("v")
                    self.emit(f"{pad}MInstruction *{local} = {cpp_expr};")
                    self.bindings[var_name] = local
        else:  # nested s-expr
            op, args = expr
            local = self.fresh("n")
            self.emit(f"{pad}MInstruction *{local} = {cpp_expr};")
            self.emit(f"{pad}if ({local}->getOpcode() != {OP_ENUM[op]}) return nullptr;")
            for i, arg in enumerate(args):
                sub_cpp = f"{local}->getOperand({i})"
                self.match_sub(arg, sub_cpp, indent)


# --- RHS emitter ---
class RhsEmitter:
    def __init__(self, bindings: dict[str, str]):
        self.bindings = bindings

    def build(self, expr, indent: int) -> str:
        """Return a C++ expression producing the RHS MInstruction*."""
        pad = " " * indent
        if is_atom(expr):
            if is_const_atom(expr):
                value, type_ = const_value_and_type(expr)
                if value == "0":
                    return f"createZeroConstant(*Inst.getType(), BB)"
                if value == "1":
                    return f"createOneConstant(*Inst.getType(), BB)"
                if value == "all_ones" or value == "18446744073709551615":
                    return f"createAllOnesConstant(*Inst.getType(), BB)"
                # Wrap raw integer value in llvm::APInt matching the type's width.
                return (
                    f"createIntegerConstant(*Inst.getType(), "
                    f"llvm::APInt(Inst.getType()->getBitWidth(), {value}ULL), BB)"
                )
            # variable — return the bound MInstruction
            if expr not in self.bindings:
                raise ValueError(f"RHS uses unbound variable: {expr}")
            return self.bindings[expr]
        op, args = expr
        if op in BINARY_OPS:
            a = self.build(args[0], indent)
            b = self.build(args[1], indent)
            return f"createBinaryInstruction({OP_ENUM[op]}, *Inst.getType(), {a}, {b}, BB)"
        if op == "not":
            a = self.build(args[0], indent)
            return f"createNotInstruction(*Inst.getType(), {a}, BB)"
        raise ValueError(f"RHS op not supported in spike generator: {op}")


# --- Guard emitter ---
def emit_guards(guards: list[str], bindings: dict[str, str], indent: int) -> list[str]:
    lines = []
    pad = " " * indent
    for g in guards or []:
        name, args = parse_guard(g)
        if name not in GUARD_CPP:
            raise ValueError(f"unknown guard: {name}")
        # Resolve args as bindings or pass-through constants
        resolved = []
        for a in args:
            if a in bindings:
                resolved.append(bindings[a])
            else:
                resolved.append(a)
        cpp = GUARD_CPP[name].format(*resolved)
        lines.append(f"{pad}if (!{cpp}) return nullptr;")
    return lines


# --- Full rule codegen ---
def emit_matcher(rule: dict, swap_root: bool = False) -> tuple[str, list[str]]:
    """Emit a single matcher function. Returns (function_name, lines)."""
    base_name = rule["name"]
    rule_id = rule_id_for(base_name, swap_root)
    fn_name = f"match_{rule_id}"

    lhs = parse_sexpr(rule["lhs"])
    # Optionally swap LHS root args (for commutative)
    if swap_root:
        if is_atom(lhs):
            raise ValueError("cannot swap atom LHS")
        op, args = lhs
        if len(args) != 2:
            raise ValueError(f"commutative swap requires 2 args, got {len(args)}")
        lhs = (op, (args[1], args[0]))

    root_op = lhs[0] if not is_atom(lhs) else None
    dispatch_type = dispatch_type_for(root_op)

    lines = []
    lines.append(f"MInstruction *{fn_name}({dispatch_type} &Inst, MBasicBlock &BB) {{")

    # Match
    me = MatchEmitter(base_name)
    me.match_root(lhs, "Inst")
    lines.extend(me.lines)

    # Guards
    lines.extend(emit_guards(rule.get("guards"), me.bindings, indent=2))

    # RHS
    rhs = parse_sexpr(rule["rhs"]) if "(" in rule["rhs"] else rule["rhs"]
    rhs_expr = RhsEmitter(me.bindings).build(rhs, indent=2)
    lines.append(f"#ifdef ZEN_ENABLE_DMIR_RULE_STATS")
    lines.append(f"  recordRuleHit(RuleId::{rule_id});")
    lines.append(f"#endif")
    lines.append(f"  return {rhs_expr};")
    lines.append("}")
    lines.append("")
    return fn_name, lines


def emit_dispatch(rule_fn_map: dict[str, list[tuple[str, str, str | None]]]) -> list[str]:
    """Emit per-opcode dispatch functions.

    rule_fn_map: {root_op: [(fn_name, dispatch_type, rule_name_or_None), ...]}
    rule_name_or_None is set ONLY for hook entries (matcher entries record
    their own hit internally, so they pass None).
    """
    lines = []
    for op, entries in sorted(rule_fn_map.items()):
        if not entries:
            continue
        dispatch_type = entries[0][1]
        lines.append(f"MInstruction *tryRewrite{op.capitalize()}Generated("
                     f"{dispatch_type} &Inst, MBasicBlock &BB) {{")
        for fn_name, _, rule_name in entries:
            if rule_name is None:
                # Matcher entry: hit already recorded inside the matcher body.
                lines.append(f"  if (auto *R = {fn_name}(Inst, BB)) return R;")
            else:
                # Hook entry: hit must be recorded at the call site since the
                # hook body is hand-written and not generated.
                lines.append(f"  if (auto *R = {fn_name}(Inst, BB)) {{")
                lines.append(f"#ifdef ZEN_ENABLE_DMIR_RULE_STATS")
                lines.append(f"    recordRuleHit(RuleId::{rule_name});")
                lines.append(f"#endif")
                lines.append(f"    return R;")
                lines.append(f"  }}")
        lines.append("  return nullptr;")
        lines.append("}")
        lines.append("")
    return lines


def emit_header() -> list[str]:
    return [
        "// Copyright (C) 2025 the DTVM authors. All Rights Reserved.",
        "// SPDX-License-Identifier: Apache-2.0",
        "// Generated by tools/generate_dmir_rewrite.py (spike). Do not edit by hand.",
        "",
    ]


def collect_rule_ids(data: dict) -> list[tuple[str, str]]:
    """Build the list of (rule_id, rule_class) pairs in JSON declaration order.

    For each non-hook rule: emit (name, class); if has_swap_variant, also emit
    (name_swap, class). For each hook rule: emit (name, class) (the rule's
    "name" field, NOT the "hook" function name).
    """
    ids: list[tuple[str, str]] = []
    for rule in data["rules"]:
        cls = rule_class_for(rule.get("status"))
        base_name = rule["name"]
        if "hook" in rule:
            ids.append((base_name, cls))
            continue
        ids.append((rule_id_for(base_name, swap_root=False), cls))
        lhs = parse_sexpr(rule["lhs"])
        root_op = lhs[0] if not is_atom(lhs) else None
        if has_swap_variant(rule, root_op):
            ids.append((rule_id_for(base_name, swap_root=True), cls))
    return ids


def emit_rule_ids_def(rule_ids: list[tuple[str, str]]) -> str:
    """Emit dmir_rule_ids.def as an X-macro fragment with two args per row:
    DMIR_RULE(<rule_id>, <RuleClass enum value>).

    Self-defaults DMIR_RULE to a no-op so the file can be included without a
    prior #define (matches the convention used by other .def files in the
    repo, e.g. opcodes.def, errors.def).
    """
    out = [
        "// Generated by tools/generate_dmir_rewrite.py. Do not edit by hand.",
        "#ifndef DMIR_RULE",
        "#define DMIR_RULE(name, cls)",
        "#endif",
    ]
    for rid, cls in rule_ids:
        out.append(f"DMIR_RULE({rid}, {cls})")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", required=True)
    ap.add_argument("--out-inc", required=True)
    ap.add_argument("--out-def", required=True)
    args = ap.parse_args()

    data = json.loads(pathlib.Path(args.rules).read_text())
    if data.get("version") != 2:
        print(f"error: expect DSL version 2, got {data.get('version')}", file=sys.stderr)
        return 1

    all_lines = emit_header()
    rule_fn_map: dict[str, list[tuple[str, str, str | None]]] = {}

    for rule in data["rules"]:
        # Hook-only rule: no DSL LHS/RHS, just dispatch to a hand-written C++ function.
        # Requires "root_op" + "dispatch_type" fields so generator knows where to wire it.
        if "hook" in rule:
            root_op = rule["root_op"]
            dispatch_type = rule.get("dispatch_type", "BinaryInstruction")
            # rule_name carries the rule's "name" so the dispatcher can record
            # the per-rule hit at the call site.
            rule_fn_map.setdefault(root_op, []).append(
                (rule["hook"], dispatch_type, rule["name"])
            )
            continue

        lhs = parse_sexpr(rule["lhs"])
        root_op = lhs[0] if not is_atom(lhs) else None
        dispatch_type = dispatch_type_for(root_op)

        fn_name, lines = emit_matcher(rule, swap_root=False)
        all_lines.extend(lines)
        # None signals that the matcher records its own hit internally.
        rule_fn_map.setdefault(root_op, []).append((fn_name, dispatch_type, None))

        if has_swap_variant(rule, root_op):
            fn_name_sw, lines_sw = emit_matcher(rule, swap_root=True)
            all_lines.extend(lines_sw)
            rule_fn_map[root_op].append((fn_name_sw, dispatch_type, None))

    all_lines.extend(emit_dispatch(rule_fn_map))

    out = "\n".join(all_lines) + "\n"
    pathlib.Path(args.out_inc).write_text(out)

    rule_ids = collect_rule_ids(data)
    pathlib.Path(args.out_def).write_text(emit_rule_ids_def(rule_ids))

    print(
        f"wrote {args.out_inc} ({len(all_lines)} lines, {len(data['rules'])} rules) "
        f"+ {args.out_def} ({len(rule_ids)} rule ids)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
