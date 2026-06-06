#!/usr/bin/env python3
"""Automated dMIR rewrite rule synthesis via enumeration + Z3 verification."""

import argparse
import json
import pathlib
import re
import sys
import time
from collections import OrderedDict

import z3

from mine_dmir_seed_rules import (
    COMMUTATIVE_OPS,
    DEFAULT_SEARCH_CONFIG,
    MASK64,
    MASK256,
    U256_BINARY_OPS,
    U256_SHIFT_OPS,
    Expr,
    binary,
    build_candidate_key,
    build_rule_key_set,
    build_sample_envs,
    build_sample_envs_256,
    canonicalize_pair,
    const,
    const_u256,
    cost_delta,
    dominates,
    eval_expr,
    expr_cost,
    is_candidate_covered,
    load_rule_patterns,
    unary,
    var,
    wrap_u64,
)

# ---------------------------------------------------------------------------
# Commutative-variant canonical key
# ---------------------------------------------------------------------------

# Commutative ops used for the post-dedup collapse. Must stay a subset of
# COMMUTATIVE_OPS in the miner; defining it locally avoids a tight coupling
# and keeps `_commute_key` readable alongside its usage.
_COMM_OPS = {"add", "and", "or", "xor", "mul"}
_TOKEN_RE = re.compile(r"\(|\)|[^\s()]+")


def _commute_key(s: str) -> str:
    """Return a canonical key for ``s`` that collapses commutative-variant
    duplicates. Unlike ``canonicalize_pair``, this key sorts operands of
    commutative ops by raw render before any alpha-renaming, so e.g.
    ``(add y (sub 0:i64 x))`` and ``(add (sub 0:i64 x) y)`` map to the same
    string. Used as a post-filter after Step 6 dedup."""
    toks = _TOKEN_RE.findall(s)
    pos = [0]

    def walk():
        tok = toks[pos[0]]
        pos[0] += 1
        if tok == "(":
            op = toks[pos[0]]
            pos[0] += 1
            args = []
            while toks[pos[0]] != ")":
                args.append(walk())
            pos[0] += 1
            if op in _COMM_OPS:
                args = sorted(args)
            return "(" + op + " " + " ".join(args) + ")"
        return tok

    return walk()


# ---------------------------------------------------------------------------
# Pattern-config expansion
# ---------------------------------------------------------------------------


def expand_pattern_config(config: dict) -> list[tuple["Expr", "Expr"]]:
    """Expand the miner DEFAULT_SEARCH_CONFIG into concrete (LHS, RHS)
    candidate pairs for Z3 verification. The cross-product intentionally
    emits semantically invalid pairs (e.g. `(add x 0) -> 0`, `(xor x x) -> x`);
    the Z3 pass in `run_synthesis` is responsible for filtering them. Do NOT
    treat the output as a validated rule list."""
    from mine_dmir_seed_rules import (
        Expr,
        parse_expr,
        unary,
        const,
        var,
    )

    pairs: list[tuple[Expr, Expr]] = []

    # binary_self: (op v v) for each op × term; candidate RHS is the term itself
    for group in config.get("binary_self", []):
        for op in group["ops"]:
            for t in group["terms"]:
                x = parse_expr(t)
                lhs = Expr(op=op, args=(x, x))
                pairs.append((lhs, x))

    # pair_binary_groups: (op lhs_term rhs_term); trial RHSs are any term in
    # the group's lhs/rhs pool. Z3 filters invalid ones.
    for group in config.get("pair_binary_groups", []):
        for op in group["ops"]:
            for l in group["lhs"]:
                for r in group["rhs"]:
                    lhs = Expr(op=op, args=(parse_expr(l), parse_expr(r)))
                    for rhs_term in group["lhs"] + group["rhs"]:
                        pairs.append((lhs, parse_expr(rhs_term)))

    # binary_fixed_rhs: (op lhs_term fixed_rhs_const) -> any term in the pool
    for group in config.get("binary_fixed_rhs", []):
        for op in group["ops"]:
            for l in group["lhs"]:
                lhs = Expr(op=op, args=(parse_expr(l),
                                        parse_expr(group["rhs"])))
                for rhs_term in group["lhs"] + [group["rhs"]]:
                    pairs.append((lhs, parse_expr(rhs_term)))

    # select_same_arm: (select cond v v) -> v
    sel = config.get("select_same_arm")
    if sel:
        for c in sel["conditions"]:
            for v in sel["values"]:
                cond = parse_expr(c)
                val = parse_expr(v)
                pairs.append((Expr(op="select", args=(cond, val, val)), val))

    # adc_sbb_zero: (adc/sbb x y 0) -> (add/sub x y), and (adc/sbb x 0 0) -> x
    cc = config.get("adc_sbb_zero")
    if cc:
        for op in cc["ops"]:
            for l in cc["lhs"]:
                for r in cc["rhs"]:
                    lhs = Expr(
                        op=op,
                        args=(parse_expr(l), parse_expr(r),
                              parse_expr(cc["carry"])),
                    )
                    reduced_op = "add" if op == "adc" else "sub"
                    rhs = Expr(op=reduced_op,
                               args=(parse_expr(l), parse_expr(r)))
                    pairs.append((lhs, rhs))
                    pairs.append((lhs, parse_expr(l)))

    # mul identity / pow2 rewrites. `pair_binary_groups` above covers
    # add/sub/and/or/xor but intentionally excludes mul (no natural identity
    # RHS pool). Enumerate the mul family here explicitly:
    #   (mul x 0) -> 0
    #   (mul x 1) -> x
    #   (mul x c) -> (shl x log2(c)) for c in {2, 4, 8}
    for v in ["x", "y"]:
        term = parse_expr(v)
        zero = parse_expr("0:i64")
        one = parse_expr("1:i64")
        pairs.append((Expr(op="mul", args=(term, zero)), zero))
        pairs.append((Expr(op="mul", args=(term, one)), term))
        for amt_bits in (1, 2, 3):
            pow2 = 1 << amt_bits
            pow2_const = parse_expr(f"{pow2}:i64")
            amt_const = parse_expr(f"{amt_bits}:i64")
            lhs = Expr(op="mul", args=(term, pow2_const))
            rhs = Expr(op="shl", args=(term, amt_const))
            pairs.append((lhs, rhs))

    # double-not: (not (not v)) -> v
    for v_spec in ["x", "y", "cond"]:
        v = parse_expr(v_spec)
        pairs.append((unary("not", unary("not", v)), v))

    # shift-zero: (<shift> v 0:i64) -> v  for shl / ushr / sshr
    for op in ("shl", "ushr", "sshr"):
        for v_spec in ["x", "y"]:
            v = parse_expr(v_spec)
            pairs.append((Expr(op=op, args=(v, parse_expr("0:i64"))), v))

    # -----------------------------------------------------------------
    # Task 6: depth-2 RHS patterns for prod rules still unmatched at
    # Z3-on after Task 5. Five structural families (A-D) targeting the
    # 19 residual misses.
    # -----------------------------------------------------------------

    # Family A: not + {or,xor,or-or} with MASK64 RHS.
    # or-not-self, xor-not-self, or-not-or -> MASK64
    MASK64_CONST = parse_expr("18446744073709551615:i64")
    for v_spec in ["x", "y"]:
        v = parse_expr(v_spec)
        pairs.append((Expr(op="or", args=(unary("not", v), v)), MASK64_CONST))
        pairs.append((Expr(op="xor", args=(unary("not", v), v)), MASK64_CONST))
    for x_spec, y_spec in [("x", "y"), ("y", "x")]:
        x = parse_expr(x_spec)
        y = parse_expr(y_spec)
        lhs = Expr(op="or", args=(unary("not", x),
                                  Expr(op="or", args=(x, y))))
        pairs.append((lhs, MASK64_CONST))

    # Family B: (not x) absorbing a matching subterm in its companion.
    for x_spec, y_spec in [("x", "y"), ("y", "x")]:
        x = parse_expr(x_spec)
        y = parse_expr(y_spec)
        not_x = unary("not", x)
        not_y = unary("not", y)
        # and-not-or, and-not-xor:
        #   (and (not x) (<or|xor> x y)) -> (and (not x) y)
        for inner_op in ("or", "xor"):
            lhs = Expr(op="and",
                       args=(not_x, Expr(op=inner_op, args=(x, y))))
            rhs = Expr(op="and", args=(not_x, y))
            pairs.append((lhs, rhs))
        # or-and-not-lhs, xor-and-not-lhs:
        #   (<or|xor> (and x y) (not x)) -> (or (not x) y)
        for outer_op in ("or", "xor"):
            lhs = Expr(op=outer_op,
                       args=(Expr(op="and", args=(x, y)), not_x))
            rhs = Expr(op="or", args=(not_x, y))
            pairs.append((lhs, rhs))
        # or-and-not-rhs, xor-and-not-rhs:
        #   (<or|xor> (and x y) (not y)) -> (or (not y) x)
        for outer_op in ("or", "xor"):
            lhs = Expr(op=outer_op,
                       args=(Expr(op="and", args=(x, y)), not_y))
            rhs = Expr(op="or", args=(not_y, x))
            pairs.append((lhs, rhs))
        # xor-not-or: (xor (not x) (or x y)) -> (or (not y) x)
        lhs = Expr(op="xor",
                   args=(not_x, Expr(op="or", args=(x, y))))
        rhs = Expr(op="or", args=(not_y, x))
        pairs.append((lhs, rhs))

    # Family C: select specializations.
    #   (select 0:i64 t f) -> f
    #   (select 1:i64 t f) -> t
    zero_c = parse_expr("0:i64")
    one_c = parse_expr("1:i64")
    for t_spec in ["x", "y", "cond"]:
        for f_spec in ["x", "y", "cond"]:
            if t_spec == f_spec:
                continue
            t = parse_expr(t_spec)
            f = parse_expr(f_spec)
            pairs.append((Expr(op="select", args=(zero_c, t, f)), f))
            pairs.append((Expr(op="select", args=(one_c, t, f)), t))

    # Family D: add/sub depth-2 identities.
    # add-self-to-shl1: (add v v) -> (shl v 1)
    for v_spec in ["x", "y"]:
        v = parse_expr(v_spec)
        pairs.append((Expr(op="add", args=(v, v)),
                      Expr(op="shl", args=(v, parse_expr("1:i64")))))
    # add-neg-x-y-to-sub-y-x, add-y-neg-x-to-sub-y-x
    for x_spec, y_spec in [("x", "y"), ("y", "x")]:
        x = parse_expr(x_spec)
        y = parse_expr(y_spec)
        neg_x = Expr(op="sub", args=(parse_expr("0:i64"), x))
        pairs.append((Expr(op="add", args=(neg_x, y)),
                      Expr(op="sub", args=(y, x))))
        pairs.append((Expr(op="add", args=(y, neg_x)),
                      Expr(op="sub", args=(y, x))))
    # add-and-xor-to-or, add-and-or-to-add, sub-or-and-to-xor
    for x_spec, y_spec in [("x", "y"), ("y", "x")]:
        x = parse_expr(x_spec)
        y = parse_expr(y_spec)
        and_xy = Expr(op="and", args=(x, y))
        or_xy = Expr(op="or", args=(x, y))
        xor_xy = Expr(op="xor", args=(x, y))
        pairs.append((Expr(op="add", args=(and_xy, xor_xy)), or_xy))
        pairs.append((Expr(op="add", args=(and_xy, or_xy)),
                      Expr(op="add", args=(x, y))))
        pairs.append((Expr(op="sub", args=(or_xy, and_xy)), xor_xy))

    return pairs


# ---------------------------------------------------------------------------
# Expression enumeration
# ---------------------------------------------------------------------------

BINARY_OPS = ["add", "sub", "mul", "and", "or", "xor"]
SHIFT_OPS = ["shl", "ushr", "sshr"]
SHIFT_AMOUNTS = [1, 2, 3, 4, 8, 16, 32, 63]
CONSTANTS = [0, 1, 2, 3, (1 << 32) - 1, (1 << 63), MASK64]
VAR_NAMES_2 = ["x", "y"]

U256_SHIFT_AMOUNTS = [0, 1, 8, 63, 64, 127, 128, 192, 255, 256]
U256_CONSTANTS = [0, 1, MASK256]
U256_VAR_NAMES_2 = ["x_256", "y_256"]


def _expr_sort_key(e: Expr) -> str:
    return e.render()


class ExprBank:
    """Stores expressions indexed by depth, with deduplication by eval signature."""

    def __init__(self, envs: list[dict[str, int]]):
        self.envs = envs
        self.by_depth: dict[int, list[Expr]] = {}
        self.seen_sigs: set[tuple[int, ...]] = set()
        self.sig_to_exprs: dict[tuple[int, ...], list[Expr]] = {}
        self.total_added = 0
        self.total_deduped = 0

    def signature(self, expr: Expr) -> tuple[int, ...]:
        return tuple(eval_expr(expr, env) for env in self.envs)

    def add(self, expr: Expr, depth: int) -> bool:
        sig = self.signature(expr)
        self.by_depth.setdefault(depth, [])
        if sig in self.seen_sigs:
            self.total_deduped += 1
            existing = self.sig_to_exprs[sig]
            ec = expr_cost(expr)["dmir_inst"]
            best_ec = min(expr_cost(e)["dmir_inst"] for e in existing)
            if ec < best_ec:
                existing.append(expr)
                self.by_depth[depth].append(expr)
                self.total_added += 1
            return False
        self.seen_sigs.add(sig)
        self.sig_to_exprs.setdefault(sig, []).append(expr)
        self.by_depth[depth].append(expr)
        self.total_added += 1
        return True

    def all_up_to(self, depth: int) -> list[Expr]:
        result = []
        for d in range(depth + 1):
            result.extend(self.by_depth.get(d, []))
        return result


def enumerate_expressions(
    max_depth: int, num_vars: int, envs: list[dict[str, int]], max_cost: int = 6,
    verbose: bool = False,
) -> ExprBank:
    bank = ExprBank(envs)
    var_names = VAR_NAMES_2[:num_vars]

    # Depth 0: leaves
    for name in var_names:
        bank.add(var(name), 0)
    for c in CONSTANTS:
        bank.add(const(c), 0)
    if verbose:
        _log(f"depth 0: {len(bank.by_depth.get(0, []))} terms")

    for depth in range(1, max_depth + 1):
        prev_all = bank.all_up_to(depth - 1)
        prev_exact = bank.by_depth.get(depth - 1, [])
        prev_exact_set = set(id(e) for e in prev_exact)

        # For depth >= 3, limit the RHS pool to depth 0-1 to avoid O(n^2) on
        # large depth-2 sets. This still discovers (depth2 op leaf) patterns.
        if depth >= 3:
            shallow = bank.all_up_to(1)
        else:
            shallow = None  # use prev_all

        def is_new_depth(e: Expr) -> bool:
            return id(e) in prev_exact_set

        # Unary: not
        for e in prev_exact:
            candidate = unary("not", e)
            if expr_cost(candidate)["dmir_inst"] <= max_cost:
                bank.add(candidate, depth)

        # Binary ops
        rhs_pool = shallow if shallow is not None else prev_all
        for op in BINARY_OPS:
            is_comm = op in COMMUTATIVE_OPS
            # new_depth × rhs_pool
            for lhs_e in prev_exact:
                for rhs_e in rhs_pool:
                    if is_comm and _expr_sort_key(lhs_e) > _expr_sort_key(rhs_e):
                        continue
                    candidate = binary(op, lhs_e, rhs_e)
                    if expr_cost(candidate)["dmir_inst"] <= max_cost:
                        bank.add(candidate, depth)
            # lhs_pool × new_depth (non-commutative, or commutative with swapped order)
            for lhs_e in rhs_pool:
                for rhs_e in prev_exact:
                    if is_new_depth(lhs_e) and is_new_depth(rhs_e):
                        continue  # already covered above
                    if is_comm and _expr_sort_key(lhs_e) > _expr_sort_key(rhs_e):
                        continue
                    candidate = binary(op, lhs_e, rhs_e)
                    if expr_cost(candidate)["dmir_inst"] <= max_cost:
                        bank.add(candidate, depth)

        # Shifts with constant amounts
        for op in SHIFT_OPS:
            for e in prev_exact:
                for amt in SHIFT_AMOUNTS:
                    candidate = binary(op, e, const(amt))
                    if expr_cost(candidate)["dmir_inst"] <= max_cost:
                        bank.add(candidate, depth)

        if verbose:
            d_count = len(bank.by_depth.get(depth, []))
            _log(f"depth {depth}: +{d_count} terms (total {bank.total_added}, "
                 f"deduped {bank.total_deduped})")

    return bank


def enumerate_u256_expressions(
    max_depth: int, envs: list[dict[str, int]], max_cost: int = 4,
    verbose: bool = False,
) -> ExprBank:
    """Enumerate u256-typed expressions over evm_u256_* pseudo-ops.

    Scope:
    - Leaves: x_256, y_256, constants 0/1/MASK256
    - Binary (commutative): u256_and, u256_or, u256_xor
    - Shifts with constant amount only: u256_shl, u256_shr, u256_sar
      over U256_SHIFT_AMOUNTS = [0, 1, 8, 63, 64, 127, 128, 192, 255, 256]
    - No unary `not` (no u256_not pseudo-op)
    - No mixing with u64 ops (shift amounts are constants, not composed)
    """
    bank = ExprBank(envs)

    # Depth 0
    for name in U256_VAR_NAMES_2:
        bank.add(var(name), 0)
    for c in U256_CONSTANTS:
        bank.add(const(c), 0)
    if verbose:
        _log(f"u256 depth 0: {len(bank.by_depth.get(0, []))} terms")

    for depth in range(1, max_depth + 1):
        prev_all = bank.all_up_to(depth - 1)
        prev_exact = bank.by_depth.get(depth - 1, [])
        prev_exact_set = set(id(e) for e in prev_exact)

        # Keep the full pool — u256 enumeration is smaller than u64 so no
        # shallow-pool limit needed at depth 2.
        rhs_pool = prev_all

        def is_new_depth(e: Expr) -> bool:
            return id(e) in prev_exact_set

        # Commutative binary: u256_and, u256_or, u256_xor
        for op in sorted(U256_BINARY_OPS):
            for lhs_e in prev_exact:
                for rhs_e in rhs_pool:
                    if _expr_sort_key(lhs_e) > _expr_sort_key(rhs_e):
                        continue
                    candidate = binary(op, lhs_e, rhs_e)
                    if expr_cost(candidate)["dmir_inst"] <= max_cost:
                        bank.add(candidate, depth)
            for lhs_e in rhs_pool:
                for rhs_e in prev_exact:
                    if is_new_depth(lhs_e) and is_new_depth(rhs_e):
                        continue  # already covered above
                    if _expr_sort_key(lhs_e) > _expr_sort_key(rhs_e):
                        continue
                    candidate = binary(op, lhs_e, rhs_e)
                    if expr_cost(candidate)["dmir_inst"] <= max_cost:
                        bank.add(candidate, depth)

        # Shifts with constant amount (const amount is treated as u64 at Z3
        # encoding time — expr_to_z3_256 narrows via _expr_to_z3_u64_subterm).
        for op in sorted(U256_SHIFT_OPS):
            for e in prev_exact:
                for amt in U256_SHIFT_AMOUNTS:
                    candidate = binary(op, e, const(amt))
                    if expr_cost(candidate)["dmir_inst"] <= max_cost:
                        bank.add(candidate, depth)

        if verbose:
            d_count = len(bank.by_depth.get(depth, []))
            _log(f"u256 depth {depth}: +{d_count} terms (total {bank.total_added}, "
                 f"deduped {bank.total_deduped})")

    return bank


# ---------------------------------------------------------------------------
# Z3 verification
# ---------------------------------------------------------------------------

def expr_to_z3(expr: Expr, z3_vars: dict[str, z3.BitVecRef]) -> z3.BitVecRef:
    if expr.op == "var":
        return z3_vars[str(expr.value)]
    if expr.op == "const":
        return z3.BitVecVal(int(expr.value), 64)
    if expr.op == "not":
        return ~expr_to_z3(expr.args[0], z3_vars)

    # select(cond, t, f): handle before binary extraction since it has 3 args
    # with a condition predicate semantically distinct from the value slots.
    if expr.op == "select" and len(expr.args) == 3:
        cond_z3 = expr_to_z3(expr.args[0], z3_vars)
        t_z3 = expr_to_z3(expr.args[1], z3_vars)
        f_z3 = expr_to_z3(expr.args[2], z3_vars)
        return z3.If(cond_z3 != z3.BitVecVal(0, 64), t_z3, f_z3)

    lhs_z3 = expr_to_z3(expr.args[0], z3_vars)
    rhs_z3 = expr_to_z3(expr.args[1], z3_vars)

    op = expr.op
    if op == "add":
        return lhs_z3 + rhs_z3
    if op == "sub":
        return lhs_z3 - rhs_z3
    if op == "mul":
        return lhs_z3 * rhs_z3
    if op == "and":
        return lhs_z3 & rhs_z3
    if op == "or":
        return lhs_z3 | rhs_z3
    if op == "xor":
        return lhs_z3 ^ rhs_z3
    if op == "shl":
        return z3.If(z3.UGE(rhs_z3, z3.BitVecVal(64, 64)),
                     z3.BitVecVal(0, 64), lhs_z3 << rhs_z3)
    if op == "ushr":
        return z3.If(z3.UGE(rhs_z3, z3.BitVecVal(64, 64)),
                     z3.BitVecVal(0, 64), z3.LShR(lhs_z3, rhs_z3))
    if op == "sshr":
        return z3.If(z3.UGE(rhs_z3, z3.BitVecVal(64, 64)),
                     lhs_z3 >> z3.BitVecVal(63, 64), lhs_z3 >> rhs_z3)
    # Ternary carry-chain ops
    if expr.op in ("adc", "sbb") and len(expr.args) == 3:
        carry_z3 = expr_to_z3(expr.args[2], z3_vars)
        if expr.op == "adc":
            return lhs_z3 + rhs_z3 + carry_z3
        return lhs_z3 - rhs_z3 - carry_z3

    raise ValueError(f"unsupported op: {op}")


def expand_u256_pattern_config() -> list[dict]:
    x = var("x")
    zero = const_u256(0)
    lhs = Expr(op="u256_xor", args=(x, x))
    rhs = zero
    lhs_cost = expr_cost(lhs)
    rhs_cost = expr_cost(rhs)
    return [
        {
            "lhs_expr": lhs,
            "rhs_expr": rhs,
            "lhs": "(u256_xor x x)",
            "rhs": "(const_u256 0)",
            "cost": {
                "lhs": lhs_cost,
                "rhs": rhs_cost,
                "delta": cost_delta(lhs_cost, rhs_cost),
            },
            "source": "pattern_config_u256",
        }
    ]

def _expr_to_z3_u64_subterm(expr: Expr,
                            z3_vars: dict[str, z3.BitVecRef]) -> z3.BitVecRef:
    """Encode an expression that must produce a u64 (BitVec(64)).

    Used for u256 shift amounts. Leaves are u64 vars or consts. For composed
    shift amounts (rare), fall back to the full u64 encoder."""
    if expr.op == "var":
        v = z3_vars[str(expr.value)]
        assert v.size() == 64, f"var {expr.value} is not u64-typed"
        return v
    if expr.op == "const":
        return z3.BitVecVal(int(expr.value), 64)
    return expr_to_z3(expr, z3_vars)


def expr_to_z3_256(expr: Expr,
                   z3_vars: dict[str, z3.BitVecRef]) -> z3.BitVecRef:
    """Encode a u256-typed expression tree to a 256-bit BV Z3 formula.

    u256 binary ops map to native bvand/bvor/bvxor. u256 shifts guard with
    UGE(k, 256) per x86 lowering semantics (SHL/SHR return 0, SAR returns
    sign-broadcast). Shift amount is u64; ZeroExt to 256 before the shift."""
    if expr.op == "var":
        v = z3_vars[str(expr.value)]
        assert v.size() == 256, f"var {expr.value} is not u256-typed"
        return v
    if expr.op == "const":
        return z3.BitVecVal(int(expr.value), 256)
    if expr.op == "const_u256":
        return z3.BitVecVal(int(expr.value), 256)

    if expr.op in U256_BINARY_OPS:
        a = expr_to_z3_256(expr.args[0], z3_vars)
        b = expr_to_z3_256(expr.args[1], z3_vars)
        if expr.op == "u256_and":
            return a & b
        if expr.op == "u256_or":
            return a | b
        return a ^ b  # u256_xor

    if expr.op in U256_SHIFT_OPS:
        v = expr_to_z3_256(expr.args[0], z3_vars)
        k_64 = _expr_to_z3_u64_subterm(expr.args[1], z3_vars)
        k_256 = z3.ZeroExt(192, k_64)
        overflow = z3.UGE(k_64, z3.BitVecVal(256, 64))
        if expr.op == "u256_shl":
            return z3.If(overflow, z3.BitVecVal(0, 256), v << k_256)
        if expr.op == "u256_shr":
            return z3.If(overflow, z3.BitVecVal(0, 256), z3.LShR(v, k_256))
        # u256_sar
        sign_bit_set = z3.Extract(255, 255, v) == z3.BitVecVal(1, 1)
        sign_fill = z3.If(sign_bit_set,
                          z3.BitVecVal(MASK256, 256),
                          z3.BitVecVal(0, 256))
        return z3.If(overflow, sign_fill, v >> k_256)

    raise ValueError(f"unsupported u256 op {expr.op}")


def verify_equivalence_256(
    lhs: Expr, rhs: Expr,
    var_names_256: list[str], var_names_64: list[str],
    timeout_ms: int = 30000,
) -> tuple[bool, str]:
    """Z3 equivalence check at 256-bit BV.

    var_names_256: u256-typed variable names (get BitVec(256))
    var_names_64 : u64-typed variable names (shift amounts; get BitVec(64))
    """
    z3_vars: dict[str, z3.BitVecRef] = {}
    for n in var_names_256:
        z3_vars[n] = z3.BitVec(n, 256)
    for n in var_names_64:
        z3_vars[n] = z3.BitVec(n, 64)
    try:
        lhs_z3 = expr_to_z3_256(lhs, z3_vars)
        rhs_z3 = expr_to_z3_256(rhs, z3_vars)
    except (ValueError, KeyError, AssertionError) as e:
        return False, f"encode_error: {e}"

    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    solver.add(lhs_z3 != rhs_z3)
    r = solver.check()
    if r == z3.unsat:
        return True, "valid"
    if r == z3.sat:
        return False, "invalid"
    return False, "timeout"


def verify_equivalence(
    lhs: Expr, rhs: Expr, var_names: list[str], timeout_ms: int = 5000,
) -> tuple[bool, str]:
    z3_vars = {name: z3.BitVec(name, 64) for name in var_names}
    try:
        lhs_z3 = expr_to_z3(lhs, z3_vars)
        rhs_z3 = expr_to_z3(rhs, z3_vars)
    except (ValueError, KeyError) as e:
        return False, f"encode_error: {e}"

    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    solver.add(lhs_z3 != rhs_z3)

    result = solver.check()
    if result == z3.unsat:
        return True, "valid"
    if result == z3.sat:
        return False, "invalid"
    return False, "timeout"


# ---------------------------------------------------------------------------
# Carry-chain synthesis (Phase 3)
# ---------------------------------------------------------------------------

def _carry_out_z3(a: z3.BitVecRef, b: z3.BitVecRef,
                  cf: z3.BitVecRef) -> z3.BitVecRef:
    """Compute carry-out of a + b + cf using 65-bit arithmetic."""
    wide_a = z3.ZeroExt(1, a)
    wide_b = z3.ZeroExt(1, b)
    wide_cf = z3.ZeroExt(1, cf)
    wide_sum = wide_a + wide_b + wide_cf
    return z3.Extract(64, 64, wide_sum)  # bit 64 = carry out


def _borrow_out_z3(a: z3.BitVecRef, b: z3.BitVecRef,
                   bf: z3.BitVecRef) -> z3.BitVecRef:
    """Compute borrow-out of a - b - bf using 65-bit arithmetic."""
    wide_a = z3.ZeroExt(1, a)
    wide_b = z3.ZeroExt(1, b)
    wide_bf = z3.ZeroExt(1, bf)
    wide_diff = wide_a - wide_b - wide_bf
    return z3.Extract(64, 64, wide_diff)  # bit 64 = borrow out


def verify_carry_rule(
    lhs: Expr, rhs: Expr, var_names: list[str],
    carry_mode: str = "carry_zero", timeout_ms: int = 10000,
) -> tuple[bool, str]:
    """
    Verify equivalence of a carry-chain rule under carry constraints.

    carry_mode:
      - "carry_zero": cf_in is 0 (safe at chain head or after non-carrying op)
      - "carry_any": cf_in is unconstrained {0, 1} (universally valid)
      - "result_and_carry": both result AND carry_out must match
    """
    z3_vars = {name: z3.BitVec(name, 64) for name in var_names if name != "cf"}

    cf_bit = z3.BitVec("cf_bit", 1)
    if carry_mode == "carry_zero":
        cf_64 = z3.BitVecVal(0, 64)
    else:
        cf_64 = z3.ZeroExt(63, cf_bit)
    z3_vars["cf"] = cf_64

    try:
        lhs_z3 = expr_to_z3(lhs, z3_vars)
        rhs_z3 = expr_to_z3(rhs, z3_vars)
    except (ValueError, KeyError) as e:
        return False, f"encode_error: {e}"

    solver = z3.Solver()
    solver.set("timeout", timeout_ms)

    if carry_mode == "carry_any":
        solver.add(z3.Or(cf_bit == z3.BitVecVal(0, 1),
                         cf_bit == z3.BitVecVal(1, 1)))

    if carry_mode == "result_and_carry":
        # Also verify carry-out matches (for chain-interior rules)
        solver.add(z3.Or(cf_bit == z3.BitVecVal(0, 1),
                         cf_bit == z3.BitVecVal(1, 1)))
        # Extract operands from LHS to compute carry_out
        # This is for rules like adc(x,y,cf) where we need carry to also match
        if lhs.op == "adc" and rhs.op == "adc":
            lhs_a = expr_to_z3(lhs.args[0], z3_vars)
            lhs_b = expr_to_z3(lhs.args[1], z3_vars)
            lhs_cf = expr_to_z3(lhs.args[2], z3_vars)
            rhs_a = expr_to_z3(rhs.args[0], z3_vars)
            rhs_b = expr_to_z3(rhs.args[1], z3_vars)
            rhs_cf = expr_to_z3(rhs.args[2], z3_vars)
            lhs_cout = _carry_out_z3(lhs_a, lhs_b, lhs_cf)
            rhs_cout = _carry_out_z3(rhs_a, rhs_b, rhs_cf)
            solver.add(z3.Or(lhs_z3 != rhs_z3, lhs_cout != rhs_cout))
            result = solver.check()
            if result == z3.unsat:
                return True, "valid_with_carry"
            if result == z3.sat:
                return False, "invalid_carry_mismatch"
            return False, "timeout"

    solver.add(lhs_z3 != rhs_z3)
    result = solver.check()
    if result == z3.unsat:
        return True, "valid"
    if result == z3.sat:
        return False, "invalid"
    return False, "timeout"


def synthesize_carry_rules(verbose: bool = True) -> list[dict]:
    """
    Synthesize ADC/SBB rewrite rules with carry-chain safety proofs.
    Tests each candidate under three modes:
      1. carry_any: universally valid (safe everywhere)
      2. carry_zero: valid when cf_in = 0 (needs precondition)
      3. neither: UNSAFE (the rule we incorrectly implemented before)
    """
    from mine_dmir_seed_rules import ternary

    results = []

    # Build candidate ADC/SBB rules
    candidates = []
    var_x = var("x")
    var_y = var("y")
    cf = var("cf")
    zero = const(0)
    one = const(1)

    # ADC candidates: adc(x, y, cf) vs simpler forms
    adc_forms = [
        (ternary("adc", var_x, var_y, cf), "adc(x, y, cf)"),
        (ternary("adc", var_x, zero, cf), "adc(x, 0, cf)"),
        (ternary("adc", zero, var_y, cf), "adc(0, y, cf)"),
        (ternary("adc", var_x, var_x, cf), "adc(x, x, cf)"),
        (ternary("adc", zero, zero, cf), "adc(0, 0, cf)"),
    ]

    simpler_forms = [
        (binary("add", var_x, var_y), "add(x, y)"),
        (var_x, "x"),
        (var_y, "y"),
        (zero, "0"),
        (binary("add", var_x, cf), "add(x, cf)"),
        (binary("add", var_y, cf), "add(y, cf)"),
        (cf, "cf"),
        (binary("shl", var_x, one), "shl(x, 1)"),
        (binary("add", binary("add", var_x, var_x), cf), "add(add(x,x), cf)"),
        (binary("add", binary("add", var_x, var_y), cf), "add(add(x,y), cf)"),
    ]

    for adc_expr, adc_name in adc_forms:
        for simple_expr, simple_name in simpler_forms:
            candidates.append({
                "lhs": adc_expr,
                "rhs": simple_expr,
                "lhs_name": adc_name,
                "rhs_name": simple_name,
                "op": "adc",
            })

    # SBB candidates: sbb(x, y, cf) vs simpler forms
    sbb_forms = [
        (ternary("sbb", var_x, var_y, cf), "sbb(x, y, cf)"),
        (ternary("sbb", var_x, zero, cf), "sbb(x, 0, cf)"),
        (ternary("sbb", zero, var_y, cf), "sbb(0, y, cf)"),
        (ternary("sbb", var_x, var_x, cf), "sbb(x, x, cf)"),
    ]

    sbb_simpler = [
        (binary("sub", var_x, var_y), "sub(x, y)"),
        (var_x, "x"),
        (binary("sub", zero, var_y), "sub(0, y)"),
        (zero, "0"),
        (binary("sub", var_x, cf), "sub(x, cf)"),
        (binary("sub", zero, cf), "sub(0, cf)"),
        (binary("sub", binary("sub", var_x, var_y), cf), "sub(sub(x,y), cf)"),
    ]

    for sbb_expr, sbb_name in sbb_forms:
        for simple_expr, simple_name in sbb_simpler:
            candidates.append({
                "lhs": sbb_expr,
                "rhs": simple_expr,
                "lhs_name": sbb_name,
                "rhs_name": simple_name,
                "op": "sbb",
            })

    if verbose:
        _log(f"carry-chain candidates: {len(candidates)}")

    # Test each candidate under different carry modes
    for c in candidates:
        lhs_e, rhs_e = c["lhs"], c["rhs"]
        var_names = sorted(extract_var_names(lhs_e) | extract_var_names(rhs_e))

        # Mode 1: universally valid (cf ∈ {0,1})
        valid_any, status_any = verify_carry_rule(
            lhs_e, rhs_e, var_names, "carry_any")

        # Mode 2: valid when cf = 0
        valid_zero, status_zero = verify_carry_rule(
            lhs_e, rhs_e, var_names, "carry_zero")

        if valid_any or valid_zero:
            safety = "universal" if valid_any else "carry_zero_only"
            results.append({
                "lhs": lhs_e.render(),
                "rhs": rhs_e.render(),
                "lhs_desc": c["lhs_name"],
                "rhs_desc": c["rhs_name"],
                "op": c["op"],
                "safety": safety,
                "z3_any": status_any,
                "z3_zero": status_zero,
            })
            if verbose:
                _log(f"  ✓ {c['lhs_name']} → {c['rhs_name']}  [{safety}]")

    if verbose:
        n_univ = sum(1 for r in results if r["safety"] == "universal")
        n_zero = sum(1 for r in results if r["safety"] == "carry_zero_only")
        _log(f"carry rules found: {len(results)} "
             f"({n_univ} universal, {n_zero} carry_zero_only)")

    return results


# ---------------------------------------------------------------------------
# Candidate extraction and filtering
# ---------------------------------------------------------------------------

def extract_var_names(expr: Expr) -> set[str]:
    if expr.op == "var":
        return {str(expr.value)}
    result: set[str] = set()
    for a in expr.args:
        result |= extract_var_names(a)
    return result


def extract_candidates(bank: ExprBank) -> list[dict]:
    candidates = []
    for sig, exprs in bank.sig_to_exprs.items():
        if len(exprs) < 2:
            continue
        sorted_exprs = sorted(
            exprs,
            key=lambda e: (
                expr_cost(e)["dmir_inst"],
                expr_cost(e).get("select_depth", 0),
                expr_cost(e).get("adc_chain", 0),
                e.render(),
            ),
        )
        best = sorted_exprs[0]
        best_cost = expr_cost(best)
        for other in sorted_exprs[1:]:
            other_cost = expr_cost(other)
            if dominates(best_cost, other_cost):
                candidates.append(
                    {
                        "lhs_expr": other,
                        "rhs_expr": best,
                        "lhs": other.render(),
                        "rhs": best.render(),
                        "cost": {
                            "lhs": other_cost,
                            "rhs": best_cost,
                            "delta": cost_delta(other_cost, best_cost),
                        },
                        "source": "enumerator",
                    }
                )
    return candidates


def filter_novel(
    candidates: list[dict],
    rule_patterns: list[tuple[Expr, Expr]],
    rule_keys: set[tuple[str, str]],
) -> list[dict]:
    novel = []
    for c in candidates:
        lhs_e, rhs_e = c["lhs_expr"], c["rhs_expr"]
        cl, cr = canonicalize_pair(lhs_e, rhs_e)
        key = build_candidate_key(cl, cr)
        if key in rule_keys:
            continue
        if is_candidate_covered(lhs_e, rhs_e, rule_patterns, rule_keys):
            continue
        novel.append(c)
    return novel


def auto_name(lhs: Expr, rhs: Expr, index: int, prefix: str = "synth") -> str:
    ops = set()

    def collect(e: Expr):
        if e.op not in ("var", "const"):
            ops.add(e.op)
        for a in e.args:
            collect(a)

    collect(lhs)
    collect(rhs)
    tag = "-".join(sorted(ops)[:3]) if ops else "identity"
    return f"{prefix}-{tag}-{index:03d}"


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def _log(msg: str):
    sys.stderr.write(f"[synth] {msg}\n")
    sys.stderr.flush()


def run_synthesis(args) -> dict:
    t0 = time.time()

    # Step 1: Build test vectors
    envs = build_sample_envs()
    _log(f"sample envs: {len(envs)}")

    # Step 2: Enumerate
    _log(f"enumerating expressions (depth={args.max_depth}, vars={args.num_vars}, "
         f"max_cost={args.max_cost})...")
    bank = enumerate_expressions(
        max_depth=args.max_depth,
        num_vars=args.num_vars,
        envs=envs,
        max_cost=args.max_cost,
        verbose=True,
    )
    _log(f"expression bank: {bank.total_added} terms, "
         f"{len(bank.sig_to_exprs)} unique signatures")

    # Step 3: Extract candidates
    raw = extract_candidates(bank)
    _log(f"raw candidates: {len(raw)}")

    # Step 4: Filter against existing rules
    rule_patterns = load_rule_patterns(args.rules) if args.rules else []
    rule_keys = build_rule_key_set(rule_patterns)
    novel = filter_novel(raw, rule_patterns, rule_keys)
    _log(f"novel candidates (not in existing rules): {len(novel)}")

    # Step 5: Z3 verification
    verified = []
    rejected = []
    if not args.no_z3 and novel:
        _log(f"verifying {len(novel)} candidates with Z3 (timeout={args.z3_timeout}ms)...")
        for i, c in enumerate(novel):
            var_names = sorted(extract_var_names(c["lhs_expr"]) |
                               extract_var_names(c["rhs_expr"]))
            is_valid, status = verify_equivalence(
                c["lhs_expr"], c["rhs_expr"], var_names, args.z3_timeout,
            )
            if is_valid:
                verified.append(c)
            else:
                c["z3_status"] = status
                rejected.append(c)
            if (i + 1) % 50 == 0:
                _log(f"  verified {i + 1}/{len(novel)} "
                     f"(valid={len(verified)}, rejected={len(rejected)})")
        _log(f"Z3 done: {len(verified)} valid, {len(rejected)} rejected")
    elif args.no_z3:
        verified = novel
        _log("Z3 skipped (--no-z3)")

    # Step 5b: Merge pattern-config candidates (S3 extension).
    # The miner's DEFAULT_SEARCH_CONFIG encodes structural LHS families
    # (e.g. `(and x x)`, `(or x (not x))`) that naive enumeration misses
    # because both sides sit at the same depth/cost. Z3 is the semantic
    # filter — invalid cross-product pairs are dropped here.
    pattern_pairs = expand_pattern_config(DEFAULT_SEARCH_CONFIG)
    _log(f"pattern-config: {len(pattern_pairs)} candidate pairs")
    _log("pattern-config: Z3 is always used for pattern pairs "
         "(--no-z3 does not apply; cross-product emits invalid pairs "
         "that only Z3 can filter)")
    pattern_accepted = 0
    pattern_new_keys = 0
    existing_keys: set[tuple[str, str]] = set()
    for c in verified:
        lhs_e = c.get("lhs_expr")
        rhs_e = c.get("rhs_expr")
        if lhs_e is not None and rhs_e is not None:
            cl, cr = canonicalize_pair(lhs_e, rhs_e)
            existing_keys.add(build_candidate_key(cl, cr))
    for lhs, rhs in pattern_pairs:
        # I-3: skip pattern pairs already covered by --rules JSON.
        cl, cr = canonicalize_pair(lhs, rhs)
        key = build_candidate_key(cl, cr)
        if key in rule_keys:
            continue
        var_names = sorted(extract_var_names(lhs) | extract_var_names(rhs))
        # I-1: always verify pattern pairs with Z3. The cross-product
        # expansion emits semantically invalid pairs by design; without
        # Z3 the output's `lhs → rhs` is unchecked. --no-z3 only applies
        # to the enumerator path above.
        ok, _status = verify_equivalence(
            lhs, rhs, var_names, args.z3_timeout,
        )
        if not ok:
            continue
        lhs_cost = expr_cost(lhs)
        rhs_cost = expr_cost(rhs)
        delta = cost_delta(lhs_cost, rhs_cost)
        if delta["dmir_inst"] > 0:
            continue  # RHS strictly worse — reject. delta==0 allowed for
                      # equivalence rewrites like mul-pow2-to-shl where the
                      # simplification is at the ISA level, not dmir_inst.
        is_new = key not in existing_keys
        if is_new:
            existing_keys.add(key)
            pattern_new_keys += 1
        verified.append({
            "lhs": lhs.render(),
            "rhs": rhs.render(),
            "lhs_expr": lhs,
            "rhs_expr": rhs,
            "cost": {"lhs": lhs_cost, "rhs": rhs_cost, "delta": delta},
            "source": "pattern_config",
        })
        pattern_accepted += 1
    _log(
        f"pattern-config: +{pattern_accepted} pairs verified, "
        f"+{pattern_new_keys} new (rest duplicates)"
    )

    # Step 6: Deduplicate by canonical key. When both enumerator and
    # pattern_config produce the same rewrite, prefer the pattern_config
    # entry — its provenance is more specific (a named pattern family
    # rather than an ad-hoc enumerated discovery).
    seen_idx: dict[tuple[str, str], int] = {}
    deduped: list[dict] = []
    for c in verified:
        cl, cr = canonicalize_pair(c["lhs_expr"], c["rhs_expr"])
        key = build_candidate_key(cl, cr)
        if key not in seen_idx:
            seen_idx[key] = len(deduped)
            deduped.append(c)
            continue
        # Already seen: replace if new entry is pattern_config and
        # existing is not.
        existing = deduped[seen_idx[key]]
        if (c.get("source") == "pattern_config"
                and existing.get("source") != "pattern_config"):
            deduped[seen_idx[key]] = c
    _log(f"after dedup: {len(deduped)} rules")

    # Step 6b: Collapse commutative-variant duplicates. Step 6's
    # ``canonicalize_pair`` interleaves alpha-rename with commutative sort,
    # which preserves variants whose rename order happens to differ (e.g.
    # ``(add y (sub 0 x))`` vs ``(add (sub 0 x) y)``). Apply a stronger
    # commute-equivalent key here to emit a single representative per
    # canonical class. Preserves first-seen order (Step 6 already prefers
    # pattern_config over enumerator when both exist).
    before_collapse = len(deduped)
    ckeys: "OrderedDict[tuple[str, str], dict]" = OrderedDict()
    for c in deduped:
        ck = (_commute_key(c["lhs"]), _commute_key(c["rhs"]))
        if ck not in ckeys:
            ckeys[ck] = c
    deduped = list(ckeys.values())
    collapsed = before_collapse - len(deduped)
    _log(f"commute-variant collapse: {len(deduped)} rules "
         f"(collapsed {collapsed} variants)")

    # Step 7: Sort by cost delta
    deduped.sort(
        key=lambda c: (
            c["cost"]["delta"].get("runtime_calls", 0),
            c["cost"]["delta"]["dmir_inst"],
        )
    )

    # Step 8: Assign names and format
    rules_out = []
    for i, c in enumerate(deduped):
        name = auto_name(c["lhs_expr"], c["rhs_expr"], i)
        src = c.get("source", "unknown")
        # Pattern-config pairs are always Z3-verified regardless of --no-z3
        # (see I-1 fix); enumerator candidates only get "smt" when Z3 ran.
        if src == "pattern_config":
            modes = ["smt"]
        else:
            modes = ["smt"] if not args.no_z3 else ["interpreter_sample"]
        rules_out.append(
            {
                "name": name,
                "status": "synthesized",
                "source": src,
                "inputs": sorted(
                    extract_var_names(c["lhs_expr"]) | extract_var_names(c["rhs_expr"])
                ),
                "lhs": c["lhs"],
                "rhs": c["rhs"],
                "cost": c["cost"],
                "validation": {
                    "modes": modes,
                    "coverage": [],
                },
            }
        )

    elapsed = time.time() - t0
    # I-2: split enumerator vs pattern-config populations so that
    # summary.z3_verified no longer conflates them. The enumerator-only
    # Z3 pass is reported as enumerator_z3_verified; pattern_config runs
    # its own always-on Z3 pass and is counted separately.
    enumerator_z3_verified = len(verified) - pattern_accepted
    report = {
        "summary": {
            "term_count": bank.total_added,
            "unique_signatures": len(bank.sig_to_exprs),
            "raw_candidate_count": len(raw),
            "novel_count": len(novel),
            "z3_verified": len(verified),
            "enumerator_z3_verified": enumerator_z3_verified,
            "z3_rejected": len(rejected),
            "pattern_config_accepted": pattern_accepted,
            "pattern_config_new": pattern_new_keys,
            "final_rule_count": len(rules_out),
            "max_depth": args.max_depth,
            "num_vars": args.num_vars,
            "elapsed_seconds": round(elapsed, 2),
        },
        "rules": rules_out,
        "rejected": [
            {"lhs": r["lhs"], "rhs": r["rhs"], "z3_status": r.get("z3_status", "?")}
            for r in rejected
        ],
    }
    return report


def run_synthesis_u256(args) -> dict:
    """u256 synthesis pipeline — parallel to run_synthesis but at 256-bit BV
    width over the evm_u256_* pseudo-op family."""
    t0 = time.time()

    envs = build_sample_envs_256()
    _log(f"u256 sample envs: {len(envs)}")

    _log(f"enumerating u256 expressions (depth={args.max_depth}, "
         f"max_cost={args.max_cost})...")
    bank = enumerate_u256_expressions(
        max_depth=args.max_depth,
        envs=envs,
        max_cost=args.max_cost,
        verbose=True,
    )
    _log(f"u256 bank: {bank.total_added} terms, "
         f"{len(bank.sig_to_exprs)} unique signatures")

    raw = extract_candidates(bank)
    _log(f"raw u256 candidates: {len(raw)}")

    rule_patterns = load_rule_patterns(args.rules) if args.rules else []
    rule_keys = build_rule_key_set(rule_patterns)
    novel = filter_novel(raw, rule_patterns, rule_keys)
    _log(f"novel u256 candidates (not in existing rules): {len(novel)}")

    verified = []
    rejected = []
    if not args.no_z3 and novel:
        _log(f"verifying {len(novel)} u256 candidates at 256-bit BV "
             f"(timeout={args.z3_timeout}ms)...")
        for i, c in enumerate(novel):
            all_vars = sorted(extract_var_names(c["lhs_expr"]) |
                              extract_var_names(c["rhs_expr"]))
            is_valid, status = verify_equivalence_256(
                c["lhs_expr"], c["rhs_expr"], all_vars, [], args.z3_timeout,
            )
            if is_valid:
                verified.append(c)
            else:
                c["z3_status"] = status
                rejected.append(c)
            if (i + 1) % 50 == 0:
                _log(f"  verified {i + 1}/{len(novel)} "
                     f"(valid={len(verified)}, rejected={len(rejected)})")
        _log(f"Z3 done: {len(verified)} valid, {len(rejected)} rejected")
    elif args.no_z3:
        verified = novel
        _log("Z3 skipped (--no-z3)")

    pattern_verified = 0
    pattern_rejected = 0
    if not args.no_z3:
        pattern_candidates = expand_u256_pattern_config()
        _log(f"u256 pattern-config: {len(pattern_candidates)} candidate pairs")
        existing_keys: set[tuple[str, str]] = set()
        for c in verified:
            cl, cr = canonicalize_pair(c["lhs_expr"], c["rhs_expr"])
            existing_keys.add(build_candidate_key(cl, cr))
        for c in pattern_candidates:
            cl, cr = canonicalize_pair(c["lhs_expr"], c["rhs_expr"])
            key = build_candidate_key(cl, cr)
            if key in existing_keys:
                continue
            all_vars = sorted(
                extract_var_names(c["lhs_expr"]) | extract_var_names(c["rhs_expr"])
            )
            is_valid, status = verify_equivalence_256(
                c["lhs_expr"], c["rhs_expr"], all_vars, [], args.z3_timeout,
            )
            if is_valid:
                verified.append(c)
                existing_keys.add(key)
                pattern_verified += 1
            else:
                c["z3_status"] = status
                rejected.append(c)
                pattern_rejected += 1
        _log(
            f"u256 pattern-config: {pattern_verified} valid, "
            f"{pattern_rejected} rejected"
        )

    seen_keys: set[tuple[str, str]] = set()
    deduped = []
    for c in verified:
        cl, cr = canonicalize_pair(c["lhs_expr"], c["rhs_expr"])
        key = build_candidate_key(cl, cr)
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(c)
    _log(f"after dedup: {len(deduped)} u256 rules")

    deduped.sort(
        key=lambda c: (
            c["cost"]["delta"].get("runtime_calls", 0),
            c["cost"]["delta"]["dmir_inst"],
        )
    )

    rules_out = []
    for i, c in enumerate(deduped):
        name = auto_name(c["lhs_expr"], c["rhs_expr"], i, prefix="u256")
        rules_out.append({
            "name": name,
            "status": "synthesized-u256",
            "source": c.get("source", "unknown"),
            "ir_width": 256,
            "inputs": sorted(
                extract_var_names(c["lhs_expr"]) | extract_var_names(c["rhs_expr"])
            ),
            "lhs": c["lhs"],
            "rhs": c["rhs"],
            "cost": c["cost"],
            "validation": {
                "modes": ["smt_256"] if not args.no_z3 else ["sampling_256"],
                "coverage": [],
            },
        })

    elapsed = time.time() - t0
    return {
        "summary": {
            "mode": "u256",
            "term_count": bank.total_added,
            "unique_signatures": len(bank.sig_to_exprs),
            "raw_candidate_count": len(raw),
            "novel_count": len(novel),
            "z3_verified": len(verified),
            "z3_rejected": len(rejected),
            "pattern_config_u256_verified": pattern_verified,
            "pattern_config_u256_rejected": pattern_rejected,
            "final_rule_count": len(rules_out),
            "max_depth": args.max_depth,
            "max_cost": args.max_cost,
            "elapsed_seconds": round(elapsed, 2),
        },
        "rules": rules_out,
        "rejected": [
            {"lhs": r["lhs"], "rhs": r["rhs"], "z3_status": r.get("z3_status", "?")}
            for r in rejected
        ],
    }


def parse_args():
    p = argparse.ArgumentParser(description="Synthesize dMIR rewrite rules")
    p.add_argument("--mode", choices=["u64", "u256"], default="u64",
                   help="Synthesis width. u64 = original pipeline; u256 = "
                        "evm_u256_* pseudo-op enumeration")
    p.add_argument("--max-depth", type=int, default=3)
    p.add_argument("--num-vars", type=int, default=2)
    p.add_argument("--max-cost", type=int, default=6)
    p.add_argument("--rules", type=str, default=None,
                   help="Existing rules JSON to filter against")
    p.add_argument("--out", type=str, default=None,
                   help="Output report path (default: stdout)")
    p.add_argument("--no-z3", action="store_true",
                   help="Skip Z3 verification (sampling only)")
    p.add_argument("--z3-timeout", type=int, default=5000,
                   help="Z3 timeout per query in ms")
    p.add_argument("--include-carry", action="store_true",
                   help="Run carry-chain ADC/SBB synthesis (Phase 3)")
    return p.parse_args()


def main():
    args = parse_args()

    if args.include_carry:
        carry_rules = synthesize_carry_rules(verbose=True)
        report = {"carry_rules": carry_rules}
        output = json.dumps(report, indent=2)
        if args.out:
            pathlib.Path(args.out).write_text(output, encoding="utf-8")
            _log(f"carry report written to {args.out}")
        else:
            print(output)
        return

    if args.mode == "u256":
        report = run_synthesis_u256(args)
    else:
        report = run_synthesis(args)
    output = json.dumps(report, indent=2)
    if args.out:
        pathlib.Path(args.out).write_text(output, encoding="utf-8")
        _log(f"report written to {args.out}")
    else:
        print(output)


if __name__ == "__main__":
    main()
