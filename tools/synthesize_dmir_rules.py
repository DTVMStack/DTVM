#!/usr/bin/env python3
"""Automated dMIR rewrite rule synthesis via enumeration + Z3 verification."""

import argparse
import json
import pathlib
import sys
import time

import z3

from mine_dmir_seed_rules import (
    COMMUTATIVE_OPS,
    MASK64,
    Expr,
    binary,
    build_candidate_key,
    build_rule_key_set,
    build_sample_envs,
    canonicalize_pair,
    const,
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
# Expression enumeration
# ---------------------------------------------------------------------------

BINARY_OPS = ["add", "sub", "mul", "and", "or", "xor"]
SHIFT_OPS = ["shl", "ushr", "sshr"]
SHIFT_AMOUNTS = [1, 2, 3, 4, 8, 16, 32, 63]
CONSTANTS = [0, 1, MASK64]
VAR_NAMES_2 = ["x", "y"]


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


def auto_name(lhs: Expr, rhs: Expr, index: int) -> str:
    ops = set()

    def collect(e: Expr):
        if e.op not in ("var", "const"):
            ops.add(e.op)
        for a in e.args:
            collect(a)

    collect(lhs)
    collect(rhs)
    tag = "-".join(sorted(ops)[:3]) if ops else "identity"
    return f"synth-{tag}-{index:03d}"


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

    # Step 6: Deduplicate by canonical key
    seen_keys: set[tuple[str, str]] = set()
    deduped = []
    for c in verified:
        cl, cr = canonicalize_pair(c["lhs_expr"], c["rhs_expr"])
        key = build_candidate_key(cl, cr)
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(c)
    _log(f"after dedup: {len(deduped)} rules")

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
        rules_out.append(
            {
                "name": name,
                "status": "synthesized",
                "inputs": sorted(
                    extract_var_names(c["lhs_expr"]) | extract_var_names(c["rhs_expr"])
                ),
                "lhs": c["lhs"],
                "rhs": c["rhs"],
                "cost": c["cost"],
                "validation": {
                    "modes": ["smt"] if not args.no_z3 else ["interpreter_sample"],
                    "coverage": [],
                },
            }
        )

    elapsed = time.time() - t0
    report = {
        "summary": {
            "term_count": bank.total_added,
            "unique_signatures": len(bank.sig_to_exprs),
            "raw_candidate_count": len(raw),
            "novel_count": len(novel),
            "z3_verified": len(verified),
            "z3_rejected": len(rejected),
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


def parse_args():
    p = argparse.ArgumentParser(description="Synthesize dMIR rewrite rules")
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

    report = run_synthesis(args)
    output = json.dumps(report, indent=2)
    if args.out:
        pathlib.Path(args.out).write_text(output, encoding="utf-8")
        _log(f"report written to {args.out}")
    else:
        print(output)


if __name__ == "__main__":
    main()
