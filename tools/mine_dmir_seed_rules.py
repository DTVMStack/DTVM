#!/usr/bin/env python3

import argparse
import json
import pathlib
import random
from dataclasses import dataclass


MASK64 = (1 << 64) - 1
COMMUTATIVE_OPS = {"add", "and", "mul", "or", "xor"}
DEFAULT_SEARCH_CONFIG = {
    "base_terms": [
        "x",
        "y",
        "cond",
        "0:i64",
        "1:i64",
        "18446744073709551615:i64",
    ],
    "unary_not_terms": ["x", "y", "cond"],
    "double_not_terms": ["x", "y", "cond"],
    "binary_fixed_rhs": [
        {
            "ops": ["add", "sub", "and", "or", "xor", "shl", "sshr", "ushr"],
            "lhs": ["x", "y", "cond"],
            "rhs": "0:i64",
        },
        {
            "ops": ["and", "or", "xor"],
            "lhs": ["x", "y", "cond", "(not x)", "(not y)"],
            "rhs": "18446744073709551615:i64",
        },
    ],
    "binary_self": [
        {
            "ops": ["and", "or", "xor"],
            "terms": ["x", "y", "cond"],
        }
    ],
    "select_same_arm": {
        "conditions": ["cond", "x", "0:i64", "1:i64"],
        "values": ["x", "y", "(not x)"],
    },
    "pair_binary_groups": [
        {
            "ops": ["add", "sub", "and", "or", "xor"],
            "lhs": ["x", "y"],
            "rhs": ["x", "y", "0:i64"],
        },
        {
            "ops": ["and", "or", "xor"],
            "lhs": [
                "x",
                "y",
                "(and x y)",
                "(or x y)",
                "(xor x y)",
                "(not x)",
                "(not y)",
            ],
            "rhs": [
                "x",
                "y",
                "0:i64",
                "(and x y)",
                "(or x y)",
                "(xor x y)",
                "(not x)",
                "(not y)",
            ],
        },
    ],
    "adc_sbb_zero": {
        "ops": ["adc", "sbb"],
        "lhs": ["x", "y"],
        "rhs": ["x", "y", "0:i64"],
        "carry": "0:i64",
    },
}


@dataclass(frozen=True)
class Expr:
    op: str
    args: tuple["Expr", ...] = ()
    value: str | int | None = None

    def render(self) -> str:
        if self.op == "var":
            return str(self.value)
        if self.op == "const":
            return f"{self.value}:i64"
        rendered_args = " ".join(arg.render() for arg in self.args)
        return f"({self.op} {rendered_args})"


def var(name: str) -> Expr:
    return Expr("var", value=name)


def const(value: int) -> Expr:
    return Expr("const", value=value)


def unary(op: str, arg: Expr) -> Expr:
    return Expr(op, args=(arg,))


def binary(op: str, lhs: Expr, rhs: Expr) -> Expr:
    return Expr(op, args=(lhs, rhs))


def ternary(op: str, first: Expr, second: Expr, third: Expr) -> Expr:
    return Expr(op, args=(first, second, third))


def wrap_u64(value: int) -> int:
    return value & MASK64


def parse_expr(text: str) -> Expr:
    tokens = text.replace("(", " ( ").replace(")", " ) ").split()
    index = 0

    def parse() -> Expr:
        nonlocal index
        token = tokens[index]
        index += 1
        if token == "(":
            op = tokens[index]
            index += 1
            args = []
            while tokens[index] != ")":
                args.append(parse())
            index += 1
            return Expr(op, args=tuple(args))
        if token.endswith(":i64"):
            return const(int(token[:-4], 10))
        return var(token)

    expr = parse()
    if index != len(tokens):
        raise ValueError(f"unexpected trailing tokens in expression '{text}'")
    return expr


def canonical_var_name(index: int) -> str:
    base_names = ("x", "y", "z")
    if index < len(base_names):
        return base_names[index]
    return f"v{index}"


def canonicalize_expr(expr: Expr, env: dict[str, str] | None = None) -> Expr:
    if env is None:
        env = {}
    if expr.op == "var":
        name = str(expr.value)
        if name not in env:
            env[name] = canonical_var_name(len(env))
        return var(env[name])
    if expr.op == "const":
        return expr

    args = tuple(canonicalize_expr(arg, env) for arg in expr.args)
    if expr.op in COMMUTATIVE_OPS:
        args = tuple(sorted(args, key=lambda arg: (arg.op == "const", arg.render())))
    return Expr(expr.op, args=args)


def canonicalize_pair(lhs: Expr, rhs: Expr) -> tuple[Expr, Expr]:
    env: dict[str, str] = {}
    return canonicalize_expr(lhs, env), canonicalize_expr(rhs, env)


def build_candidate_key(lhs: Expr, rhs: Expr) -> tuple[str, str]:
    canonical_lhs, canonical_rhs = canonicalize_pair(lhs, rhs)
    return canonical_lhs.render(), canonical_rhs.render()


def substitute_expr(expr: Expr, bindings: dict[str, Expr]) -> Expr:
    if expr.op == "var":
        return bindings.get(str(expr.value), expr)
    if expr.op == "const":
        return expr
    return Expr(
        expr.op, args=tuple(substitute_expr(arg, bindings) for arg in expr.args)
    )


def match_pattern(pattern: Expr, expr: Expr, bindings: dict[str, Expr]) -> bool:
    if pattern.op == "var":
        name = str(pattern.value)
        bound = bindings.get(name)
        if bound is None:
            bindings[name] = expr
            return True
        return bound == expr
    if pattern.op == "const":
        return pattern == expr
    if pattern.op != expr.op or len(pattern.args) != len(expr.args):
        return False
    return all(
        match_pattern(pattern_arg, expr_arg, bindings)
        for pattern_arg, expr_arg in zip(pattern.args, expr.args)
    )


def is_rule_instance(rule_lhs: Expr, rule_rhs: Expr,
                     candidate_lhs: Expr, candidate_rhs: Expr) -> bool:
    bindings: dict[str, Expr] = {}
    if not match_pattern(rule_lhs, candidate_lhs, bindings):
        return False
    substituted_rhs = substitute_expr(rule_rhs, bindings)
    return substituted_rhs == candidate_rhs


def eval_expr(expr: Expr, env: dict[str, int]) -> int:
    if expr.op == "var":
        return env[str(expr.value)]
    if expr.op == "const":
        return int(expr.value)
    if expr.op == "not":
        return wrap_u64(~eval_expr(expr.args[0], env))
    if expr.op == "add":
        return wrap_u64(eval_expr(expr.args[0], env) + eval_expr(expr.args[1], env))
    if expr.op == "sub":
        return wrap_u64(eval_expr(expr.args[0], env) - eval_expr(expr.args[1], env))
    if expr.op == "mul":
        return wrap_u64(eval_expr(expr.args[0], env) * eval_expr(expr.args[1], env))
    if expr.op == "and":
        return wrap_u64(eval_expr(expr.args[0], env) & eval_expr(expr.args[1], env))
    if expr.op == "or":
        return wrap_u64(eval_expr(expr.args[0], env) | eval_expr(expr.args[1], env))
    if expr.op == "xor":
        return wrap_u64(eval_expr(expr.args[0], env) ^ eval_expr(expr.args[1], env))
    if expr.op == "adc":
        return wrap_u64(
            eval_expr(expr.args[0], env)
            + eval_expr(expr.args[1], env)
            + eval_expr(expr.args[2], env)
        )
    if expr.op == "sbb":
        return wrap_u64(
            eval_expr(expr.args[0], env)
            - eval_expr(expr.args[1], env)
            - eval_expr(expr.args[2], env)
        )
    if expr.op == "select":
        return (
            eval_expr(expr.args[1], env)
            if eval_expr(expr.args[0], env) != 0
            else eval_expr(expr.args[2], env)
        )
    if expr.op == "shl":
        amount = eval_expr(expr.args[1], env)
        if amount >= 64:
            return 0
        return wrap_u64(eval_expr(expr.args[0], env) << amount)
    if expr.op == "sshr":
        amount = eval_expr(expr.args[1], env)
        value = eval_expr(expr.args[0], env)
        if amount >= 64:
            return MASK64 if value & (1 << 63) else 0
        if value & (1 << 63):
            value -= 1 << 64
        return wrap_u64(value >> amount)
    if expr.op == "ushr":
        amount = eval_expr(expr.args[1], env)
        if amount >= 64:
            return 0
        return eval_expr(expr.args[0], env) >> amount
    raise ValueError(f"unsupported op {expr.op}")


def expr_cost(expr: Expr) -> dict[str, int]:
    if expr.op in {"var", "const"}:
        return {
            "dmir_inst": 0,
            "select_depth": 0,
            "adc_chain": 0,
            "runtime_calls": 0,
        }

    child_costs = [expr_cost(arg) for arg in expr.args]
    return {
        "dmir_inst": 1 + sum(cost["dmir_inst"] for cost in child_costs),
        "select_depth": (
            1 + max(cost["select_depth"] for cost in child_costs)
            if expr.op == "select"
            else max(cost["select_depth"] for cost in child_costs)
        ),
        "adc_chain": (
            1 + sum(cost["adc_chain"] for cost in child_costs)
            if expr.op in {"adc", "sbb"}
            else sum(cost["adc_chain"] for cost in child_costs)
        ),
        "runtime_calls": sum(cost["runtime_calls"] for cost in child_costs),
    }


def dominates(rhs_cost: dict[str, int], lhs_cost: dict[str, int]) -> bool:
    fields = ("dmir_inst", "select_depth", "adc_chain", "runtime_calls")
    return all(rhs_cost[field] <= lhs_cost[field] for field in fields) and any(
        rhs_cost[field] < lhs_cost[field] for field in fields
    )


def cost_delta(lhs_cost: dict[str, int], rhs_cost: dict[str, int]) -> dict[str, int]:
    return {
        field: rhs_cost[field] - lhs_cost[field]
        for field in ("dmir_inst", "select_depth", "adc_chain", "runtime_calls")
    }


def build_sample_envs() -> list[dict[str, int]]:
    boundary_values = [
        0,
        1,
        2,
        3,
        7,
        8,
        15,
        16,
        0x7FFFFFFFFFFFFFFF,
        0x8000000000000000,
        0xFFFFFFFFFFFFFFFF,
    ]
    envs = []
    for x in boundary_values:
        # Use the full boundary set for y so shift-sensitive expressions
        # (e.g. shl/ushr with large shift amounts) are covered.
        for y in boundary_values:
            for cond in (0, 1, x, y, x ^ y):
                envs.append({"x": x, "y": y, "cond": wrap_u64(cond)})

    rng = random.Random(0x7D6B4A1C)
    for _ in range(64):
        envs.append(
            {
                "x": rng.getrandbits(64),
                "y": rng.getrandbits(64),
                "cond": rng.getrandbits(64),
            }
        )
    return envs


def load_search_config(path: str | None) -> dict:
    if path is None:
        return DEFAULT_SEARCH_CONFIG
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def build_term_map(config: dict) -> dict[str, Expr]:
    term_specs = set(config.get("base_terms", []))
    term_specs.update(config.get("unary_not_terms", []))
    term_specs.update(config.get("double_not_terms", []))
    for entry in config.get("binary_fixed_rhs", []):
        term_specs.update(entry.get("lhs", []))
        term_specs.add(entry.get("rhs"))
    for entry in config.get("binary_self", []):
        term_specs.update(entry.get("terms", []))
    select_same_arm = config.get("select_same_arm", {})
    term_specs.update(select_same_arm.get("conditions", []))
    term_specs.update(select_same_arm.get("values", []))
    pair_binary_groups = list(config.get("pair_binary_groups", []))
    if not pair_binary_groups and "pair_binary" in config:
        pair_binary_groups.append(config["pair_binary"])
    for entry in pair_binary_groups:
        term_specs.update(entry.get("lhs", []))
        term_specs.update(entry.get("rhs", []))
    adc_sbb_zero = config.get("adc_sbb_zero", {})
    term_specs.update(adc_sbb_zero.get("lhs", []))
    term_specs.update(adc_sbb_zero.get("rhs", []))
    if adc_sbb_zero.get("carry"):
        term_specs.add(adc_sbb_zero["carry"])

    return {spec: parse_expr(spec) for spec in term_specs}


def build_search_space(config: dict) -> list[Expr]:
    term_map = build_term_map(config)
    base_terms = [term_map[spec] for spec in config.get("base_terms", [])]

    terms = set(base_terms)

    for spec in config.get("unary_not_terms", []):
        terms.add(unary("not", term_map[spec]))

    for spec in config.get("double_not_terms", []):
        terms.add(unary("not", unary("not", term_map[spec])))

    for entry in config.get("binary_fixed_rhs", []):
        rhs = term_map[entry["rhs"]]
        for op in entry.get("ops", []):
            for lhs_spec in entry.get("lhs", []):
                terms.add(binary(op, term_map[lhs_spec], rhs))

    for entry in config.get("binary_self", []):
        for op in entry.get("ops", []):
            for spec in entry.get("terms", []):
                value = term_map[spec]
                terms.add(binary(op, value, value))

    select_same_arm = config.get("select_same_arm", {})
    for cond_spec in select_same_arm.get("conditions", []):
        for value_spec in select_same_arm.get("values", []):
            value = term_map[value_spec]
            terms.add(ternary("select", term_map[cond_spec], value, value))

    pair_binary_groups = list(config.get("pair_binary_groups", []))
    if not pair_binary_groups and "pair_binary" in config:
        pair_binary_groups.append(config["pair_binary"])
    for entry in pair_binary_groups:
        for op in entry.get("ops", []):
            for lhs_spec in entry.get("lhs", []):
                for rhs_spec in entry.get("rhs", []):
                    terms.add(binary(op, term_map[lhs_spec], term_map[rhs_spec]))

    adc_sbb_zero = config.get("adc_sbb_zero", {})
    carry = term_map[adc_sbb_zero.get("carry", "0:i64")]
    for op in adc_sbb_zero.get("ops", []):
        for lhs_spec in adc_sbb_zero.get("lhs", []):
            for rhs_spec in adc_sbb_zero.get("rhs", []):
                terms.add(ternary(op, term_map[lhs_spec], term_map[rhs_spec], carry))

    return sorted(terms, key=lambda expr: expr.render())

def load_rule_patterns(rules_path: str | None) -> list[tuple[Expr, Expr]]:
    if rules_path is None:
        return []
    data = json.loads(pathlib.Path(rules_path).read_text(encoding="utf-8"))
    return [
        (parse_expr(rule["lhs"]), parse_expr(rule["rhs"]))
        for rule in data.get("rules", [])
    ]


def build_rule_key_set(rule_patterns: list[tuple[Expr, Expr]]) -> set[tuple[str, str]]:
    return {build_candidate_key(lhs, rhs) for lhs, rhs in rule_patterns}


def is_candidate_covered(lhs: Expr, rhs: Expr,
                         rule_patterns: list[tuple[Expr, Expr]],
                         rule_keys: set[tuple[str, str]]) -> bool:
    if build_candidate_key(lhs, rhs) in rule_keys:
        return True
    canonical_lhs, canonical_rhs = canonicalize_pair(lhs, rhs)
    return any(
        is_rule_instance(
            *canonicalize_pair(rule_lhs, rule_rhs),
            canonical_lhs,
            canonical_rhs,
        )
        for rule_lhs, rule_rhs in rule_patterns
    )


def serialize_candidate(lhs: Expr, rhs: Expr, cost: dict[str, dict[str, int]],
                        variants: list[tuple[str, str]] | None = None,
                        covered: bool | None = None) -> dict:
    entry = {
        "lhs": lhs.render(),
        "rhs": rhs.render(),
        "cost": cost,
    }
    if variants is not None:
        entry["variant_count"] = len(variants)
        entry["variants"] = [{"lhs": variant[0], "rhs": variant[1]} for variant in variants]
    if covered is not None:
        entry["covered_by_rule_repo"] = covered
    return entry


def build_candidates(rules_path: str | None = None,
                     config_path: str | None = None) -> dict:
    envs = build_sample_envs()
    search_config = load_search_config(config_path)
    terms = build_search_space(search_config)
    classes: dict[tuple[int, ...], list[Expr]] = {}
    for expr in terms:
        signature = tuple(eval_expr(expr, env) for env in envs)
        classes.setdefault(signature, []).append(expr)

    raw_candidates = []
    for exprs in classes.values():
        exprs = sorted(
            exprs,
            key=lambda expr: (
                expr_cost(expr)["dmir_inst"],
                expr_cost(expr)["select_depth"],
                expr_cost(expr)["adc_chain"],
                expr_cost(expr)["runtime_calls"],
                expr.render(),
            ),
        )
        best = exprs[0]
        best_cost = expr_cost(best)
        for expr in exprs[1:]:
            expr_cost_value = expr_cost(expr)
            if not dominates(best_cost, expr_cost_value):
                continue
            raw_candidates.append(
                {
                    "lhs_expr": expr,
                    "rhs_expr": best,
                    "cost": {
                        "lhs": expr_cost_value,
                        "rhs": best_cost,
                        "delta": cost_delta(expr_cost_value, best_cost),
                    },
                }
            )

    raw_candidates.sort(
        key=lambda item: (item["lhs_expr"].render(), item["rhs_expr"].render())
    )

    curated: dict[tuple[str, str], dict[str, object]] = {}
    for candidate in raw_candidates:
        lhs_expr = candidate["lhs_expr"]
        rhs_expr = candidate["rhs_expr"]
        key = build_candidate_key(lhs_expr, rhs_expr)
        variant = (lhs_expr.render(), rhs_expr.render())
        entry = curated.setdefault(
            key,
            {
                "lhs_expr": parse_expr(key[0]),
                "rhs_expr": parse_expr(key[1]),
                "cost": candidate["cost"],
                "variants": [],
            },
        )
        entry["variants"].append(variant)

    rule_patterns = load_rule_patterns(rules_path)
    rule_keys = build_rule_key_set(rule_patterns)
    curated_candidates = []
    novel_candidates = []
    covered_candidates = []
    for key, entry in sorted(curated.items()):
        covered = is_candidate_covered(
            entry["lhs_expr"], entry["rhs_expr"], rule_patterns, rule_keys
        )
        serialized = serialize_candidate(
            entry["lhs_expr"],
            entry["rhs_expr"],
            entry["cost"],
            variants=sorted(set(entry["variants"])),
            covered=covered,
        )
        curated_candidates.append(serialized)
        if covered:
            covered_candidates.append(serialized)
        else:
            novel_candidates.append(serialized)

    novel_candidates.sort(
        key=lambda item: (
            item["cost"]["delta"]["runtime_calls"],
            item["cost"]["delta"]["dmir_inst"],
            item["cost"]["delta"]["select_depth"],
            item["cost"]["delta"]["adc_chain"],
            item["lhs"],
            item["rhs"],
        )
    )

    return {
        "summary": {
            "term_count": len(terms),
            "sample_count": len(envs),
            "candidate_count": len(raw_candidates),
            "curated_candidate_count": len(curated_candidates),
            "covered_candidate_count": len(covered_candidates),
            "novel_candidate_count": len(novel_candidates),
            "config_supplied": config_path is not None,
        },
        "candidates": [
            serialize_candidate(
                candidate["lhs_expr"], candidate["rhs_expr"], candidate["cost"]
            )
            for candidate in raw_candidates
        ],
        "curated_candidates": curated_candidates,
        "covered_candidates": covered_candidates,
        "novel_candidates": novel_candidates,
    }


def parse_args():
    parser = argparse.ArgumentParser(
        description="Bootstrap offline dMIR rewrite mining with a seed search space."
    )
    parser.add_argument(
        "--out",
        help="Optional output path. Defaults to stdout when omitted.",
    )
    parser.add_argument(
        "--rules",
        help="Optional rule file used to mark already-covered candidates.",
    )
    parser.add_argument(
        "--config",
        help="Optional search-space config file.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    result = build_candidates(args.rules, args.config)
    output = json.dumps(result, indent=2) + "\n"
    if args.out:
        pathlib.Path(args.out).write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
