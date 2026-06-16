#!/usr/bin/env python3
# Copyright (C) 2026 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Generate storage-I/O-heavy, self-verifying statetest benchmark fixtures.

Each contract initializes its storage to a deterministic state at the start of
every invocation, so behaviour is identical across evmone-bench iterations
despite MockedHost persisting state. Each contract computes a value-sensitive
checksum over its storage round-trips and REVERTs on mismatch, so EVMC_SUCCESS
is itself a correctness gate (the JSON bench path does not check output).
Expected checksums are derived from an exact integer simulation.

These are synthetic storage-throughput probes representative of real-load
character (storage-I/O bound), not captured real transactions.
"""
import json
import sys

MASK256 = (1 << 256) - 1

OPC = {
    'STOP': 0x00, 'ADD': 0x01, 'MUL': 0x02, 'SUB': 0x03, 'DIV': 0x04, 'MOD': 0x06,
    'LT': 0x10, 'GT': 0x11, 'EQ': 0x14, 'ISZERO': 0x15, 'AND': 0x16, 'OR': 0x17, 'XOR': 0x18,
    'POP': 0x50, 'MLOAD': 0x51, 'MSTORE': 0x52, 'SLOAD': 0x54, 'SSTORE': 0x55,
    'JUMP': 0x56, 'JUMPI': 0x57, 'JUMPDEST': 0x5b,
    'RETURN': 0xf3, 'REVERT': 0xfd,
}
for _i in range(1, 17):
    OPC[f'DUP{_i}'] = 0x80 + _i - 1
    OPC[f'SWAP{_i}'] = 0x90 + _i - 1


class Asm:
    def __init__(self):
        self.items = []
        self.labelpc = {}
        self._n = 0

    def newlabel(self, base='L'):
        self._n += 1
        return f'{base}{self._n}'

    def op(self, name):
        self.items.append(('op', OPC[name]))
        return self

    def push(self, val):
        val &= MASK256
        if val == 0:
            b = b'\x00'
        else:
            b = val.to_bytes((val.bit_length() + 7) // 8, 'big')
        self.items.append(('push', b))
        return self

    def pushlabel(self, name):
        self.items.append(('pushlabel', name))
        return self

    def label(self, name):
        self.items.append(('label', name))
        return self

    def assemble(self):
        pc = 0
        for it in self.items:
            t = it[0]
            if t == 'op':
                pc += 1
            elif t == 'push':
                pc += 1 + len(it[1])
            elif t == 'pushlabel':
                pc += 3            # PUSH2 + 2 bytes
            elif t == 'label':
                self.labelpc[it[1]] = pc
                pc += 1            # JUMPDEST byte
        out = bytearray()
        for it in self.items:
            t = it[0]
            if t == 'op':
                out.append(it[1])
            elif t == 'push':
                b = it[1]
                out.append(0x60 + len(b) - 1)
                out += b
            elif t == 'pushlabel':
                target = self.labelpc[it[1]]
                if target > 0xffff:
                    raise ValueError(
                        f"label PC {target} exceeds PUSH2 range; "
                        "shrink the contract or extend the assembler to PUSH3")
                out.append(0x61)   # PUSH2
                out += target.to_bytes(2, 'big')
            elif t == 'label':
                out.append(0x5b)
        return bytes(out)


# --- emit helpers ---------------------------------------------------------

def mstore_const(a, off, val):
    a.push(val); a.push(off); a.op('MSTORE')


def mload(a, off):
    a.push(off); a.op('MLOAD')


def counted_loop(a, counter_off, limit, body):
    """for c in 0..limit-1: body() ; c lives in mem[counter_off]."""
    top = a.newlabel('top'); end = a.newlabel('end')
    mstore_const(a, counter_off, 0)
    a.label(top)
    # continue while counter < limit
    a.push(limit); mload(a, counter_off); a.op('LT'); a.op('ISZERO')
    a.pushlabel(end); a.op('JUMPI')
    body()
    mload(a, counter_off); a.push(1); a.op('ADD'); a.push(counter_off); a.op('MSTORE')
    a.pushlabel(top); a.op('JUMP')
    a.label(end)


def verify_tail(a, acc_off, expected):
    good = a.newlabel('good')
    mload(a, acc_off); a.push(expected); a.op('EQ')
    a.pushlabel(good); a.op('JUMPI')
    a.push(0); a.push(0); a.op('REVERT')
    a.label(good); a.op('STOP')


# --- contracts ------------------------------------------------------------

def build_rw_churn():
    N, MASK, T, AMOUNT, SEED_MUL, SEED_ADD = 64, 63, 256, 7, 3, 11
    I, R, A, ACC, B = 0x00, 0x20, 0x40, 0x60, 0x80
    a = Asm()

    # Phase 1: seed slot i = i*SEED_MUL + SEED_ADD
    def seed_body():
        mload(a, I); a.push(SEED_MUL); a.op('MUL'); a.push(SEED_ADD); a.op('ADD')  # value
        mload(a, I); a.op('SSTORE')                                                # key=i
    counted_loop(a, I, N, seed_body)

    # Phase 2: move AMOUNT from slot a -> slot b (conservative; total invariant)
    def churn_body():
        mload(a, R); a.push(MASK); a.op('AND'); a.push(A); a.op('MSTORE')          # a = r & MASK
        mload(a, A); a.op('SLOAD'); a.push(AMOUNT); a.op('SWAP1'); a.op('SUB')     # va - AMOUNT
        mload(a, A); a.op('SSTORE')
        mload(a, A); a.push(1); a.op('ADD'); a.push(MASK); a.op('AND'); a.push(B); a.op('MSTORE')  # b=(a+1)&MASK
        mload(a, B); a.op('SLOAD'); a.push(AMOUNT); a.op('ADD')                    # vb + AMOUNT
        mload(a, B); a.op('SSTORE')
    counted_loop(a, R, T, churn_body)

    # Phase 3: value-sensitive weighted checksum acc = sum_i slot_i*(i+1).
    # A plain conservation sum would cancel symmetric/operand-swap/in-range-slot
    # miscompiles; weighting by position breaks that cancellation.
    mstore_const(a, ACC, 0)

    def sum_body():
        mload(a, I); a.op('SLOAD')                          # slot value
        mload(a, I); a.push(1); a.op('ADD'); a.op('MUL')    # * (i+1)
        mload(a, ACC); a.op('ADD'); a.push(ACC); a.op('MSTORE')
    counted_loop(a, I, N, sum_body)

    M = MASK256
    st = {i: (i * SEED_MUL + SEED_ADD) & M for i in range(N)}
    for r in range(T):
        x = r & MASK
        y = (x + 1) & MASK
        st[x] = (st[x] - AMOUNT) & M
        st[y] = (st[y] + AMOUNT) & M
    expected = 0
    for i in range(N):
        expected = (expected + st[i] * (i + 1)) & M
    verify_tail(a, ACC, expected)
    return a.assemble(), expected, dict(N=N, T=T, AMOUNT=AMOUNT)


def build_sstore_hot():
    N, MASK, T, MUL, ADD = 64, 63, 4096, 5, 1
    assert T % N == 0
    R, SLOT, ACC, I = 0x00, 0x20, 0x40, 0x60
    a = Asm()

    def write_body():
        mload(a, R); a.push(MASK); a.op('AND'); a.push(SLOT); a.op('MSTORE')       # slot = r & MASK
        mload(a, SLOT); a.push(MUL); a.op('MUL'); a.push(ADD); a.op('ADD')         # val = slot*MUL+ADD
        mload(a, SLOT); a.op('SSTORE')
    counted_loop(a, R, T, write_body)

    # value+position-sensitive weighted checksum (kills slot-permutation blind spot)
    mstore_const(a, ACC, 0)

    def sum_body():
        mload(a, I); a.op('SLOAD')
        mload(a, I); a.push(1); a.op('ADD'); a.op('MUL')
        mload(a, ACC); a.op('ADD'); a.push(ACC); a.op('MSTORE')
    counted_loop(a, I, N, sum_body)

    # final slot i holds its last write = i*MUL+ADD (T is a multiple of N)
    expected = sum((i * MUL + ADD) * (i + 1) for i in range(N)) & MASK256
    verify_tail(a, ACC, expected)
    return a.assemble(), expected, dict(N=N, T=T)


def build_sload_hot():
    N, MASK, T, MUL, ADD = 64, 63, 4096, 9, 2
    assert T % N == 0
    I, ACC, R = 0x00, 0x20, 0x40
    a = Asm()

    def seed_body():
        mload(a, I); a.push(MUL); a.op('MUL'); a.push(ADD); a.op('ADD')
        mload(a, I); a.op('SSTORE')
    counted_loop(a, I, N, seed_body)

    mstore_const(a, ACC, 0)

    # weight each read by (slot+1) so a uniform full-pass slot-shift no longer
    # maps to the same accumulated total
    def read_body():
        mload(a, ACC)
        mload(a, R); a.push(MASK); a.op('AND')              # slot
        a.op('DUP1'); a.op('SLOAD')                          # [slot, val]
        a.op('SWAP1'); a.push(1); a.op('ADD'); a.op('MUL')   # val*(slot+1)
        a.op('ADD'); a.push(ACC); a.op('MSTORE')
    counted_loop(a, R, T, read_body)

    per_pass = sum((i * MUL + ADD) * (i + 1) for i in range(N))
    expected = (per_pass * (T // N)) & MASK256
    verify_tail(a, ACC, expected)
    return a.assemble(), expected, dict(N=N, T=T)


def build_amm_swap():
    """Macro contract: constant-product AMM swaps interleaving MUL/DIV math with
    SLOAD/SSTORE on reserves and a trader balance table. Models a realistic DeFi
    compute+storage mix; reserves sized so k=r0*r1 exceeds u64 (u128 math). All
    slots are warm after the Phase 1 reseed, so this times the storage-handler
    path, not inter-transaction cold-slot cost. Checksum is a value-sensitive
    weighted sum, so a miscompiled DIV/MUL/storage op changes it; expected is
    computed by an exact integer simulation."""
    N, MASK, T = 64, 63, 4096
    R0_INIT = R1_INIT = 10 ** 15   # 18-decimal-token scale; k=r0*r1 ~ 1e30 (u128)
    AMT = 10 ** 9
    BAL = 0x80  # storage slot base for trader balances (clear of slots 0,1)
    # memory scratch
    I, ACC, R0M, R1M, KM, NR0, AOUT, TKEY = 0x00, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0, 0xE0
    a = Asm()

    # Phase 1: reseed reserves and trader balances (idempotent across iterations)
    a.push(R0_INIT); a.push(0); a.op('SSTORE')
    a.push(R1_INIT); a.push(1); a.op('SSTORE')

    def seed_body():
        mload(a, I); a.push(7); a.op('MUL'); a.push(3); a.op('ADD')        # bal = i*7+3
        mload(a, I); a.push(BAL); a.op('ADD'); a.op('SSTORE')              # key = BAL+i
    counted_loop(a, I, N, seed_body)

    # Phase 2: T swaps (token0 -> token1), constant product k = r0*r1
    def swap_body():
        a.push(0); a.op('SLOAD'); a.push(R0M); a.op('MSTORE')             # r0
        a.push(1); a.op('SLOAD'); a.push(R1M); a.op('MSTORE')             # r1
        mload(a, R0M); mload(a, R1M); a.op('MUL'); a.push(KM); a.op('MSTORE')   # k = r0*r1
        mload(a, R0M); a.push(AMT); a.op('ADD'); a.push(NR0); a.op('MSTORE')    # newR0 = r0+AMT
        mload(a, NR0); mload(a, KM); a.op('DIV')                          # newR1 = k // newR0
        a.op('DUP1'); a.push(1); a.op('SSTORE')                           # SSTORE(1, newR1)
        mload(a, R1M); a.op('SUB'); a.push(AOUT); a.op('MSTORE')          # amountOut = r1-newR1
        mload(a, NR0); a.push(0); a.op('SSTORE')                          # SSTORE(0, newR0)
        mload(a, I); a.push(MASK); a.op('AND'); a.push(BAL); a.op('ADD')
        a.push(TKEY); a.op('MSTORE')                                      # tkey = BAL+(s&MASK)
        mload(a, TKEY); a.op('SLOAD'); mload(a, AOUT); a.op('ADD')        # bal + amountOut
        mload(a, TKEY); a.op('SSTORE')
    counted_loop(a, I, T, swap_body)

    # Phase 3: value-sensitive weighted checksum
    mstore_const(a, ACC, 0)
    a.push(0); a.op('SLOAD'); a.push(1); a.op('MUL'); mload(a, ACC); a.op('ADD'); a.push(ACC); a.op('MSTORE')
    a.push(1); a.op('SLOAD'); a.push(2); a.op('MUL'); mload(a, ACC); a.op('ADD'); a.push(ACC); a.op('MSTORE')

    def sum_body():
        mload(a, I); a.push(BAL); a.op('ADD'); a.op('SLOAD')             # bal_i
        mload(a, I); a.push(3); a.op('ADD'); a.op('MUL')                 # * (i+3)
        mload(a, ACC); a.op('ADD'); a.push(ACC); a.op('MSTORE')
    counted_loop(a, I, N, sum_body)

    # exact integer simulation -> expected checksum
    M = MASK256
    st = {0: R0_INIT, 1: R1_INIT}
    for i in range(N):
        st[BAL + i] = (i * 7 + 3) & M
    for s in range(T):
        r0, r1 = st[0], st[1]
        k = (r0 * r1) & M
        newR0 = (r0 + AMT) & M
        newR1 = (k // newR0) if newR0 else 0
        amountOut = (r1 - newR1) & M
        st[1] = newR1
        st[0] = newR0
        tk = BAL + (s & MASK)
        st[tk] = (st[tk] + amountOut) & M
    acc = (st[0] * 1) & M
    acc = (acc + st[1] * 2) & M
    for i in range(N):
        acc = (acc + st[BAL + i] * (i + 3)) & M
    verify_tail(a, ACC, acc)
    return a.assemble(), acc, dict(N=N, T=T, AMT=AMT, R_init=R0_INIT)


# --- statetest JSON wrapper (mirrors narrow_compare_u64.json schema) ------

CONTRACT_ADDR = "0xbe7c43a580000000000000000000000000000001"
SENDER_ADDR = "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"


def wrap(name, code_hex, label, comment):
    return {
        name: {
            "_info": {
                "comment": comment,
                "labels": {"0": label},
                "source": "generated by tools/gen_realistic_benchmarks.py (real-load rebalance)",
            },
            "env": {
                "currentBaseFee": "0x01",
                "currentCoinbase": SENDER_ADDR,
                "currentDifficulty": "0x01",
                "currentGasLimit": "0x3b9aca00",
                "currentNumber": "0x01",
                "currentRandom": "0x0000000000000000000000000000000000000000000000000000000000000001",
                "currentTimestamp": "0x61a8d289",
                "previousHash": "0x5e20a0453cecd065ea59c37ac63e079ee08998b6045136a8ce6635c7912ec0b6",
            },
            "post": {
                "London": [{
                    "hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "indexes": {"data": 0, "gas": 0, "value": 0},
                    "logs": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                    "txbytes": "0x",
                }]
            },
            "pre": {
                SENDER_ADDR: {"balance": "0x3b9aca00", "code": "0x", "nonce": "0x00", "storage": {}},
                CONTRACT_ADDR: {"balance": "0x00", "code": "0x" + code_hex, "nonce": "0x00", "storage": {}},
            },
            "transaction": {
                "data": ["0x"],
                "gasLimit": ["0x3b9aca00"],
                "gasPrice": "0x01",
                "nonce": "0x00",
                "secretKey": "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8",
                "to": CONTRACT_ADDR,
                "value": ["0x00"],
            },
        }
    }


# (name, label, builder, subdir, comment) -- subdir is the evmone benchmarks
# category dir, which becomes the external/total/<subdir>/ name prefix.
SPECS = [
    ("defi_amm_swap", "swap", build_amm_swap, "main",
     "Macro: 4096 constant-product AMM swaps interleaving u128 MUL/DIV math with "
     "reserve and trader-balance SLOAD/SSTORE. Representative DeFi compute+storage "
     "mix (warm-only); value-sensitive weighted checksum; self-verifying via REVERT."),
    ("storage_rw_churn", "churn", build_rw_churn, "micro",
     "Adjacent-slot read-modify-write throughput probe: reseed 64 slots then run "
     "conservative transfers between adjacent slots. Sequential warm access; "
     "value-sensitive weighted checksum; self-verifying via REVERT."),
    ("sstore_hot", "store", build_sstore_hot, "micro",
     "Synthetic SSTORE-handler throughput probe: 4096 deterministic SSTOREs across "
     "64 slots; value+position-sensitive weighted checksum; self-verifying via REVERT."),
    ("sload_hot", "load", build_sload_hot, "micro",
     "Synthetic SLOAD-handler throughput probe: seed 64 slots then 4096 weighted "
     "SLOAD accumulations; value+position-sensitive checksum; self-verifying via REVERT."),
]


def selftest():
    """Guard against generator regressions: every spec must build deterministically
    and embed a REVERT self-check. Run: gen_realistic_benchmarks.py --selftest"""
    for name, label, builder, subdir, comment in SPECS:
        c1, e1, _ = builder()
        c2, e2, _ = builder()
        assert c1 == c2, f"{name}: non-deterministic bytecode"
        assert e1 == e2, f"{name}: non-deterministic expected checksum"
        assert 0xfd in c1, f"{name}: missing REVERT self-check opcode"
        assert 0x00 == c1[-1], f"{name}: success path must end in STOP"
    print(f"selftest OK: {len(SPECS)} specs deterministic and self-checking")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--selftest':
        selftest()
        return
    base = sys.argv[1] if len(sys.argv) > 1 else '.'
    for name, label, builder, subdir, comment in SPECS:
        code, expected, params = builder()
        comment_full = f"{comment} expected_checksum={expected} params={params}"
        doc = wrap(name, code.hex(), label, comment_full)
        path = f"{base}/{subdir}/{name}.json"
        with open(path, 'w') as f:
            json.dump(doc, f, indent=4)
            f.write('\n')
        print(f"{subdir}/{name}: {len(code)} bytes  expected={expected}  params={params}")
        print(f"  code=0x{code.hex()}")
        print(f"  wrote {path}")


if __name__ == '__main__':
    main()
