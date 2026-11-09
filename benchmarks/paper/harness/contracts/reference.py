#!/usr/bin/env python3
"""Independent Python model of the archived Solidity sources (PyCryptodome)."""
from Crypto.Hash import keccak

P = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def k256(data):
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def constant(i):
    return int.from_bytes(k256(i.to_bytes(32, 'big')), 'big')


C = [constant(i) for i in range(91)]


def merkle_hash(left, right):
    x, c = left, 0
    for i in range(91):
        t = (x + c + right) % P
        x = pow(t, 7, P)
        c = (c + C[i]) % P
    return (x + right) % P


def archived_merkle():
    proof = [i * 7 + 13 for i in range(8)]
    root = 42
    for sibling in proof:
        root = merkle_hash(root, sibling)
    computed = 42
    for i, sibling in enumerate(proof):
        computed = merkle_hash(computed, sibling) if i % 2 == 0 else merkle_hash(sibling, computed)
    return int(computed == root), root, computed


def nft(token_id):
    def sponge(x, key):
        for c in C:
            x = pow((x + c + key) % P, 7, P)
        return (x + key) % P
    state = token_id
    for layer in range(8):
        state = sponge(state, layer + 1)
        state = (state + sponge(state, layer + 100)) % P
    return state


if __name__ == '__main__':
    value, root, computed = archived_merkle()
    print('merkle', value, 'root', f'{root:064x}', 'computed', f'{computed:064x}')
    for x in (0, 1, 2):
        print('nft', x, f'{nft(x):064x}')
