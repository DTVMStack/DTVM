// Copyright (C) 2026 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// A new, explicitly non-paper C-to-Wasm case: 8-level MiMC proof validation.
#include <stddef.h>
#include <stdint.h>

#define IMPORT(name) __attribute__((import_module("env"), import_name(name)))
IMPORT("getCallDataSize") int32_t calldata_size(void);
IMPORT("callDataCopy") void calldata_copy(uint32_t, uint32_t, uint32_t);
IMPORT("keccak256") void keccak256(uint32_t, uint32_t, uint32_t);
IMPORT("addmod") void addmod(uint32_t, uint32_t, uint32_t, uint32_t);
IMPORT("mulmod") void mulmod(uint32_t, uint32_t, uint32_t, uint32_t);
IMPORT("finish") void finish(uint32_t, uint32_t);
IMPORT("revert") void revert(uint32_t, uint32_t);
#define ADDR(p) ((uint32_t)(uintptr_t)(p))
typedef struct {
  uint8_t bytes[32];
} word;
// The SDK's addmod and mulmod host ABI uses big-endian uint256s.
static const word prime = {{0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
                            0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
                            0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
                            0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01}};
static word small(uint8_t x) {
  word w = {{0}};
  w.bytes[31] = x;
  return w;
}
static word add(word a, word b) {
  word out;
  addmod(ADDR(&a), ADDR(&b), ADDR(&prime), ADDR(&out));
  return out;
}
static word mul(word a, word b) {
  word out;
  mulmod(ADDR(&a), ADDR(&b), ADDR(&prime), ADDR(&out));
  return out;
}
static word hash(word left, word right) {
  word x = left, c = small(0);
  for (unsigned i = 0; i < 91; ++i) {
    word t = add(add(x, c), right), t2 = mul(t, t), t4 = mul(t2, t2);
    x = mul(mul(t4, t2), t);
    uint8_t packed[32] = {0}, digest[32];
    packed[31] = (uint8_t)i;
    keccak256(ADDR(packed), 32, ADDR(digest));
    word k;
    for (unsigned j = 0; j < 32; ++j)
      k.bytes[j] = digest[j];
    c = add(c, k);
  }
  return add(x, right);
}
static int equal(word a, word b) {
  uint8_t x = 0;
  for (unsigned i = 0; i < 32; ++i)
    x |= a.bytes[i] ^ b.bytes[i];
  return x == 0;
}
__attribute__((export_name("call"))) void call(void) {
  uint8_t data[5] = {0};
  if (calldata_size() < 4) {
    revert(0, 0);
    __builtin_unreachable();
  }
  calldata_copy(ADDR(data), 0, calldata_size() >= 5 ? 5 : 4);
  if (data[0] != 0x89 || data[1] != 0x03 || data[2] != 0xc5 ||
      data[3] != 0xa2) {
    revert(0, 0);
    __builtin_unreachable();
  }
  word proof[8], root = small(42), computed = small(42);
  for (unsigned i = 0; i < 8; ++i) {
    proof[i] = small((uint8_t)(i * 7 + 13));
    root = (i % 2) ? hash(proof[i], root) : hash(root, proof[i]);
  }
  if (data[4])
    proof[3].bytes[31] ^= 1; // negative vector
  for (unsigned i = 0; i < 8; ++i)
    computed = (i % 2) ? hash(proof[i], computed) : hash(computed, proof[i]);
  uint8_t result[32] = {0};
  result[31] = (uint8_t)equal(root, computed);
  finish(ADDR(result), 32);
  __builtin_unreachable();
}
