// Copyright (C) 2026 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// Research harness: the same native ABI operations back both engines.
#include "host/evm/keccak/keccak.h"
#include "runtime/module.h"
#include "runtime/runtime.h"
#include "zetaengine-c.h"
#include <algorithm>
#include <array>
#include <boost/multiprecision/cpp_int.hpp>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>
#include <wasmtime.h>

using boost::multiprecision::uint512_t;
struct Host {
  std::vector<uint8_t> input, code, output;
  std::array<uint64_t, 10> calls{};
  uint64_t crypto_trace = 14695981039346656037ULL;
  bool finished = false, reverted = false, fault = false, trace_enabled = false;
};
static void trace(Host &h, const uint8_t *p, size_t n) {
  if (!h.trace_enabled)
    return;
  for (size_t i = 0; i < n; ++i) {
    h.crypto_trace ^= p[i];
    h.crypto_trace *= 1099511628211ULL;
  }
}
enum Op {
  Size,
  Copy,
  Value,
  Revert,
  Finish,
  CodeSize,
  CodeCopy,
  Keccak,
  Addmod,
  Mulmod
};
struct Mem {
  uint8_t *data;
  size_t size;
  uint8_t *at(uint32_t p, uint32_t n) const {
    if (p > size || n > size - p)
      throw std::runtime_error("host memory out of bounds");
    return data + p;
  }
};
static uint512_t read_be(const uint8_t *p) {
  uint512_t x = 0;
  for (int i = 0; i < 32; ++i) {
    x <<= 8;
    x |= p[i];
  }
  return x;
}
static void write_be(uint8_t *p, uint512_t x) {
  for (int i = 31; i >= 0; --i) {
    p[i] = static_cast<uint8_t>(x & 255);
    x >>= 8;
  }
}
static uint32_t host_call(Host &h, Mem m, Op op, const uint32_t *a) {
  ++h.calls[op];
  switch (op) {
  case Size:
    return h.input.size();
  case CodeSize:
    return h.code.size();
  case Copy:
  case CodeCopy: {
    auto &src = op == Copy ? h.input : h.code;
    auto *dst = m.at(a[0], a[2]);
    size_t available = a[1] < src.size() ? src.size() - a[1] : 0;
    size_t n = std::min<size_t>(a[2], available);
    if (n)
      std::memcpy(dst, src.data() + a[1], n);
    std::memset(dst + n, 0, a[2] - n);
    return 0;
  }
  case Value:
    std::memset(m.at(a[0], 32), 0, 32);
    return 0;
  case Finish:
  case Revert: {
    auto *p = m.at(a[0], a[1]);
    h.output.assign(p, p + a[1]);
    h.finished = op == Finish;
    h.reverted = op == Revert;
    return 0;
  }
  case Keccak: {
    auto *src = m.at(a[0], a[1]);
    auto *dst = m.at(a[2], 32);
    uint8_t tag = op;
    trace(h, &tag, 1);
    trace(h, src, a[1]);
    auto hash = ethash_keccak256(src, a[1]);
    trace(h, hash.bytes, 32);
    std::memcpy(dst, hash.bytes, 32);
    return 0;
  }
  case Addmod:
  case Mulmod: {
    uint8_t tag = op;
    trace(h, &tag, 1);
    trace(h, m.at(a[0], 32), 32);
    trace(h, m.at(a[1], 32), 32);
    trace(h, m.at(a[2], 32), 32);
    uint512_t x = read_be(m.at(a[0], 32)), y = read_be(m.at(a[1], 32));
    uint512_t n = read_be(m.at(a[2], 32));
    auto *dst = m.at(a[3], 32);
    uint512_t z = 0;
    if (n != 0) {
      if (op == Addmod)
        z = (x + y) % n;
      else
        z = (x * y) % n;
    }
    write_be(dst, z);
    trace(h, dst, 32);
    return 0;
  }
  }
  throw std::runtime_error("unknown host function");
}
static Host *active;
static uint32_t dt_call(ZenInstanceRef i, Op op, uint32_t a0 = 0,
                        uint32_t a1 = 0, uint32_t a2 = 0, uint32_t a3 = 0) {
  uint32_t a[] = {a0, a1, a2, a3};
  try {
    // Validate each accessed range before constructing a memory view.  A full
    // 4 GiB validation is neither needed nor possible for small memories.
    auto valid = [&](uint32_t p, uint32_t n) {
      if (!ZenValidateAppMemAddr(i, p, n))
        throw std::runtime_error("host memory out of bounds");
    };
    switch (op) {
    case Copy:
    case CodeCopy:
      valid(a0, a2);
      break;
    case Value:
      valid(a0, 32);
      break;
    case Revert:
    case Finish:
      valid(a0, a1);
      break;
    case Keccak:
      valid(a0, a1);
      valid(a2, 32);
      break;
    case Addmod:
    case Mulmod:
      valid(a0, 32);
      valid(a1, 32);
      valid(a2, 32);
      valid(a3, 32);
      break;
    default:
      break;
    }
    auto *base = static_cast<uint8_t *>(ZenGetHostMemAddr(i, 0));
    uint32_t result = host_call(*active, {base, size_t(UINT32_MAX) + 1}, op, a);
    if (op == Finish || op == Revert)
      ZenInstanceExit(i, op == Finish ? 0 : 1);
    return result;
  } catch (...) {
    active->fault = true;
    ZenSetInstanceExceptionByHostapi(i, ZenGetErrCodeOutOfBoundsMemory());
    return 0;
  }
}
static int32_t d_size(ZenInstanceRef i) { return dt_call(i, Size); }
static int32_t d_codesize(ZenInstanceRef i) { return dt_call(i, CodeSize); }
static void d_copy(ZenInstanceRef i, int32_t a, int32_t b, int32_t c) {
  dt_call(i, Copy, a, b, c);
}
static void d_codecopy(ZenInstanceRef i, int32_t a, int32_t b, int32_t c) {
  dt_call(i, CodeCopy, a, b, c);
}
static void d_value(ZenInstanceRef i, int32_t a) { dt_call(i, Value, a); }
static void d_revert(ZenInstanceRef i, int32_t a, int32_t b) {
  dt_call(i, Revert, a, b);
}
static void d_finish(ZenInstanceRef i, int32_t a, int32_t b) {
  dt_call(i, Finish, a, b);
}
static void d_hash(ZenInstanceRef i, int32_t a, int32_t b, int32_t c) {
  dt_call(i, Keccak, a, b, c);
}
static void d_add(ZenInstanceRef i, int32_t a, int32_t b, int32_t c,
                  int32_t d) {
  dt_call(i, Addmod, a, b, c, d);
}
static void d_mul(ZenInstanceRef i, int32_t a, int32_t b, int32_t c,
                  int32_t d) {
  dt_call(i, Mulmod, a, b, c, d);
}
struct Def {
  const char *name;
  Op op;
  int args;
  bool ret;
  void *fn;
};
static const Def defs[] = {
    {"getCallDataSize", Size, 0, true, (void *)d_size},
    {"callDataCopy", Copy, 3, false, (void *)d_copy},
    {"getCallValue", Value, 1, false, (void *)d_value},
    {"revert", Revert, 2, false, (void *)d_revert},
    {"finish", Finish, 2, false, (void *)d_finish},
    {"getCodeSize", CodeSize, 0, true, (void *)d_codesize},
    {"codeCopy", CodeCopy, 3, false, (void *)d_codecopy},
    {"keccak256", Keccak, 3, false, (void *)d_hash},
    {"addmod", Addmod, 4, false, (void *)d_add},
    {"mulmod", Mulmod, 4, false, (void *)d_mul}};
static void run_dtvm(Host &h, const std::string &path, ZenRunMode mode,
                     bool lazy = false) {
  ZenRuntimeConfig config{};
  config.Mode = mode;
  config.DisableWASI = true;
  ZenRuntimeRef rt;
  if (lazy) {
    // The public C API does not expose lazy JIT; create the same runtime with
    // the internal configuration. This relies on the current C API handle
    // implementation and must use the exact DTVM build configuration.
    zen::runtime::RuntimeConfig cfg;
    cfg.Mode = zen::common::RunMode::MultipassMode;
    cfg.EnableMultipassLazy = true;
#ifdef ZEN_ENABLE_BUILTIN_WASI
    cfg.DisableWASI = true;
#endif
    rt = reinterpret_cast<ZenRuntimeRef>(
        zen::runtime::Runtime::newRuntime(cfg).release());
  } else
    rt = ZenCreateRuntime(&config);
  if (!rt)
    throw std::runtime_error("DTVM runtime creation failed");
  ZenType i32[] = {ZenTypeI32, ZenTypeI32, ZenTypeI32, ZenTypeI32};
  std::vector<ZenHostFuncDesc> desc;
  for (auto &d : defs)
    desc.push_back({d.name, static_cast<uint32_t>(d.args), i32, d.ret ? 1u : 0u,
                    i32, d.fn});
  auto hd = ZenCreateHostModuleDesc(rt, "env", desc.data(), desc.size());
  auto hm = hd ? ZenLoadHostModule(rt, hd) : nullptr;
  if (!hm)
    throw std::runtime_error("DTVM host registration failed");
  char error[1024]{};
  auto module = ZenLoadModuleFromFile(rt, path.c_str(), error, sizeof(error));
  if (!module)
    throw std::runtime_error(std::string("DTVM load: ") + error);
  uint32_t function_index = 0;
  if (!ZenGetExportFunc(module, "call", &function_index))
    throw std::runtime_error("missing call export");
  const auto *type =
      reinterpret_cast<zen::runtime::Module *>(module)->getFunctionType(
          function_index);
  if (!type || type->NumParams != 0 || type->NumReturns != 0)
    throw std::runtime_error("call must have type () -> ()");
  auto iso = ZenCreateIsolation(rt);
  auto inst = ZenCreateInstance(iso, module, error, sizeof(error));
  if (!inst)
    throw std::runtime_error(std::string("DTVM instance: ") + error);
  active = &h;
  // The current DTVM module ABI represents at most two return values. The
  // signature check above rejects any return before entering the C API.
  ZenValue results[2];
  uint32_t count = 0;
  bool ok =
      ZenCallWasmFuncByName(rt, inst, "call", nullptr, 0, results, &count);
  if (!ok && !h.finished && !h.reverted) {
    ZenGetInstanceError(inst, error, sizeof(error));
    throw std::runtime_error(std::string("DTVM call: ") + error);
  }
  ZenDeleteInstance(iso, inst);
  ZenDeleteIsolation(rt, iso);
  ZenDeleteModule(rt, module);
  ZenDeleteHostModule(rt, hm);
  ZenDeleteHostModuleDesc(rt, hd);
  ZenDeleteRuntime(rt);
  active = nullptr;
}
struct WEnv {
  Host *h;
  Op op;
};
static wasm_trap_t *wt_callback(void *p, wasmtime_caller_t *caller,
                                const wasmtime_val_t *args, size_t nargs,
                                wasmtime_val_t *res, size_t) {
  auto &e = *static_cast<WEnv *>(p);
  uint32_t a[4]{};
  for (size_t i = 0; i < nargs; ++i)
    a[i] = static_cast<uint32_t>(args[i].of.i32);
  try {
    wasmtime_extern_t ext;
    if (!wasmtime_caller_export_get(caller, "memory", 6, &ext))
      throw std::runtime_error("missing exported memory");
    struct ExternGuard {
      wasmtime_extern_t *value;
      ~ExternGuard() { wasmtime_extern_delete(value); }
    } guard{&ext};
    if (ext.kind != WASMTIME_EXTERN_MEMORY)
      throw std::runtime_error("exported memory has wrong type");
    auto *ctx = wasmtime_caller_context(caller);
    Mem m{wasmtime_memory_data(ctx, &ext.of.memory),
          wasmtime_memory_data_size(ctx, &ext.of.memory)};
    auto value = host_call(*e.h, m, e.op, a);
    if (e.op == Size || e.op == CodeSize) {
      res[0].kind = WASMTIME_I32;
      res[0].of.i32 = value;
    }
    if (e.op == Finish || e.op == Revert)
      return wasmtime_trap_new("contract exit", 13);
    return nullptr;
  } catch (const std::exception &x) {
    e.h->fault = true;
    return wasmtime_trap_new(x.what(), std::strlen(x.what()));
  }
}
static void check_wt(wasmtime_error_t *err) {
  if (!err)
    return;
  wasm_name_t msg;
  wasmtime_error_message(err, &msg);
  std::string s(msg.data, msg.size);
  wasm_name_delete(&msg);
  wasmtime_error_delete(err);
  throw std::runtime_error(s);
}
static void run_wt(Host &h, const std::vector<uint8_t> &bytes) {
  auto *engine = wasm_engine_new();
  auto *store = wasmtime_store_new(engine, nullptr, nullptr);
  auto *ctx = wasmtime_store_context(store);
  auto *linker = wasmtime_linker_new(engine);
  std::array<WEnv, std::size(defs)> env{};
  for (size_t i = 0; i < std::size(defs); ++i) {
    auto &d = defs[i];
    env[i] = {&h, d.op};
    wasm_valtype_vec_t params, results;
    wasm_valtype_vec_new_uninitialized(&params, d.args);
    for (int j = 0; j < d.args; ++j)
      params.data[j] = wasm_valtype_new_i32();
    wasm_valtype_vec_new_uninitialized(&results, d.ret ? 1 : 0);
    if (d.ret)
      results.data[0] = wasm_valtype_new_i32();
    auto *ty = wasm_functype_new(&params, &results);
    check_wt(wasmtime_linker_define_func(linker, "env", 3, d.name,
                                         std::strlen(d.name), ty, wt_callback,
                                         &env[i], nullptr));
    wasm_functype_delete(ty);
  }
  wasmtime_module_t *module = nullptr;
  check_wt(wasmtime_module_new(engine, bytes.data(), bytes.size(), &module));
  wasmtime_instance_t instance;
  wasm_trap_t *trap = nullptr;
  check_wt(wasmtime_linker_instantiate(linker, ctx, module, &instance, &trap));
  if (trap) {
    wasm_trap_delete(trap);
    throw std::runtime_error("Wasmtime instantiation trapped");
  }
  wasmtime_extern_t fn;
  if (!wasmtime_instance_export_get(ctx, &instance, "call", 4, &fn) ||
      fn.kind != WASMTIME_EXTERN_FUNC)
    throw std::runtime_error("missing call export");
  auto *type = wasmtime_func_type(ctx, &fn.of.func);
  const bool valid_type = wasm_functype_params(type)->size == 0 &&
                          wasm_functype_results(type)->size == 0;
  wasm_functype_delete(type);
  if (!valid_type) {
    wasmtime_extern_delete(&fn);
    throw std::runtime_error("call must have type () -> ()");
  }
  auto *err =
      wasmtime_func_call(ctx, &fn.of.func, nullptr, 0, nullptr, 0, &trap);
  wasmtime_extern_delete(&fn);
  if (err && (h.finished || h.reverted) && !h.fault)
    wasmtime_error_delete(err);
  else
    check_wt(err);
  if (trap) {
    wasm_trap_delete(trap);
    if (!h.finished && !h.reverted)
      throw std::runtime_error("unexpected Wasmtime trap");
  }
  wasmtime_module_delete(module);
  wasmtime_linker_delete(linker);
  wasmtime_store_delete(store);
  wasm_engine_delete(engine);
}
static std::vector<uint8_t> hex(const std::string &s) {
  if (s.size() % 2)
    throw std::runtime_error("odd-length hex");
  std::vector<uint8_t> v;
  for (size_t i = 0; i < s.size(); i += 2) {
    auto x = s.substr(i, 2);
    if (x.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
      throw std::runtime_error("invalid hex");
    v.push_back(std::stoul(x, nullptr, 16));
  }
  return v;
}
int main(int argc, char **argv) {
  try {
    if (argc != 4 && argc != 5)
      throw std::runtime_error(
          "usage: contract-runner "
          "<dtvm-interp|dtvm-singlepass|dtvm-multipass|dtvm-lazy|wasmtime> "
          "<wasm> <calldata-hex> [--trace]");
    std::string mode = argv[1], path = argv[2];
    Host h;
    h.input = hex(argv[3]);
    if (h.input.size() > UINT32_MAX)
      throw std::runtime_error("calldata too large");
    if (argc == 5) {
      if (std::string(argv[4]) != "--trace")
        throw std::runtime_error("unknown option");
      h.trace_enabled = true;
    }
    std::ifstream f(path, std::ios::binary);
    if (!f)
      throw std::runtime_error("cannot read wasm");
    std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(f), {}};
    if (bytes.size() > UINT32_MAX - 4u)
      throw std::runtime_error("wasm too large");
    uint32_t n = bytes.size();
    h.code = {uint8_t(n >> 24), uint8_t(n >> 16), uint8_t(n >> 8), uint8_t(n)};
    h.code.insert(h.code.end(), bytes.begin(), bytes.end());
    if (mode == "wasmtime")
      run_wt(h, bytes);
    else if (mode == "dtvm-interp")
      run_dtvm(h, path, ZenModeInterp);
    else if (mode == "dtvm-singlepass")
      run_dtvm(h, path, ZenModeSinglepass);
    else if (mode == "dtvm-multipass")
      run_dtvm(h, path, ZenModeMultipass);
    else if (mode == "dtvm-lazy")
      run_dtvm(h, path, ZenModeMultipass, true);
    else
      throw std::runtime_error("unknown engine");
    if (h.fault || (!h.finished && !h.reverted))
      throw std::runtime_error("missing contract finish/revert");
    std::cout << (h.finished ? "finish " : "revert ");
    static const char *digits = "0123456789abcdef";
    for (auto b : h.output)
      std::cout << digits[b >> 4] << digits[b & 15];
    std::cout << "\ncounts";
    for (auto x : h.calls)
      std::cout << ' ' << x;
    if (h.trace_enabled)
      std::cout << "\ncrypto_trace " << std::hex << h.crypto_trace << std::dec;
    std::cout << '\n';
    return h.finished ? 0 : 2;
  } catch (const std::exception &x) {
    std::cerr << "error: " << x.what() << '\n';
    return 1;
  }
}
