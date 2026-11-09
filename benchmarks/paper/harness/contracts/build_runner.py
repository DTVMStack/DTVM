#!/usr/bin/env python3
"""Link the smoke runner with an existing Ninja DTVM build and Wasmtime C API."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess

p = argparse.ArgumentParser()
p.add_argument('--dtvm-build', type=Path, required=True)
p.add_argument('--wasmtime-capi', type=Path, required=True)
p.add_argument('--boost-include', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
a = p.parse_args()
root = Path(__file__).resolve().parents[4]
build = a.dtvm_build.resolve()
wt = a.wasmtime_capi.resolve()
out = a.out.resolve()
cache = (build / 'CMakeCache.txt').read_text()
home_line = next((line for line in cache.splitlines() if line.startswith('CMAKE_HOME_DIRECTORY:INTERNAL=')), None)
if not home_line or Path(home_line.split('=', 1)[1]).resolve() != root:
    raise SystemExit('DTVM build must be configured from this exact checkout')
out.parent.mkdir(parents=True, exist_ok=True)
obj = out.with_suffix('.o')
keccak_obj = out.with_name(out.name + '-keccak.o')
# The lazy adapter uses internal RuntimeConfig, whose layout is conditional on
# build defines. Extract the same defines and include paths as the CLI build.
lines = subprocess.check_output(['ninja', '-C', str(build), '-t', 'commands', 'dtvm'], text=True).splitlines()
compile_line = next((x for x in lines if 'src/cli/CMakeFiles/dtvm.dir/dtvm.cpp.o' in x and ' -c ' in x), None)
if compile_line is None:
    raise SystemExit('No dtvm compile command found; build the dtvm Ninja target first')
build_flags = [x for x in shlex.split(compile_line) if x.startswith(('-D', '-I'))]
if '-DZEN_ENABLE_MULTIPASS_JIT' not in build_flags or '-DZEN_ENABLE_SINGLEPASS_JIT' not in build_flags:
    raise SystemExit('DTVM build must enable both multipass and singlepass JIT')
subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17', '-O2', '-I', str(root/'src'),
                '-I', str(a.boost_include.resolve()), '-I', str(wt/'include'), *build_flags, '-c',
                str(Path(__file__).with_name('runner.cpp')), '-o', str(obj)], check=True)
subprocess.run([os.environ.get('CC', 'cc'), '-O2', '-I', str(root/'src'), '-c',
                str(root/'src/host/evm/keccak/keccak.c'), '-o', str(keccak_obj)], check=True)
# Reuse the configured DTVM executable's exact static libraries and LLVM flags.
# This supports the repository's Ninja build without modifying its CMake graph.
link = next((x for x in reversed(lines) if 'src/cli/CMakeFiles/dtvm.dir/dtvm.cpp.o' in x and ' -o dtvm ' in x), None)
if link is None:
    raise SystemExit('No dtvm link command found; build the dtvm Ninja target first')
args = shlex.split(link)
if args[:2] == [':', '&&']:
    args = args[2:]
if args[-2:] == ['&&', ':']:
    args = args[:-2]
args = [x for x in args if not x.startswith('-Wl,--dependency-file=')]
idx = args.index('src/cli/CMakeFiles/dtvm.dir/dtvm.cpp.o')
args[idx:idx+1] = [str(obj), str(keccak_obj)]
idx = args.index('-o')
args[idx+1] = str(out)
args += ['-L' + str(wt/'lib'), '-Wl,-rpath,' + str(wt/'lib'), '-lwasmtime']
subprocess.run(args, cwd=build, check=True)
print(out)
