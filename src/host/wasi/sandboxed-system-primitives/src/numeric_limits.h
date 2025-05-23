// Part of the Wasmtime Project, under the Apache License v2.0 with LLVM
// Exceptions. See
// https://github.com/bytecodealliance/wasmtime/blob/main/LICENSE for license
// information.
//
// Significant parts of this file are derived from cloudabi-utils. See
// https://github.com/bytecodealliance/wasmtime/blob/main/lib/wasi/sandboxed-system-primitives/src/LICENSE
// for license information.
//
// The upstream file contains the following copyright notice:
//
// Copyright (c) 2015 Nuxi, https://nuxi.nl/

#ifndef COMMON_LIMITS_H
#define COMMON_LIMITS_H

#define NUMERIC_MIN(t)                                                         \
  _Generic((t)0, char                                                          \
           : CHAR_MIN, signed char                                             \
           : SCHAR_MIN, unsigned char : 0, short                               \
           : SHRT_MIN, unsigned short : 0, int                                 \
           : INT_MIN, unsigned int : 0, long                                   \
           : LONG_MIN, unsigned long : 0, long long                            \
           : LLONG_MIN, unsigned long long : 0, default                        \
           : (void)0)

#define NUMERIC_MAX(t)                                                         \
  _Generic((t)0, char                                                          \
           : CHAR_MAX, signed char                                             \
           : SCHAR_MAX, unsigned char                                          \
           : UCHAR_MAX, short                                                  \
           : SHRT_MAX, unsigned short                                          \
           : USHRT_MAX, int                                                    \
           : INT_MAX, unsigned int                                             \
           : UINT_MAX, long                                                    \
           : LONG_MAX, unsigned long                                           \
           : ULONG_MAX, long long                                              \
           : LLONG_MAX, unsigned long long                                     \
           : ULLONG_MAX, default                                               \
           : (void)0)

#endif
