// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_PLATFORM_PLATFORM_H
#define ZEN_PLATFORM_PLATFORM_H

#ifndef ZEN_ENABLE_SGX
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <shared_mutex>
#else
#include <platform/sgx/zen_sgx.h>
#include <platform/sgx/zen_sgx_mman.h>
#include <platform/sgx/zen_sgx_thread.h>
#include <platform/sgx/zen_sgx_time.h>
#endif // ZEN_ENABLE_SGX
#include <array>
#include <cassert>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifdef ZEN_DISABLE_CXX17_STL
#include "common/libcxx/cstddef.h"
#include "common/libcxx/optional.h"
#include "common/libcxx/string_view.h"
#include "common/libcxx/variant.h"
#else
#include <optional>
#include <string_view>
#include <variant>
#endif // ZEN_DISABLE_CXX17_STL
#include "common/libcxx/utility.h"

namespace zen::common {

#ifdef ZEN_DISABLE_CXX17_STL
using Byte = libcxx::byte;
using Bytes = libcxx::basic_string_view<Byte>;
using StringView = libcxx::string_view;
const auto Nullopt = libcxx::nullopt;
template <typename T> using Optional = libcxx::optional<T>;
template <typename... Types> using Variant = libcxx::variant<Types...>;
#else
using Byte = std::byte;
using Bytes = std::basic_string_view<Byte>;
using StringView = std::string_view;
const auto Nullopt = std::nullopt;
template <typename T> using Optional = std::optional<T>;
template <typename... Types> using Variant = std::variant<Types...>;
#endif // ZEN_DISABLE_CXX17_STL

using libcxx::to_underlying;

#ifndef ZEN_ENABLE_SGX
namespace chrono = std::chrono;
using SharedMutex = std::shared_timed_mutex;
using Mutex = std::mutex;
template <typename T> using LockGuard = std::lock_guard<T>;
template <typename T> using SharedLock = std::shared_lock<T>;
template <typename T> using UniqueLock = std::unique_lock<T>;
using STDFile = std::FILE;
using SteadyClock = chrono::steady_clock;
using SystemClock = chrono::system_clock;
#define os_sdtout ::stdout
#define os_stderr ::stderr
#define os_write(fd, buf, count) ::write(fd, buf, count)
#else
namespace chrono = sgx::chrono;
using SharedMutex = SgxSharedMutex;
using Mutex = SgxMutex;
template <typename T> using LockGuard = SgxLockGuard<T>;
template <typename T> using SharedLock = SgxSharedLock<T>;
template <typename T> using UniqueLock = SgxUniqueLock<T>;
using STDFile = SGXFILE;
using SteadyClock = chrono::SystemClock;
#define os_sdtout sgx_stdout
#define os_stderr sgx_stderr
#define os_write(fd, buf, count) sgx_write(fd, buf, count)
#endif // ZEN_ENABLE_SGX
} // namespace zen::common

#endif // ZEN_PLATFORM_H