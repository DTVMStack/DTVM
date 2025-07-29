// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_COMMON_LIBCXX_OPTIONAL_H
#define ZEN_COMMON_LIBCXX_OPTIONAL_H

#include "common/libcxx/type_traits.h"
#include "common/libcxx/utility.h"
#include <cassert>
#include <exception>

// NOLINTBEGIN(readability-identifier-naming)

namespace zen::common::libcxx {

struct nullopt_t {};

inline constexpr nullopt_t nullopt;

class bad_optional_access : public std::exception {
public:
  bad_optional_access() = default;
  virtual ~bad_optional_access() = default;

  const char *what() const noexcept override { return "bad optional access"; }
};

template <typename T> class optional {
public:
  using value_type = T;

  /// 1a - default construct
  constexpr optional() noexcept : engaged(false) {}

  /// 1b - construct explicitly empty
  constexpr optional(nullopt_t) noexcept : engaged(false) {}

  /// 2 - copy-construct
  constexpr optional(const optional &other) : engaged(other.engaged) {
    if (engaged) {
      construct_value(other.val);
    }
  }

  /// 3 - move-construct
  constexpr optional(optional &&other) noexcept(
      std::is_nothrow_move_constructible<value_type>::value)
      : engaged(other.engaged) {
    if (engaged) {
      construct_value(std::move(other.val));
    }
  }

  /// 4a - explicit converting copy-construct
  template <typename U,
            typename std::enable_if_t<
                std::is_constructible<T, const U &>::value &&
                    !std::is_constructible<T, optional<U> &>::value &&
                    !std::is_constructible<T, const optional<U> &>::value &&
                    !std::is_constructible<T, optional<U> &&>::value &&
                    !std::is_constructible<T, const optional<U> &&>::value &&
                    !std::is_convertible<optional<U> &, T>::value &&
                    !std::is_convertible<const optional<U> &, T>::value &&
                    !std::is_convertible<optional<U> &&, T>::value &&
                    !std::is_convertible<const optional<U> &&, T>::value &&
                    !std::is_convertible<const U &, T>::value, /*=> explicit */
                int> = 0>
  explicit optional(const optional<U> &other) : engaged(other.engaged) {
    if (engaged) {
      construct_value(other.val);
    }
  }

  /// 4b - implicit converting copy-construct
  template <typename U,
            typename std::enable_if_t<
                std::is_constructible<T, const U &>::value &&
                    !std::is_constructible<T, optional<U> &>::value &&
                    !std::is_constructible<T, const optional<U> &>::value &&
                    !std::is_constructible<T, optional<U> &&>::value &&
                    !std::is_constructible<T, const optional<U> &&>::value &&
                    !std::is_convertible<optional<U> &, T>::value &&
                    !std::is_convertible<const optional<U> &, T>::value &&
                    !std::is_convertible<optional<U> &&, T>::value &&
                    !std::is_convertible<const optional<U> &&, T>::value &&
                    std::is_convertible<const U &, T>::value, /*=> implicit */
                int> = 0>
  optional(const optional<U> &other) : engaged(other.engaged) {
    if (engaged) {
      construct_value(other.val);
    }
  }

  /// 5a - explicit converting move-construct
  template <typename U,
            typename std::enable_if_t<
                std::is_constructible<T, U &&>::value &&
                    !std::is_constructible<T, optional<U> &>::value &&
                    !std::is_constructible<T, const optional<U> &>::value &&
                    !std::is_constructible<T, optional<U> &&>::value &&
                    !std::is_constructible<T, const optional<U> &&>::value &&
                    !std::is_convertible<optional<U> &, T>::value &&
                    !std::is_convertible<const optional<U> &, T>::value &&
                    !std::is_convertible<optional<U> &&, T>::value &&
                    !std::is_convertible<const optional<U> &&, T>::value &&
                    !std::is_convertible<U &&, T>::value, /*=> explicit */
                int> = 0>
  explicit optional(optional<U> &&other) : engaged(other.engaged) {
    if (engaged) {
      construct_value(std::move(other.val));
    }
  }

  /// 5b - implicit converting move-construct
  template <typename U,
            typename std::enable_if_t<
                std::is_constructible<T, U &&>::value &&
                    !std::is_constructible<T, optional<U> &>::value &&
                    !std::is_constructible<T, const optional<U> &>::value &&
                    !std::is_constructible<T, optional<U> &&>::value &&
                    !std::is_constructible<T, const optional<U> &&>::value &&
                    !std::is_convertible<optional<U> &, T>::value &&
                    !std::is_convertible<const optional<U> &, T>::value &&
                    !std::is_convertible<optional<U> &&, T>::value &&
                    !std::is_convertible<const optional<U> &&, T>::value &&
                    std::is_convertible<U &&, T>::value, /*=> implicit */
                int> = 0>
  optional(optional<U> &&other) : engaged(other.engaged) {
    if (engaged) {
      construct_value(std::move(other.val));
    }
  }

  /// 8a - explicit move-construct from value
  template <typename U = T,
            typename std::enable_if_t<
                std::is_constructible<T, U &&>::value &&
                    !std::is_same<remove_cvref_t<U>, in_place_t>::value &&
                    !std::is_same<remove_cvref_t<U>, optional<T>>::value &&
                    !std::is_convertible<U &&, T>::value /*=> explicit */,
                int> = 0>
  constexpr explicit optional(U &&value) : engaged(true) {
    construct_value(std::forward<U>(value));
  }

  /// 8b - implicit move-construct from value
  template <typename U = T,
            typename std::enable_if_t<
                std::is_constructible<T, U &&>::value &&
                    !std::is_same<remove_cvref_t<U>, in_place_t>::value &&
                    !std::is_same<remove_cvref_t<U>, optional<T>>::value &&
                    std::is_convertible<U &&, T>::value /*=> implicit */,
                int> = 0>
  constexpr optional(U &&value) : engaged(true) {
    construct_value(std::forward<U>(value));
  }

  ~optional() { reset(); }

  /// 1 - assign explicitly empty
  optional &operator=(nullopt_t) noexcept {
    reset();
    return *this;
  }

  /// 2 - copy-assign
  constexpr std::enable_if_t<std::is_copy_constructible<T>::value &&
                                 std::is_copy_assignable<T>::value,
                             optional &>
  operator=(const optional &other) {
    if (this != &other) {
      reset();
      engaged = other.engaged;
      if (engaged) {
        construct_value(other.val);
      }
    }
    return *this;
  }

  /// 3 - move-assign
  constexpr std::enable_if_t<std::is_move_constructible<T>::value &&
                                 std::is_move_assignable<T>::value,
                             optional &>
  operator=(optional &&other) noexcept(
      std::is_nothrow_move_assignable<T>::value
          &&std::is_nothrow_move_constructible<T>::value) {
    if (this != &other) {
      reset();
      engaged = other.engaged;
      if (engaged) {
        construct_value(std::move(other.val));
      }
    }
    return *this;
  }

  /// 4 - move-assign from value
  template <typename U = T>
  std::enable_if_t<!std::is_same<remove_cvref_t<U>, optional>::value &&
                       (!std::is_same<remove_cvref_t<U>, T>::value ||
                        !std::is_scalar<T>::value) &&
                       std::is_constructible<T, U>::value &&
                       std::is_assignable<T &, U>::value,
                   optional &>
  operator=(U &&value) {
    static_assert(std::is_same<T, std::decay_t<U>>::value);
    reset();
    construct_value(std::forward<U>(value));
    engaged = true;
    return *this;
  }

  /// 5 - converting copy-assign
  template <typename U>
  std::enable_if_t<!std::is_constructible<T, optional<U> &>::value &&
                       !std::is_constructible<T, const optional<U> &>::value &&
                       !std::is_constructible<T, optional<U> &&>::value &&
                       !std::is_constructible<T, const optional<U> &&>::value &&
                       !std::is_convertible<optional<U> &, T>::value &&
                       !std::is_convertible<const optional<U> &, T>::value &&
                       !std::is_convertible<optional<U> &&, T>::value &&
                       !std::is_convertible<const optional<U> &&, T>::value &&
                       !std::is_assignable<T &, optional<U> &>::value &&
                       !std::is_assignable<T &, const optional<U> &>::value &&
                       !std::is_assignable<T &, optional<U> &&>::value &&
                       !std::is_assignable<T &, const optional<U> &&>::value &&
                       std::is_constructible<T, const U &>::value &&
                       std::is_assignable<T &, const U &>::value,
                   optional &>
  operator=(const optional<U> &other) {
    *this = optional(other);
    return *this;
  }

  /// 6 - converting move-assign
  template <typename U>
  std::enable_if_t<!std::is_constructible<T, optional<U> &>::value &&
                       !std::is_constructible<T, const optional<U> &>::value &&
                       !std::is_constructible<T, optional<U> &&>::value &&
                       !std::is_constructible<T, const optional<U> &&>::value &&
                       !std::is_convertible<optional<U> &, T>::value &&
                       !std::is_convertible<const optional<U> &, T>::value &&
                       !std::is_convertible<optional<U> &&, T>::value &&
                       !std::is_convertible<const optional<U> &&, T>::value &&
                       !std::is_assignable<T &, optional<U> &>::value &&
                       !std::is_assignable<T &, const optional<U> &>::value &&
                       !std::is_assignable<T &, optional<U> &&>::value &&
                       !std::is_assignable<T &, const optional<U> &&>::value &&
                       std::is_constructible<T, U>::value &&
                       std::is_assignable<T &, U>::value,
                   optional &>
  operator=(optional<U> &&other) {
    *this = optional(std::move(other));
    return *this;
  }

  constexpr const value_type *operator->() const noexcept {
    assert(engaged && "optional operator-> called on a disengaged value");
    return std::addressof(val);
  }

  constexpr value_type *operator->() noexcept {
    assert(engaged && "optional operator-> called on a disengaged value");
    return std::addressof(val);
  }

  constexpr const value_type &operator*() const &noexcept {
    assert(engaged && "optional operator* called on a disengaged value");
    return val;
  }

  constexpr value_type &operator*() &noexcept {
    assert(engaged && "optional operator* called on a disengaged value");
    return val;
  }

  constexpr const value_type &&operator*() const &&noexcept {
    assert(engaged && "optional operator* called on a disengaged value");
    return std::move(val);
  }

  constexpr value_type &&operator*() &&noexcept {
    assert(engaged && "optional operator* called on a disengaged value");
    return std::move(val);
  }

  constexpr bool has_value() const noexcept { return engaged; }

  constexpr explicit operator bool() const noexcept { return has_value(); }

  constexpr value_type &value() & {
    check_engaged();
    return val;
  }

  constexpr const value_type &value() const & {
    check_engaged();
    return val;
  }

  constexpr value_type &&value() && {
    check_engaged();
    return std::move(val);
  }

  constexpr const value_type &&value() const && {
    check_engaged();
    return std::move(val);
  }

  template <typename U>
  constexpr value_type value_or(U &&default_value) const & {
    static_assert(std::is_convertible<U, T>::value);
    return engaged ? val
                   : static_cast<value_type>(std::forward<U>(default_value));
  }

  template <typename U> constexpr value_type value_or(U &&default_value) && {
    return engaged ? std::move(val)
                   : static_cast<value_type>(std::forward<U>(default_value));
  }

  void reset() noexcept {
    if (engaged) {
      destroy_value();
      engaged = false;
    }
  }

  template <class... Args> value_type &emplace(Args &&...args) {
    reset();
    construct_value(std::forward<Args>(args)...);
    engaged = true;
    return val;
  }

private:
  template <typename... Args> void construct_value(Args &&...args) {
    new (std::addressof(val)) value_type(std::forward<Args>(args)...);
  }

  void
  destroy_value() noexcept(std::is_nothrow_destructible<value_type>::value) {
    if (!std::is_trivially_destructible<value_type>::value) {
      val.~value_type();
    }
  }

  void check_engaged() const {
    if (!engaged) {
      throw bad_optional_access();
    }
  }

  bool engaged;
  union {
    value_type val;
  };
};

} // namespace zen::common::libcxx

// NOLINTEND(readability-identifier-naming)

#endif // ZEN_COMMON_LIBCXX_OPTIONAL_H
