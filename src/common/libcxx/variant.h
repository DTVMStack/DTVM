// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_COMMON_LIBCXX_VARIANT_H
#define ZEN_COMMON_LIBCXX_VARIANT_H

#include "common/libcxx/type_traits.h"
#include <algorithm>
#include <cassert>
#include <cstdint>

// NOLINTBEGIN(readability-identifier-naming)

namespace zen::common::libcxx {

class bad_variant_access : public std::exception {
public:
  bad_variant_access() = default;
  virtual ~bad_variant_access() = default;

  const char *what() const noexcept override { return "bad variant access"; }
};

template <typename... Types> class variant;

template <size_t I, typename T> struct variant_alternative;

template <size_t I, typename T>
using variant_alternative_t = typename variant_alternative<I, T>::type;

template <typename T> struct add_const {
  typedef const T type;
};

template <size_t I, typename T>
struct variant_alternative<I, const T>
    : add_const<variant_alternative_t<I, T>> {};

template <size_t I, typename FirstType, typename... RestTypes>
struct variant_alternative<I, variant<FirstType, RestTypes...>>
    : variant_alternative<I - 1, variant<RestTypes...>> {};

template <typename FirstType, typename... RestTypes>
struct variant_alternative<0, variant<FirstType, RestTypes...>> {
  using type = FirstType;
};

inline constexpr size_t variant_npos = size_t(-1);

namespace find_detail {

constexpr size_t not_found = static_cast<size_t>(-1);
constexpr size_t ambiguous = not_found - 1;

template <typename T, typename... Types> constexpr size_t find_index() {
  constexpr bool same_matches[] = {std::is_same<T, Types>::value...};
  size_t result = not_found;
  for (size_t i = 0; i < sizeof...(Types); ++i) {
    if (same_matches[i]) {
      if (result != not_found) {
        return ambiguous;
      }
      result = i;
    }
  }
  if (result != not_found) {
    return result;
  }
  // TODO: is_convertible?
  constexpr bool convertible_matches[] = {
      std::is_convertible<T, Types>::value...};
  for (size_t i = 0; i < sizeof...(Types); ++i) {
    if (convertible_matches[i]) {
      if (result != not_found) {
        return ambiguous;
      }
      result = i;
    }
  }
  return result;
}

template <typename T, typename... Types> struct find_possible_ambiguous_index {
  static constexpr size_t value = find_index<T, Types...>();
};

template <typename T, typename... Types> struct find_unambiguous_index {
  static constexpr size_t value = find_index<T, Types...>();
  static_assert(value != not_found, "ambiguous type in variant");
  static_assert(value != ambiguous, "type not found in variant");
};

} // namespace find_detail

template <typename... Types> class variant {
  template <size_t I, typename... OtherTypes>
  friend constexpr variant_alternative_t<I, variant<OtherTypes...>> &
  std::get(variant<OtherTypes...> &);

  template <size_t I, typename... OtherTypes>
  friend constexpr const variant_alternative_t<I, variant<OtherTypes...>> &
  std::get(const variant<OtherTypes...> &);

  template <size_t I, typename... OtherTypes>
  friend constexpr variant_alternative_t<I, variant<OtherTypes...>> &&
  std::get(variant<OtherTypes...> &&);

  template <size_t I, typename... OtherTypes>
  friend constexpr const variant_alternative_t<I, variant<OtherTypes...>> &&
  std::get(const variant<OtherTypes...> &&);

  template <typename T, typename... OtherTypes>
  friend constexpr T &std::get(variant<OtherTypes...> &);

  template <typename T, typename... OtherTypes>
  friend constexpr T &&std::get(variant<OtherTypes...> &&);

  template <typename T, typename... OtherTypes>
  friend constexpr const T &std::get(const variant<OtherTypes...> &);

  template <typename T, typename... OtherTypes>
  friend constexpr const T &&std::get(const variant<OtherTypes...> &&);

  static_assert(sizeof...(Types) > 0,
                "variant must consist of at least one alternative.");
  static_assert(conjunction_v<!std::is_array<Types>::value...>,
                "variant can not have an array type as an alternative.");
  static_assert(conjunction_v<!std::is_reference<Types>::value...>,
                "variant can not have a reference type as an alternative.");
  static_assert(conjunction_v<!std::is_void<Types>::value...>,
                "variant can not have a void type as an alternative.");

  using first_type = variant_alternative_t<0, variant<Types...>>;

public:
  /// 1 - default constructor
  constexpr variant() noexcept(
      std::is_nothrow_default_constructible<first_type>::value)
      : idx(0) {}

  /// 2 - copy constructor
  constexpr variant(const variant &other) : idx(other.idx) {
    if (idx != variant_npos) {
      copiers[idx](&storage, &other.storage);
    }
  }

  /// 3 - move constructor
  constexpr variant(variant &&other) noexcept(
      conjunction_v<std::is_nothrow_move_constructible<Types>::value...>)
      : idx(other.idx) {
    if (idx != variant_npos) {
      movers[idx](&storage, &other.storage);
    }
  }

  /// 4 - converting constructor
  template <typename T,
            std::enable_if_t<!std::is_same<remove_cvref_t<T>, variant>::value,
                             int> = 0,
            size_t Index =
                find_detail::find_possible_ambiguous_index<T, Types...>::value,
            std::enable_if_t<Index != find_detail::not_found &&
                                 Index != find_detail::ambiguous,
                             int> = 0>
  constexpr variant(T &&arg) noexcept(std::is_nothrow_constructible<T>::value) {
    helper_construct<T>(std::forward<T>(arg));
  }

  ~variant() {
    if (idx != variant_npos) {
      helper_destroy(idx);
    }
  }

  /// 1 - copy assignment
  constexpr variant &operator=(const variant &other) {
    if (this != other) {
      if (idx != variant_npos) {
        helper_destroy(idx);
      }
      if (idx != variant_npos) {
        copiers[idx](&storage, &other.storage);
      }
      idx = other.idx;
    }
    return *this;
  }

  /// 2 - move assignment
  constexpr variant &operator=(variant &&other) noexcept(
      conjunction_v<(std::is_nothrow_move_constructible<Types>::value &&
                     std::is_nothrow_move_assignable<Types>::value)...>) {

    if (this != other) {
      if (idx != variant_npos) {
        helper_destroy(idx);
      }
      if (idx != variant_npos) {
        movers[idx](&storage, &other.storage);
      }
      idx = other.idx;
    }
    return *this;
  }

  /// 3 - converting assignment
  template <typename T,
            std::enable_if_t<!std::is_same<remove_cvref_t<T>, variant>::value,
                             int> = 0,
            size_t Index =
                find_detail::find_possible_ambiguous_index<T, Types...>::value,
            std::enable_if_t<Index != find_detail::not_found &&
                                 Index != find_detail::ambiguous,
                             int> = 0>
  variant &
  operator=(T &&arg) noexcept(std::is_nothrow_assignable<T, T>::value
                                  &&std::is_nothrow_constructible<T>::value) {
    if (idx != variant_npos) {
      helper_destroy(idx);
    }
    helper_construct<T>(std::forward<T>(arg));
    return *this;
  }

  constexpr bool valueless_by_exception() const noexcept {
    return idx == variant_npos;
  }

  constexpr size_t index() const noexcept {
    return idx == variant_npos ? variant_npos : idx;
  }

private:
  template <typename T>
  static void copy_construct(void *dest, const void *src) {
    assert(dest);
    assert(src);
    new (dest) T(*reinterpret_cast<const T *>(src));
  }

  template <typename T> static void move_construct(void *dest, void *src) {
    assert(dest);
    assert(src);
    new (dest) T(std::move(*reinterpret_cast<T *>(src)));
  }

  template <typename T> static void destroy(void *ptr) noexcept {
    assert(ptr);
    reinterpret_cast<T *>(ptr)->~T();
  }

  template <typename T> void helper_construct(T &&arg) {
    try {
      new (&storage) std::remove_reference_t<T>(std::forward<T>(arg));
      idx = find_detail::find_unambiguous_index<T, Types...>::value;
    } catch (...) {
      idx = variant_npos;
      throw;
    }
  }

  void helper_destroy(size_t idx) {
    assert(idx != variant_npos);
    destroyers[idx](&storage);
  }

  using copy_func_t = void (*)(void *, const void *);
  static inline constexpr copy_func_t copiers[sizeof...(Types)] = {
      &copy_construct<Types>...,
  };

  using move_func_t = void (*)(void *, void *);
  static inline constexpr move_func_t movers[sizeof...(Types)] = {
      &move_construct<Types>...,
  };

  using destroy_func_t = void (*)(void *);
  static inline constexpr destroy_func_t destroyers[sizeof...(Types)] = {
      &destroy<Types>...,
  };

  size_t idx;
  alignas(Types...) char storage[std::max({sizeof(Types)...})];
};

} // namespace zen::common::libcxx

namespace std {

namespace zencxx = zen::common::libcxx;

template <size_t I, typename... Types>
constexpr zencxx::variant_alternative_t<I, zencxx::variant<Types...>> &
get(zencxx::variant<Types...> &v) {
  static_assert(I < sizeof...(Types));
  using alternative_t =
      zencxx::variant_alternative_t<I, zencxx::variant<Types...>>;
  static_assert(!std::is_void<alternative_t>::value);
  if (v.index() != I) {
    throw zencxx::bad_variant_access();
  }
  return *reinterpret_cast<alternative_t *>(v.storage);
}

template <size_t I, typename... Types>
constexpr const zencxx::variant_alternative_t<I, zencxx::variant<Types...>> &
get(const zencxx::variant<Types...> &v) {
  static_assert(I < sizeof...(Types));
  using alternative_t =
      zencxx::variant_alternative_t<I, zencxx::variant<Types...>>;
  static_assert(!std::is_void<alternative_t>::value);
  if (v.index() != I) {
    throw zencxx::bad_variant_access();
  }
  return *reinterpret_cast<const alternative_t *>(v.storage);
}

template <size_t I, typename... Types>
constexpr zencxx::variant_alternative_t<I, zencxx::variant<Types...>> &&
get(zencxx::variant<Types...> &&v) {
  static_assert(I < sizeof...(Types));
  using alternative_t =
      zencxx::variant_alternative_t<I, zencxx::variant<Types...>>;
  static_assert(!std::is_void<alternative_t>::value);
  if (v.index() != I) {
    throw zencxx::bad_variant_access();
  }
  return std::move(*reinterpret_cast<alternative_t *>(v.storage));
}

template <size_t I, typename... Types>
constexpr const zencxx::variant_alternative_t<I, zencxx::variant<Types...>> &&
get(const zencxx::variant<Types...> &&v) {
  static_assert(I < sizeof...(Types));
  using alternative_t =
      zencxx::variant_alternative_t<I, zencxx::variant<Types...>>;
  static_assert(!std::is_void<alternative_t>::value);
  if (v.index() != I) {
    throw zencxx::bad_variant_access();
  }
  return std::move(*reinterpret_cast<const alternative_t *>(v.storage));
}

template <typename T, typename... Types>
constexpr T &get(zencxx::variant<Types...> &v) {
  static_assert(!std::is_void<T>::value);
  constexpr size_t index =
      zencxx::find_detail::find_unambiguous_index<T, Types...>::value;
  if (v.index() != index) {
    throw zencxx::bad_variant_access();
  }
  return *reinterpret_cast<T *>(v.storage);
}

template <typename T, typename... Types>
constexpr T &&get(zencxx::variant<Types...> &&v) {
  static_assert(!std::is_void<T>::value);
  constexpr size_t index =
      zencxx::find_detail::find_unambiguous_index<T, Types...>::value;
  if (v.index() != index) {
    throw zencxx::bad_variant_access();
  }
  return std::move(*reinterpret_cast<T *>(v.storage));
}

template <typename T, typename... Types>
constexpr const T &get(const zencxx::variant<Types...> &v) {
  static_assert(!std::is_void<T>::value);
  constexpr size_t index =
      zencxx::find_detail::find_unambiguous_index<T, Types...>::value;
  if (v.index() != index) {
    throw zencxx::bad_variant_access();
  }
  return *reinterpret_cast<const T *>(v.storage);
}

template <typename T, typename... Types>
constexpr const T &&get(const zencxx::variant<Types...> &&v) {
  static_assert(!std::is_void<T>::value);
  constexpr size_t index =
      zencxx::find_detail::find_unambiguous_index<T, Types...>::value;
  if (v.index() != index) {
    throw zencxx::bad_variant_access();
  }
  return std::move(*reinterpret_cast<const T *>(v.storage));
}

template <size_t I, typename... Types>
constexpr std::add_pointer_t<
    zencxx::variant_alternative_t<I, zencxx::variant<Types...>>>
get_if(zencxx::variant<Types...> *pv) noexcept {
  using alternative_t =
      zencxx::variant_alternative_t<I, zencxx::variant<Types...>>;
  static_assert(I < sizeof...(Types));
  static_assert(!std::is_void<alternative_t>::value);
  if (pv && pv->index() == I) {
    return std::addressof(get<I>(*pv));
  }
  return nullptr;
}

template <size_t I, typename... Types>
constexpr std::add_pointer_t<
    const zencxx::variant_alternative_t<I, zencxx::variant<Types...>>>
get_if(const zencxx::variant<Types...> *pv) noexcept {
  using alternative_t =
      zencxx::variant_alternative_t<I, zencxx::variant<Types...>>;
  static_assert(I < sizeof...(Types));
  static_assert(!std::is_void<alternative_t>::value);
  if (pv && pv->index() == I) {
    return std::addressof(get<I>(*pv));
  }
  return nullptr;
}

template <typename T, typename... Types>
constexpr std::add_pointer_t<T> get_if(zencxx::variant<Types...> *pv) noexcept {
  constexpr size_t I =
      zencxx::find_detail::find_unambiguous_index<T, Types...>::value;
  static_assert(!std::is_void<T>::value);
  return get_if<I>(pv);
}

template <typename T, typename... Types>
constexpr std::add_pointer_t<const T>
get_if(const zencxx::variant<Types...> *pv) noexcept {
  constexpr size_t I =
      zencxx::find_detail::find_unambiguous_index<T, Types...>::value;
  static_assert(!std::is_void<T>::value);
  return get_if<I>(pv);
}

} // namespace std

// NOLINTEND(readability-identifier-naming)

#endif
