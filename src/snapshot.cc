// SPDX-License-Identifier: AGPL-3.0-only
// quay.snapshot -- a value as bytes and back, for keeping a connection
// between runs: its ratchet, its queues, its keys. Written from the types
// themselves, by overloading: integers big-endian, a key or secret its raw
// bytes, strings and vectors counted, optionals flagged, maps counted
// pairs, a variant its index and its alternative, an aggregate its members
// in order (a structured binding pack), and a type with members it hides --
// a move-only state -- through the tie its snapshot_fields() gives.
//
// What is written is secret: it holds private keys and chain keys. Where it
// is kept is the caller's to protect.
export module quay.snapshot;

import std;
import splice;
import quay.bytes;

export namespace quay::snapshot {

// What a snapshot starts with: "quay", and the version of this layout.
inline constexpr std::array<byte, 4> magic{'q', 'u', 'a', 'y'};
inline constexpr byte layout_version = 1;
// No count read is believed above this: a corrupt snapshot allocates nothing large.
inline constexpr std::uint32_t max_count = 1u << 24;

namespace errors {
struct not_a_snapshot {};
struct other_version {
  byte version = 0;
};
struct bad_value {};  // a flag, an index or a count out of range
struct trailing {};   // bytes after the value
}  // namespace errors
using error = spl::variant<decode_error, errors::not_a_snapshot, errors::other_version, errors::bad_value, errors::trailing>;

namespace detail {
template <class T>
concept has_raw = requires(const T& t) {
  { t.raw } -> std::ranges::contiguous_range;
} && std::same_as<std::ranges::range_value_t<decltype(T::raw)>, byte>;
template <class T>
struct is_array : std::false_type {};
template <class T, std::size_t N>
struct is_array<std::array<T, N>> : std::true_type {};
template <class T>
concept tied = requires(T& t) { snapshot_fields(t); };
template <class T>
concept plain_aggregate = std::is_class_v<T> && std::is_aggregate_v<T> && !has_raw<T> && !is_array<T>::value && !tied<T>;

}  // namespace detail

// ---- writing ----------------------------------------------------------------------
// Members of one struct, so that every overload sees every other, whichever
// order they are written in.
struct writing {

template <byte_sink Out>
static constexpr void put(Out& out, bool flag) {
  put_byte(out, flag ? 1 : 0);
}
template <byte_sink Out, std::integral T>
  requires(!std::same_as<T, bool>)
static constexpr void put(Out& out, T n) {
  using U = std::make_unsigned_t<T>;
  const auto u = static_cast<U>(n);
  for (int shift = 8 * (static_cast<int>(sizeof(T)) - 1); shift >= 0; shift -= 8) put_byte(out, static_cast<byte>(u >> shift));
}
template <byte_sink Out, class T>
  requires std::is_enum_v<T>
static constexpr void put(Out& out, T e) {
  put(out, std::to_underlying(e));
}
template <byte_sink Out, detail::has_raw T>
static constexpr void put(Out& out, const T& key) {
  put_bytes(out, key.raw);
}
template <byte_sink Out, class T, std::size_t N>
static constexpr void put(Out& out, const std::array<T, N>& a) {
  for (const auto& one : a) put(out, one);
}
template <byte_sink Out>
static constexpr void put(Out& out, const std::string& s) {
  put(out, static_cast<std::uint32_t>(s.size()));
  for (const char c : s) put_byte(out, static_cast<byte>(c));
}
template <byte_sink Out, class T>
static constexpr void put(Out& out, const std::vector<T>& v) {
  put(out, static_cast<std::uint32_t>(v.size()));
  for (const auto& one : v) put(out, one);
}
template <byte_sink Out, class T>
static constexpr void put(Out& out, const std::optional<T>& o) {
  put_byte(out, o ? 1 : 0);
  if (o) put(out, *o);
}
template <byte_sink Out, class K, class V>
static constexpr void put(Out& out, const std::map<K, V>& m) {
  put(out, static_cast<std::uint32_t>(m.size()));
  for (const auto& [k, v] : m) put(out, k), put(out, v);
}
template <byte_sink Out, class A, class B>
static constexpr void put(Out& out, const std::pair<A, B>& p) {
  put(out, p.first), put(out, p.second);
}
template <byte_sink Out, class... Ts>
static constexpr void put(Out& out, const std::tuple<Ts...>& t) {
  std::apply([&](const auto&... each) { (put(out, each), ...); }, t);
}
template <byte_sink Out, class... Ts>
static constexpr void put(Out& out, const spl::variant<Ts...>& v) {
  put_byte(out, static_cast<byte>(v.index()));
  spl::visit([&](const auto& alternative) { put(out, alternative); }, v);
}
template <byte_sink Out, detail::tied T>
static constexpr void put(Out& out, const T& value) {
  put(out, snapshot_fields(value));
}
template <byte_sink Out, detail::plain_aggregate T>
static constexpr void put(Out& out, const T& value) {
  const auto& [... members] = value;
  (put(out, members), ...);
}

};

// ---- reading ----------------------------------------------------------------------
struct reading {

template <class R, std::integral T>
  requires(!std::same_as<T, bool>)
static constexpr std::expected<void, error> get(R& in, T& n) {
  using U = std::make_unsigned_t<T>;
  U u = 0;
  for (std::size_t i = 0; i < sizeof(T); ++i) {
    const auto b = in.u8();
    if (!b) return std::unexpected(b.error());
    u = static_cast<U>((sizeof(T) > 1 ? (u << 8) : 0) | *b);
  }
  n = static_cast<T>(u);
  return {};
}
template <class R>
static constexpr std::expected<void, error> get(R& in, bool& flag) {
  const auto b = in.u8();
  if (!b) return std::unexpected(b.error());
  if (*b > 1) return std::unexpected(errors::bad_value{});
  flag = *b == 1;
  return {};
}
template <class R, class T>
  requires std::is_enum_v<T>
static constexpr std::expected<void, error> get(R& in, T& e) {
  std::underlying_type_t<T> n{};
  if (auto r = get(in, n); !r) return r;
  e = static_cast<T>(n);
  return {};
}
template <class R, detail::has_raw T>
static constexpr std::expected<void, error> get(R& in, T& key) {
  for (auto& b : key.raw) {
    const auto got = in.u8();
    if (!got) return std::unexpected(got.error());
    b = *got;
  }
  return {};
}
template <class R, class T, std::size_t N>
static constexpr std::expected<void, error> get(R& in, std::array<T, N>& a) {
  for (auto& one : a)
    if (auto r = get(in, one); !r) return r;
  return {};
}
template <class R>
static constexpr std::expected<std::uint32_t, error> count(R& in) {
  std::uint32_t n = 0;
  if (auto r = get(in, n); !r) return std::unexpected(r.error());
  if (n > max_count) return std::unexpected(errors::bad_value{});
  return n;
}
template <class R>
static constexpr std::expected<void, error> get(R& in, std::string& s) {
  const auto n = count(in);
  if (!n) return std::unexpected(n.error());
  s.clear();
  for (std::uint32_t i = 0; i < *n; ++i) {
    const auto b = in.u8();
    if (!b) return std::unexpected(b.error());
    s.push_back(static_cast<char>(*b));
  }
  return {};
}
template <class R, class T>
static constexpr std::expected<void, error> get(R& in, std::vector<T>& v) {
  const auto n = count(in);
  if (!n) return std::unexpected(n.error());
  v.clear();
  for (std::uint32_t i = 0; i < *n; ++i) {
    T one{};
    if (auto r = get(in, one); !r) return r;
    v.push_back(std::move(one));
  }
  return {};
}
template <class R, class T>
static constexpr std::expected<void, error> get(R& in, std::optional<T>& o) {
  bool present = false;
  if (auto r = get(in, present); !r) return r;
  o.reset();
  if (!present) return {};
  T one{};
  if (auto r = get(in, one); !r) return r;
  o = std::move(one);
  return {};
}
template <class R, class K, class V>
static constexpr std::expected<void, error> get(R& in, std::map<K, V>& m) {
  const auto n = count(in);
  if (!n) return std::unexpected(n.error());
  m.clear();
  for (std::uint32_t i = 0; i < *n; ++i) {
    K k{};
    V v{};
    if (auto r = get(in, k); !r) return r;
    if (auto r = get(in, v); !r) return r;
    m.insert_or_assign(std::move(k), std::move(v));
  }
  return {};
}
template <class R, class A, class B>
static constexpr std::expected<void, error> get(R& in, std::pair<A, B>& p) {
  if (auto r = get(in, p.first); !r) return r;
  return get(in, p.second);
}
template <class R, class... Ts>
static constexpr std::expected<void, error> get(R& in, std::tuple<Ts...> t) {  // a tie: references, taken by value
  std::expected<void, error> result;
  std::apply([&](auto&... each) { ((result ? (void)(result = get(in, each)) : void()), ...); }, t);
  return result;
}
template <class R, class... Ts>
static constexpr std::expected<void, error> get(R& in, spl::variant<Ts...>& v) {
  const auto index = in.u8();
  if (!index) return std::unexpected(index.error());
  if (*index >= sizeof...(Ts)) return std::unexpected(errors::bad_value{});
  std::expected<void, error> result;
  std::size_t at = 0;
  // The alternative at the index read: made, read into, held.
  (([&] {
     if (at++ != *index) return;
     Ts one{};
     result = get(in, one);
     if (result) v = std::move(one);
   }()),
   ...);
  return result;
}
template <class R, detail::tied T>
static constexpr std::expected<void, error> get(R& in, T& value) {
  return get(in, snapshot_fields(value));
}
template <class R, detail::plain_aggregate T>
static constexpr std::expected<void, error> get(R& in, T& value) {
  auto& [... members] = value;
  std::expected<void, error> result;
  ((result ? (void)(result = get(in, members)) : void()), ...);
  return result;
}

};

// ---- whole snapshots ------------------------------------------------------------------

template <class T>
bytes of(const T& value) {
  bytes out;
  put_bytes(out, magic);
  put_byte(out, layout_version);
  writing::put(out, value);
  return out;
}
template <class T, std::ranges::input_range In>
std::expected<void, error> restore(In&& from, T& into) {
  auto in = reader_of(from);
  for (const byte m : magic) {
    const auto b = in.u8();
    if (!b || *b != m) return std::unexpected(errors::not_a_snapshot{});
  }
  const auto version = in.u8();
  if (!version) return std::unexpected(errors::not_a_snapshot{});
  if (*version != layout_version) return std::unexpected(errors::other_version{*version});
  if (auto r = reading::get(in, into); !r) return r;
  if (!in.done()) return std::unexpected(errors::trailing{});
  return {};
}

}  // namespace quay::snapshot
