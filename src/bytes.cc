// SPDX-License-Identifier: AGPL-3.0-only
// quay.bytes -- The encodings SimpleX's protocols are written in, read from
// any input range and written into anything that takes bytes (push_back):
// big-endian integers, shortString (a byte's length) and largeString (two
// bytes'), the fixed-size padded blocks every transport frame and
// encrypted body is (a length, the content, '#' to the end), the T/F
// flags, and public keys as X.509 SubjectPublicKeyInfo -- the four curves
// SimpleX uses, each a type of its own. Nothing allocated where a caller's
// buffer or a view will do; errors are types, in a spl::variant.
export module quay.bytes;

import std;
import splice;

export namespace quay {

using byte = std::uint8_t;
using bytes = std::vector<byte>;

// What is wrong with what was read.
namespace errors {
struct short_input {  // it ended before what was asked of it
  friend constexpr bool operator==(short_input, short_input) = default;
};
struct too_long {  // more than its length can say, or than its block holds
  std::size_t size = 0;
  friend constexpr bool operator==(too_long, too_long) = default;
};
struct bad_padding {  // a padded block whose length is past its end
  friend constexpr bool operator==(bad_padding, bad_padding) = default;
};
struct bad_flag {  // neither 'T' nor 'F'
  friend constexpr bool operator==(bad_flag, bad_flag) = default;
};
struct bad_key {  // not a SubjectPublicKeyInfo of the curve asked for
  friend constexpr bool operator==(bad_key, bad_key) = default;
};
}  // namespace errors
using decode_error = spl::variant<errors::short_input, errors::too_long, errors::bad_padding, errors::bad_flag, errors::bad_key>;

// What takes bytes: a std::vector<byte>, a std::string, a counting sink.
template <class Out>
concept byte_sink = requires(Out& out, byte b) { out.push_back(b); };

// ---- written ----------------------------------------------------------------

template <byte_sink Out> constexpr void put_byte(Out& out, byte b) { out.push_back(static_cast<std::ranges::range_value_t<Out>>(b)); }
template <byte_sink Out, std::ranges::input_range R> constexpr void put_bytes(Out& out, R&& what) {
  for (const auto one : what) put_byte(out, static_cast<byte>(one));
}
template <byte_sink Out> constexpr void put_u16(Out& out, std::uint16_t n) {
  put_byte(out, static_cast<byte>(n >> 8)), put_byte(out, static_cast<byte>(n));
}
template <byte_sink Out> constexpr void put_u32(Out& out, std::uint32_t n) {
  for (int shift = 24; shift >= 0; shift -= 8) put_byte(out, static_cast<byte>(n >> shift));
}
template <byte_sink Out> constexpr void put_u64(Out& out, std::uint64_t n) {
  for (int shift = 56; shift >= 0; shift -= 8) put_byte(out, static_cast<byte>(n >> shift));
}
template <byte_sink Out> constexpr void put_flag(Out& out, bool on) { put_byte(out, on ? 'T' : 'F'); }
// A shortString: its length in a byte -- 255 at most -- then it.
template <byte_sink Out, std::ranges::sized_range R>
constexpr std::expected<void, decode_error> put_short(Out& out, R&& what) {
  const auto n = std::ranges::size(what);
  if (n > 255) return std::unexpected(errors::too_long{n});
  put_byte(out, static_cast<byte>(n));
  put_bytes(out, what);
  return {};
}
// A largeString: its length in two bytes -- 65535 at most -- then it.
template <byte_sink Out, std::ranges::sized_range R>
constexpr std::expected<void, decode_error> put_large(Out& out, R&& what) {
  const auto n = std::ranges::size(what);
  if (n > 65535) return std::unexpected(errors::too_long{n});
  put_u16(out, static_cast<std::uint16_t>(n));
  put_bytes(out, what);
  return {};
}
// A padded block of `size` bytes: the content's length (two bytes), the
// content, then '#' to the end. Too long for the block: nothing written.
template <byte_sink Out, std::ranges::sized_range R>
constexpr std::expected<void, decode_error> put_padded(Out& out, R&& content, std::size_t size) {
  const auto n = std::ranges::size(content);
  if (size < 2 || n > size - 2 || n > 65535) return std::unexpected(errors::too_long{n});
  put_u16(out, static_cast<std::uint16_t>(n));
  put_bytes(out, content);
  for (std::size_t i = n + 2; i < size; ++i) put_byte(out, '#');
  return {};
}
// A padded block's content: a view into it.
[[nodiscard]] constexpr std::expected<std::span<const byte>, decode_error> unpadded(std::span<const byte> block) {
  if (block.size() < 2) return std::unexpected(errors::short_input{});
  const std::size_t n = (std::size_t{block[0]} << 8) | block[1];
  if (n > block.size() - 2) return std::unexpected(errors::bad_padding{});
  return block.subspan(2, n);
}

// ---- read -------------------------------------------------------------------

// What is read from an input range, a field at a time: each read takes
// what it reads, and says where the range ended too soon.
template <std::input_iterator I, std::sentinel_for<I> S = I>
class reader {
 public:
  constexpr reader(I at, S end) : at_(std::move(at)), end_(std::move(end)) {}
  [[nodiscard]] constexpr bool done() const { return at_ == end_; }
  constexpr std::expected<byte, decode_error> u8() {
    if (at_ == end_) return std::unexpected(errors::short_input{});
    const auto b = static_cast<byte>(*at_);
    ++at_;
    return b;
  }
  constexpr std::expected<std::uint16_t, decode_error> u16() { return number<std::uint16_t>(2); }
  constexpr std::expected<std::uint32_t, decode_error> u32() { return number<std::uint32_t>(4); }
  constexpr std::expected<std::uint64_t, decode_error> u64() { return number<std::uint64_t>(8); }
  constexpr std::expected<bool, decode_error> flag() {
    const auto b = u8();
    if (!b) return std::unexpected(b.error());
    if (*b == 'T') return true;
    if (*b == 'F') return false;
    return std::unexpected(errors::bad_flag{});
  }
  // `n` bytes, as they are, into `out`.
  template <byte_sink Out>
  constexpr std::expected<void, decode_error> take(std::size_t n, Out& out) {
    for (; n > 0; --n) {
      const auto b = u8();
      if (!b) return std::unexpected(b.error());
      put_byte(out, *b);
    }
    return {};
  }
  // `n` bytes, owned.
  constexpr std::expected<bytes, decode_error> take(std::size_t n) {
    bytes out;
    if (auto got = take(n, out); !got) return std::unexpected(got.error());
    return out;
  }
  // A fixed number of bytes, as an array.
  template <std::size_t N>
  constexpr std::expected<std::array<byte, N>, decode_error> fixed() {
    std::array<byte, N> out{};
    for (auto& one : out) {
      const auto b = u8();
      if (!b) return std::unexpected(b.error());
      one = *b;
    }
    return out;
  }
  constexpr std::expected<bytes, decode_error> short_string() {
    const auto n = u8();
    if (!n) return std::unexpected(n.error());
    return take(*n);
  }
  constexpr std::expected<bytes, decode_error> large_string() {
    const auto n = u16();
    if (!n) return std::unexpected(n.error());
    return take(*n);
  }
  // What is left, owned.
  constexpr bytes rest() {
    bytes out;
    for (; at_ != end_; ++at_) out.push_back(static_cast<byte>(*at_));
    return out;
  }

 private:
  template <class N>
  constexpr std::expected<N, decode_error> number(int size) {
    N value = 0;
    for (int i = 0; i < size; ++i) {
      const auto b = u8();
      if (!b) return std::unexpected(b.error());
      value = static_cast<N>((value << 8) | *b);
    }
    return value;
  }
  I at_;
  S end_;
};
template <std::ranges::input_range R>
constexpr auto reader_of(R& range) {
  return reader<std::ranges::iterator_t<R>, std::ranges::sentinel_t<R>>(std::ranges::begin(range), std::ranges::end(range));
}

// ---- keys -------------------------------------------------------------------

// The curves SimpleX uses, each with its key sizes and its
// SubjectPublicKeyInfo's DER prefix (RFC 8410): the key's raw bytes follow it.
namespace curve {
struct x25519 {
  static constexpr std::size_t public_size = 32, private_size = 32;
  static constexpr std::array<byte, 12> spki_prefix{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00};
};
struct ed25519 {
  static constexpr std::size_t public_size = 32, private_size = 32, signature_size = 64;
  static constexpr std::array<byte, 12> spki_prefix{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};
};
struct x448 {
  static constexpr std::size_t public_size = 56, private_size = 56;
  static constexpr std::array<byte, 12> spki_prefix{0x30, 0x42, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6f, 0x03, 0x39, 0x00};
};
struct ed448 {
  static constexpr std::size_t public_size = 57, private_size = 57, signature_size = 114;
  static constexpr std::array<byte, 12> spki_prefix{0x30, 0x43, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x03, 0x3a, 0x00};
};
}  // namespace curve

template <class Curve>
struct public_key {
  std::array<byte, Curve::public_size> raw{};
  friend constexpr bool operator==(const public_key&, const public_key&) = default;
};
// Any of them, where what comes says which (an X.509 key read).
using any_public_key = spl::variant<public_key<curve::x25519>, public_key<curve::ed25519>, public_key<curve::x448>, public_key<curve::ed448>>;

// A key as X.509 SubjectPublicKeyInfo, DER: what SimpleX puts on the wire
// (behind a shortString's length, where it goes in a field).
template <class Curve, byte_sink Out>
constexpr void put_spki(Out& out, const public_key<Curve>& key) {
  put_bytes(out, Curve::spki_prefix);
  put_bytes(out, key.raw);
}
template <class Curve>
[[nodiscard]] constexpr bytes spki_of(const public_key<Curve>& key) {
  bytes out;
  put_spki(out, key);
  return out;
}
// A SubjectPublicKeyInfo of the curve asked for: its key.
template <class Curve>
[[nodiscard]] constexpr std::expected<public_key<Curve>, decode_error> key_from_spki(std::span<const byte> der) {
  if (der.size() != Curve::spki_prefix.size() + Curve::public_size ||
      !std::ranges::equal(der.first(Curve::spki_prefix.size()), Curve::spki_prefix))
    return std::unexpected(errors::bad_key{});
  public_key<Curve> out;
  std::ranges::copy(der.subspan(Curve::spki_prefix.size()), out.raw.begin());
  return out;
}
// Of any of the four: the one its prefix says.
[[nodiscard]] constexpr std::expected<any_public_key, decode_error> any_key_from_spki(std::span<const byte> der) {
  if (auto k = key_from_spki<curve::x25519>(der)) return any_public_key(*k);
  if (auto k = key_from_spki<curve::ed25519>(der)) return any_public_key(*k);
  if (auto k = key_from_spki<curve::x448>(der)) return any_public_key(*k);
  if (auto k = key_from_spki<curve::ed448>(der)) return any_public_key(*k);
  return std::unexpected(errors::bad_key{});
}

// ---- base64url ----------------------------------------------------------------

// Base64url (RFC 4648, 5), with its '=' padding: how SimpleX's URIs and
// links carry keys and ids -- simplexmq writes it padded and reads it only
// so. Encoded lazily into a sink of characters; decoded into bytes, padded
// or not.
template <class Out, std::ranges::input_range R>
constexpr void put_base64url(Out& out, R&& what) {
  constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::uint32_t held = 0;
  int count = 0;
  for (const auto one : what) {
    held = (held << 8) | static_cast<byte>(one);
    if (++count == 3) {
      for (int shift = 18; shift >= 0; shift -= 6) out.push_back(alphabet[(held >> shift) & 63]);
      held = 0, count = 0;
    }
  }
  if (count == 1) held <<= 16, out.push_back(alphabet[(held >> 18) & 63]), out.push_back(alphabet[(held >> 12) & 63]), out.push_back('='), out.push_back('=');
  if (count == 2) held <<= 8, out.push_back(alphabet[(held >> 18) & 63]), out.push_back(alphabet[(held >> 12) & 63]), out.push_back(alphabet[(held >> 6) & 63]), out.push_back('=');
}
// Padding '=' and the standard alphabet's + and / taken too, as some write them.
[[nodiscard]] constexpr std::optional<bytes> base64url_decode(std::string_view text) {
  const auto value = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-' || c == '+') return 62;
    if (c == '_' || c == '/') return 63;
    return -1;
  };
  while (!text.empty() && text.back() == '=') text.remove_suffix(1);
  bytes out;
  std::uint32_t held = 0;
  int bits = 0;
  for (const char c : text) {
    const int v = value(c);
    if (v < 0) return std::nullopt;
    held = (held << 6) | static_cast<std::uint32_t>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<byte>(held >> bits));
    }
  }
  if (bits >= 6) return std::nullopt;  // a lone character: no byte it could end
  return out;
}

}  // namespace quay
