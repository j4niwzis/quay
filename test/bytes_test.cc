// SPDX-License-Identifier: AGPL-3.0-only
// quay.bytes: the encodings, checked while compiling, and run.
import std;
import splice;
import gtest;
import quay.bytes;

#include "gtest/gtest-macros.h"

namespace {
using namespace quay;

constexpr bytes of(std::string_view s) { return bytes(s.begin(), s.end()); }

// Big-endian integers and the flags, both ways.
static_assert([] {
  bytes out;
  put_u16(out, 0x1234), put_u32(out, 0xdeadbeef), put_u64(out, 0x0102030405060708), put_flag(out, true), put_flag(out, false);
  auto r = reader_of(out);
  return *r.u16() == 0x1234 && *r.u32() == 0xdeadbeef && *r.u64() == 0x0102030405060708 && *r.flag() && !*r.flag() && r.done();
}());
// shortString and largeString; one too long for its length refused.
static_assert([] {
  bytes out;
  if (!put_short(out, of("smp")) || !put_large(out, of("queue"))) return false;
  auto r = reader_of(out);
  return *r.short_string() == of("smp") && *r.large_string() == of("queue") && r.done();
}());
static_assert([] {
  bytes out;
  const auto refused = put_short(out, bytes(256));
  return !refused && refused.error() == decode_error(errors::too_long{256}) && out.empty();
}());
// Read past the end: short input, said as such.
static_assert([] {
  const bytes one{0x01};
  auto r = reader_of(one);
  const auto got = r.u16();
  return !got && got.error() == decode_error(errors::short_input{});
}());
static_assert([] {
  const bytes flag{'X'};
  auto r = reader_of(flag);
  return r.flag().error() == decode_error(errors::bad_flag{});
}());
// A padded block: its length, the content, '#' to the end; and back.
static_assert([] {
  bytes block;
  if (!put_padded(block, of("hello"), 16)) return false;
  if (block.size() != 16 || block[0] != 0 || block[1] != 5 || block[7] != '#' || block[15] != '#') return false;
  const auto content = unpadded(block);
  return content && std::ranges::equal(*content, of("hello"));
}());
static_assert([] {
  bytes block;
  return !put_padded(block, bytes(15), 16) && block.empty();  // 15 + 2 > 16
}());
static_assert([] {
  const bytes lying{0x00, 0x09, 'a', 'b'};
  return unpadded(lying).error() == decode_error(errors::bad_padding{});
}());
// A key as SubjectPublicKeyInfo: written, read back, and read as the curve its prefix says.
static_assert([] {
  public_key<curve::ed25519> key;
  for (std::size_t i = 0; i < key.raw.size(); ++i) key.raw[i] = static_cast<byte>(i);
  const bytes der = spki_of(key);
  if (der.size() != 44 || key_from_spki<curve::ed25519>(der) != key) return false;
  if (key_from_spki<curve::x25519>(der)) return false;  // the same size, another curve
  const auto any = any_key_from_spki(der);
  return any && any->template get_if<public_key<curve::ed25519>>() != nullptr;
}());
// base64url, both ways (RFC 4648's vectors, unpadded).
static_assert([] {
  const auto enc = [](std::string_view s) {
    std::string out;
    put_base64url(out, s);
    return out;
  };
  return enc("") == "" && enc("f") == "Zg" && enc("fo") == "Zm8" && enc("foo") == "Zm9v" && enc("foob") == "Zm9vYg" &&
         enc("fooba") == "Zm9vYmE" && enc("foobar") == "Zm9vYmFy" && enc("\xfb\xff") == "-_8";
}());
static_assert(base64url_decode("Zm9vYmFy") == of("foobar") && base64url_decode("Zm9vYg==") == of("foob") && !base64url_decode("Z") &&
              !base64url_decode("Zm9v*"));
}  // namespace

TEST(Bytes, RoundTripsWhenRun) {
  bytes block;
  ASSERT_TRUE(put_padded(block, bytes(100, 7), 16384).has_value());
  EXPECT_EQ(block.size(), 16384u);
  EXPECT_EQ(unpadded(block)->size(), 100u);
}
