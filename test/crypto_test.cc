// SPDX-License-Identifier: AGPL-3.0-only
// quay.crypto against what independent implementations say: Python's
// cryptography (OpenSSL) and hashlib for the curves, GCM, HKDF and hashes
// (test/vectors.inc, tools/gen_vectors.py); libsodium's own test for
// secretbox; Keccak-256's published values.
import std;
import splice;
import gtest;
import quay.bytes;
import quay.crypto;

#include "gtest/gtest-macros.h"

namespace {
using namespace quay;
using namespace quay::crypto;
#include "vectors.inc"

template <std::size_t N>
bool same(const std::array<byte, N>& a, std::span<const byte> b) {
  return std::ranges::equal(a, b);
}
template <class Curve, std::size_t N>
private_key<Curve> key_of(const std::array<byte, N>& raw) {
  private_key<Curve> out;
  std::ranges::copy(raw, out.raw.begin());
  return out;
}
template <class Curve, std::size_t N>
public_key<Curve> pub_of(const std::array<byte, N>& raw) {
  public_key<Curve> out;
  std::ranges::copy(raw, out.raw.begin());
  return out;
}
// A deterministic source: bytes counting up.
struct counting {
  byte next = 0;
  void operator()(std::span<byte> out) {
    for (auto& b : out) b = next++;
  }
};
}  // namespace

TEST(Crypto, X25519) {
  const auto a = key_of<curve::x25519>(x25519_a), b = key_of<curve::x25519>(x25519_b);
  EXPECT_TRUE(same(public_of(a).raw, x25519_a_pub));
  EXPECT_TRUE(same(public_of(b).raw, x25519_b_pub));
  EXPECT_TRUE(same(*agree(a, public_of(b)), x25519_shared));
  EXPECT_TRUE(same(*agree(b, public_of(a)), x25519_shared));
  EXPECT_TRUE(std::ranges::equal(spki_of(public_of(a)), x25519_a_spki));
  EXPECT_TRUE(!agree(a, public_key<curve::x25519>{}));  // the zero point: refused
}
TEST(Crypto, X448) {
  const auto a = key_of<curve::x448>(x448_a), b = key_of<curve::x448>(x448_b);
  EXPECT_TRUE(same(public_of(a).raw, x448_a_pub));
  EXPECT_TRUE(same(*agree(a, public_of(b)), x448_shared));
  EXPECT_TRUE(std::ranges::equal(spki_of(public_of(a)), x448_a_spki));
}
TEST(Crypto, Ed25519) {
  const auto k = key_of<curve::ed25519>(ed25519_seed);
  EXPECT_TRUE(same(public_of(k).raw, ed25519_pub));
  const auto s = sign(k, signed_message);
  EXPECT_TRUE(same(s.raw, ed25519_sig));
  EXPECT_TRUE(verify(public_of(k), signed_message, s));
  auto wrong = s;
  wrong.raw[0] ^= 1;
  EXPECT_TRUE(!verify(public_of(k), signed_message, wrong));
  EXPECT_TRUE(std::ranges::equal(spki_of(public_of(k)), ed25519_spki));
}
TEST(Crypto, Ed448) {
  const auto k = key_of<curve::ed448>(ed448_seed);
  EXPECT_TRUE(same(public_of(k).raw, ed448_pub));
  const auto s = sign(k, signed_message);
  EXPECT_TRUE(same(s.raw, ed448_sig));
  EXPECT_TRUE(verify(public_of(k), signed_message, s));
  EXPECT_TRUE(std::ranges::equal(spki_of(public_of(k)), ed448_spki));
}
// libsodium's test/default/secretbox.c and .exp.
TEST(Crypto, SecretboxAsLibsodium) {
  const box_key key{0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
                    0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2, 0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89};
  const box_nonce nonce{0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8,
                        0x75, 0xfc, 0x73, 0xd6, 0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37};
  const bytes message{0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5, 0xcf, 0x14, 0x13, 0x16, 0xeb, 0xeb, 0x0c, 0x7b, 0x52, 0x28, 0xc5,
                      0x2a, 0x4c, 0x62, 0xcb, 0xd4, 0x4b, 0x66, 0x84, 0x9b, 0x64, 0x24, 0x4f, 0xfc, 0xe5, 0xec, 0xba, 0xaf, 0x33, 0xbd,
                      0x75, 0x1a, 0x1a, 0xc7, 0x28, 0xd4, 0x5e, 0x6c, 0x61, 0x29, 0x6c, 0xdc, 0x3c, 0x01, 0x23, 0x35, 0x61, 0xf4, 0x1d,
                      0xb6, 0x6c, 0xce, 0x31, 0x4a, 0xdb, 0x31, 0x0e, 0x3b, 0xe8, 0x25, 0x0c, 0x46, 0xf0, 0x6d, 0xce, 0xea, 0x3a, 0x7f,
                      0xa1, 0x34, 0x80, 0x57, 0xe2, 0xf6, 0x55, 0x6a, 0xd6, 0xb1, 0x31, 0x8a, 0x02, 0x4a, 0x83, 0x8f, 0x21, 0xaf, 0x1f,
                      0xde, 0x04, 0x89, 0x77, 0xeb, 0x48, 0xf5, 0x9f, 0xfd, 0x49, 0x24, 0xca, 0x1c, 0x60, 0x90, 0x2e, 0x52, 0xf0, 0xa0,
                      0x89, 0xbc, 0x76, 0x89, 0x70, 0x40, 0xe0, 0x82, 0xf9, 0x37, 0x76, 0x38, 0x48, 0x64, 0x5e, 0x07, 0x05};
  const bytes expected{0xf3, 0xff, 0xc7, 0x70, 0x3f, 0x94, 0x00, 0xe5, 0x2a, 0x7d, 0xfb, 0x4b, 0x3d, 0x33, 0x05, 0xd9, 0x8e, 0x99, 0x3b,
                       0x9f, 0x48, 0x68, 0x12, 0x73, 0xc2, 0x96, 0x50, 0xba, 0x32, 0xfc, 0x76, 0xce, 0x48, 0x33, 0x2e, 0xa7, 0x16, 0x4d,
                       0x96, 0xa4, 0x47, 0x6f, 0xb8, 0xc5, 0x31, 0xa1, 0x18, 0x6a, 0xc0, 0xdf, 0xc1, 0x7c, 0x98, 0xdc, 0xe8, 0x7b, 0x4d,
                       0xa7, 0xf0, 0x11, 0xec, 0x48, 0xc9, 0x72, 0x71, 0xd2, 0xc2, 0x0f, 0x9b, 0x92, 0x8f, 0xe2, 0x27, 0x0d, 0x6f, 0xb8,
                       0x63, 0xd5, 0x17, 0x38, 0xb4, 0x8e, 0xee, 0xe3, 0x14, 0xa7, 0xcc, 0x8a, 0xb9, 0x32, 0x16, 0x45, 0x48, 0xe5, 0x26,
                       0xae, 0x90, 0x22, 0x43, 0x68, 0x51, 0x7a, 0xcf, 0xea, 0xbd, 0x6b, 0xb3, 0x73, 0x2b, 0xc0, 0xe9, 0xda, 0x99, 0x83,
                       0x2b, 0x61, 0xca, 0x01, 0xb6, 0xde, 0x56, 0x24, 0x4a, 0x9e, 0x88, 0xd5, 0xf9, 0xb3, 0x79, 0x73, 0xf6, 0x22, 0xa4,
                       0x3d, 0x14, 0xa6, 0x59, 0x9b, 0x1f, 0x65, 0x4c, 0xb4, 0x5a, 0x74, 0xe3, 0x55, 0xa5};
  const bytes boxed = secretbox(key, nonce, message);
  EXPECT_TRUE(boxed == expected);
  EXPECT_TRUE(*secretbox_open(key, nonce, boxed) == message);
  auto tampered = boxed;
  tampered.back() ^= 1;
  EXPECT_TRUE(!secretbox_open(key, nonce, tampered));
}
// A box's key is symmetric: each side's agreement through HSalsa20.
TEST(Crypto, BoxKeyBothWays) {
  counting random;
  const auto a = generate<curve::x25519>(random), b = generate<curve::x25519>(random);
  EXPECT_TRUE(*box_key_of(a.pub, b.priv) == *box_key_of(b.pub, a.priv));
}
TEST(Crypto, AesGcmSixteenByteIv) {
  aes_key key{};
  std::ranges::copy(gcm_key, key.begin());
  const auto s = gcm_seal(key, gcm_iv, gcm_ad, gcm_plain);
  EXPECT_TRUE(std::ranges::equal(s.cipher, gcm_cipher));
  EXPECT_TRUE(same(s.tag, gcm_expected_tag));
  EXPECT_TRUE(std::ranges::equal(*gcm_open(key, gcm_iv, gcm_ad, s.cipher, s.tag), gcm_plain));
  auto wrong = s.tag;
  wrong[3] ^= 1;
  EXPECT_TRUE(!gcm_open(key, gcm_iv, gcm_ad, s.cipher, wrong));
}
TEST(Crypto, HkdfAndHashes) {
  EXPECT_TRUE(std::ranges::equal(hkdf_sha512(hkdf_salt, hkdf_ikm, hkdf_info, 96), hkdf_out));
  const std::array<byte, 3> abc{'a', 'b', 'c'};
  EXPECT_TRUE(same(sha256(abc), abc_sha256));
  EXPECT_TRUE(same(sha512(abc), abc_sha512));
  EXPECT_TRUE(same(sha3_256(abc), abc_sha3_256));
  EXPECT_TRUE(same(sha3_384(abc), abc_sha3_384));
  const std::array<byte, 3> k{'k', 'e', 'y'};
  EXPECT_TRUE(same(hmac_sha512(k, abc), abc_hmac_sha512));
  // Keccak-256 (the original padding, not SHA3's): its published values.
  const std::array<byte, 32> empty_keccak{0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
                                          0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70};
  EXPECT_TRUE(keccak256(std::span<const byte>()) == empty_keccak);
}
// sntrup761: a secret encapsulated is the secret decapsulated; a
// ciphertext not for the key gives another.
TEST(Crypto, Sntrup761RoundTrip) {
  counting random;
  const auto keys = sntrup761::generate(random);
  const auto sent = sntrup761::encapsulate(keys.pub, random);
  EXPECT_TRUE(sntrup761::decapsulate(keys.secret, sent.cipher) == sent.shared);
  auto other = sent.cipher;
  other[10] ^= 1;
  EXPECT_TRUE(sntrup761::decapsulate(keys.secret, other) != sent.shared);
}
