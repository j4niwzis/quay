// SPDX-License-Identifier: AGPL-3.0-only
// sntrup761 against its known answers: NIST's AES-256-CTR DRBG seeded as the
// KATs are (entropy 0..47, then the 48 bytes it gives), the record liboqs's
// kat_kem writes for count 0 -- seed, pk, sk, ct, ss in upper-case hex --
// and its SHA-256, as liboqs's tests/KATs/kem/kats.json says ("single").
import std;
import gtest;
import quay.bytes;
import quay.crypto;

#include "gtest/gtest-macros.h"

namespace {
using quay::byte;

// NIST's randombytes (rng.c): AES-256 in counter mode, its key and counter
// updated after each call.
class nist_drbg {
 public:
  explicit nist_drbg(std::span<const byte, 48> entropy) { update(entropy); }
  void operator()(std::span<byte> out) {
    std::size_t at = 0;
    while (at < out.size()) {
      increment();
      const auto block = encrypt(v_);
      const std::size_t n = std::min<std::size_t>(16, out.size() - at);
      std::ranges::copy(std::span(block).first(n), out.begin() + static_cast<std::ptrdiff_t>(at));
      at += n;
    }
    update({});
  }

 private:
  void increment() {
    for (int j = 15; j >= 0; --j) {
      if (v_[static_cast<std::size_t>(j)] == 0xff) {
        v_[static_cast<std::size_t>(j)] = 0;
      } else {
        ++v_[static_cast<std::size_t>(j)];
        break;
      }
    }
  }
  // One block of AES-256, as rng.c's AES256_ECB.
  std::array<byte, 16> encrypt(const std::array<byte, 16>& block) const {
    return quay::crypto::aes256_block(key_, block);
  }
  void update(std::span<const byte> provided) {
    std::array<byte, 48> temp{};
    for (std::size_t i = 0; i < 3; ++i) {
      increment();
      const auto b = encrypt(v_);
      std::ranges::copy(b, temp.begin() + static_cast<std::ptrdiff_t>(16 * i));
    }
    for (std::size_t i = 0; i < provided.size(); ++i) temp[i] ^= provided[i];
    std::ranges::copy(std::span(temp).first(32), key_.begin());
    std::ranges::copy(std::span(temp).subspan(32), v_.begin());
  }
  std::array<byte, 32> key_{};
  std::array<byte, 16> v_{};
};

void hex(std::string& out, std::string_view label, std::span<const byte> data) {
  out += label;
  for (const byte b : data) out += std::format("{:02X}", b);
  out += '\n';
}
}  // namespace

TEST(Sntrup761, KnownAnswerAsLiboqs) {
  std::array<byte, 48> entropy{};
  for (std::size_t i = 0; i < 48; ++i) entropy[i] = static_cast<byte>(i);
  nist_drbg first(entropy);
  std::array<byte, 48> seed{};
  first(seed);
  nist_drbg random(seed);
  const auto keys = quay::crypto::sntrup761::generate(random);
  const auto sent = quay::crypto::sntrup761::encapsulate(keys.pub, random);
  EXPECT_TRUE(quay::crypto::sntrup761::decapsulate(keys.secret, sent.cipher) == sent.shared);
  std::string record = "count = 0\n";
  hex(record, "seed = ", seed);
  hex(record, "pk = ", keys.pub.raw);
  hex(record, "sk = ", keys.secret.raw);
  hex(record, "ct = ", sent.cipher);
  hex(record, "ss = ", sent.shared.raw);
  const auto as_bytes = record | std::views::transform([](char c) { return std::bit_cast<byte>(c); }) | std::ranges::to<quay::bytes>();
  const auto digest = quay::crypto::sha256(as_bytes);
  std::string got;
  for (const byte b : digest) got += std::format("{:02x}", b);
  EXPECT_EQ(got, std::string("afc42c3a5b10f4ef69654250097ebda9b9564570f4086744b24a6daf2bd1f89a"));
}
