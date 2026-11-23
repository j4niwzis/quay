// SPDX-License-Identifier: AGPL-3.0-only
// quay.ratchet: two parties' ratchets, made as SimpleX's agents make them --
// the inviting side's parameters in the invitation, the joining side's in
// reply -- with and without the post-quantum KEM; messages both ways, in
// and out of order; a duplicate refused; the KEM's states as it goes.
import std;
import splice;
import gtest;
import quay.bytes;
import quay.crypto;
import quay.ratchet;

#include "gtest/gtest-macros.h"

namespace {
using namespace quay;
using namespace quay::ratchet;

struct counting {
  std::uint32_t next = 1;
  void operator()(std::span<byte> out) {
    for (auto& b : out) b = static_cast<byte>((next = next * 1103515245u + 12345u) >> 16);
  }
};
bytes text(std::string_view s) { return bytes(s.begin(), s.end()); }

struct pair_of_ratchets {
  state alice, bob;  // alice joined, bob invited
};
pair_of_ratchets connect(bool pq, counting& random) {
  // Bob invites: his parameters, a KEM key proposed where PQ is on.
  auto [bob_pub, bob_priv] = make_params(current_version, pq, std::nullopt, random);
  // Alice replies: hers, accepting his KEM key where he proposed one.
  std::optional<crypto::sntrup761::public_key> proposed;
  if (bob_pub.kem) proposed = bob_pub.kem->template get_if<kem_params::proposed>()->key;
  auto [alice_pub, alice_priv] = make_params(current_version, pq, proposed, random);
  // Her parameters, written and read as the confirmation carries them.
  bytes wire;
  put_e2e_params(wire, alice_pub);
  auto in = reader_of(wire);
  const auto alice_read = read_e2e_params(in);
  EXPECT_TRUE(alice_read.has_value() && in.done());

  const auto sending = x3dh_sending(alice_priv, bob_pub);
  EXPECT_TRUE(sending.has_value());
  const auto fresh = crypto::generate<curve::x448>(random);
  state alice = sending_ratchet(current_version, current_version, bob_pub.key2, fresh.priv, sending->first, sending->second);

  const auto receiving = x3dh_receiving(bob_priv, *alice_read);
  EXPECT_TRUE(receiving.has_value());
  state bob = receiving_ratchet(current_version, current_version, bob_priv.key2, receiving->first, receiving->second, pq);
  EXPECT_TRUE(alice.associated == bob.associated);
  return {std::move(alice), std::move(bob)};
}
constexpr std::size_t padded = 15840;
}  // namespace

TEST(Ratchet, WithoutKem) {
  counting random;
  auto [alice, bob] = connect(false, random);
  const auto m1 = encrypt(alice, text("hello bob"), padded, random);
  ASSERT_TRUE(m1.has_value());
  const auto got1 = decrypt(bob, *m1, random);
  ASSERT_TRUE(got1.has_value());
  EXPECT_TRUE(*got1 == text("hello bob"));
  const auto r1 = encrypt(bob, text("hello alice"), padded, random);
  ASSERT_TRUE(r1.has_value());
  EXPECT_TRUE(*decrypt(alice, *r1, random) == text("hello alice"));
  EXPECT_TRUE(!alice.kem && !bob.kem && !alice.send_kem && !bob.receive_kem);
}

TEST(Ratchet, WithKemBothWays) {
  counting random;
  auto [alice, bob] = connect(true, random);
  EXPECT_TRUE(alice.send_kem);  // the agreement already had the KEM's secret
  for (int round = 0; round < 3; ++round) {
    const auto a = encrypt(alice, text("from alice " + std::to_string(round)), 13618, random);
    ASSERT_TRUE(a.has_value());
    EXPECT_TRUE(*decrypt(bob, *a, random) == text("from alice " + std::to_string(round)));
    const auto b = encrypt(bob, text("from bob " + std::to_string(round)), 13618, random);
    ASSERT_TRUE(b.has_value());
    EXPECT_TRUE(*decrypt(alice, *b, random) == text("from bob " + std::to_string(round)));
  }
  // Every step augmented with the KEM, both ways.
  EXPECT_TRUE(alice.kem && bob.kem && alice.send_kem && alice.receive_kem && bob.send_kem && bob.receive_kem);
}

TEST(Ratchet, OutOfOrderAndDuplicate) {
  counting random;
  auto [alice, bob] = connect(true, random);
  std::vector<bytes> sent;
  for (int i = 0; i < 5; ++i) sent.push_back(*encrypt(alice, text("m" + std::to_string(i)), 13618, random));
  // 4, then 0, 2, 1, 3: the skipped kept, each opened once.
  EXPECT_TRUE(*decrypt(bob, sent[4], random) == text("m4"));
  EXPECT_TRUE(*decrypt(bob, sent[0], random) == text("m0"));
  EXPECT_TRUE(*decrypt(bob, sent[2], random) == text("m2"));
  EXPECT_TRUE(*decrypt(bob, sent[1], random) == text("m1"));
  EXPECT_TRUE(*decrypt(bob, sent[3], random) == text("m3"));
  EXPECT_TRUE(bob.skipped.empty());
  const auto again = decrypt(bob, sent[3], random);
  EXPECT_TRUE(!again.has_value());
  // A message tampered with: refused, the state as it was.
  auto next = *encrypt(alice, text("m5"), 13618, random);
  next.back() ^= 1;
  const auto before = bob.nr;
  EXPECT_TRUE(!decrypt(bob, next, random).has_value());
  EXPECT_EQ(bob.nr, before);
}

TEST(Ratchet, TooLargeRefused) {
  counting random;
  auto [alice, bob] = connect(false, random);
  EXPECT_TRUE(!encrypt(alice, bytes(padded), padded, random).has_value());
}
