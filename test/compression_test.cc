// SPDX-License-Identifier: AGPL-3.0-only
import std;
import gtest;
import quay.bytes;
import quay.compression;
#include "gtest/gtest-macros.h"

using namespace quay;

namespace {
bytes text(std::string_view s) { return s | std::views::transform([](char c) { return static_cast<byte>(c); }) | std::ranges::to<bytes>(); }
std::string chat_message(std::size_t padding) {
  return R"({"v":"1-22","msgId":"cXVheQ==","event":"x.msg.new","params":{"content":{"type":"text","text":")" + std::string(padding, 'q') + R"("}}})";
}
}  // namespace

TEST(Compression, ShortBodiesPassThrough) {
  const auto body = text(R"({"v":"1-22","event":"x.ok","params":{}})");
  const auto p = compression::compress(body);
  EXPECT_TRUE(p == compression::piece_t(compression::piece::passthrough{body}));
  const auto back = compression::decompress(p);
  ASSERT_TRUE(back.has_value());
  EXPECT_TRUE(*back == body);
}

TEST(Compression, LongBodiesAreZstdFrames) {
  const auto body = text(chat_message(2000));
  const auto p = compression::compress(body);
  EXPECT_EQ(compression::decompressed_size(p), std::optional(body.size()));
  const auto back = compression::decompress(p);
  ASSERT_TRUE(back.has_value());
  EXPECT_TRUE(*back == body);
  EXPECT_TRUE(compression::decompress(p, 100).error() == compression::error(compression::errors::too_large{body.size()}));
}

TEST(Compression, BatchFraming) {
  // As simplexmq writes it: 'X', a count, then '0' + short string or '1' + large string.
  const std::vector<compression::piece_t> pieces{compression::piece::passthrough{text("ab")}, compression::piece::zstd{text("zz")}};
  bytes out;
  ASSERT_TRUE(compression::put_batch(out, pieces).has_value());
  EXPECT_TRUE(out == (bytes{'X', 2, '0', 2, 'a', 'b', '1', 0, 2, 'z', 'z'}));
  const auto back = compression::batch_of(std::span<const byte>(out).subspan(1));
  ASSERT_TRUE(back.has_value());
  EXPECT_TRUE(*back == pieces);
}

TEST(Compression, BodiesOfABatch) {
  const auto a = text(chat_message(10)), b = text(chat_message(3000));
  const std::vector<compression::piece_t> pieces{compression::compress(a), compression::compress(b)};
  bytes body;
  ASSERT_TRUE(compression::put_batch(body, pieces).has_value());
  EXPECT_GT(b.size(), body.size());
  const auto bodies = compression::bodies_of(body);
  ASSERT_TRUE(bodies.has_value());
  ASSERT_EQ(bodies->size(), 2u);
  EXPECT_TRUE((*bodies)[0] == a);
  EXPECT_TRUE((*bodies)[1] == b);
  // Not a batch: itself.
  const auto plain = compression::bodies_of(a);
  ASSERT_TRUE(plain.has_value());
  EXPECT_TRUE(plain->front() == a);
}

TEST(Compression, Refusals) {
  EXPECT_TRUE(compression::bodies_of(bytes{'X', 0}).error() == compression::error(compression::errors::empty{}));
  EXPECT_TRUE(compression::bodies_of(bytes{'X', 1, '2'}).error() == compression::error(compression::errors::bad_tag{'2'}));
  EXPECT_TRUE(compression::bodies_of(bytes{'X', 1, '1', 0, 3, 1, 2, 3}).error() == compression::error(compression::errors::no_size{}));
  // Two pieces of 40 KiB each: each within the limit, not together.
  const auto big = text(chat_message(40000));
  const std::vector<compression::piece_t> pieces{compression::compress(big), compression::compress(big)};
  bytes body;
  ASSERT_TRUE(compression::put_batch(body, pieces).has_value());
  EXPECT_TRUE(compression::bodies_of(body).error() == compression::error(compression::errors::too_large{2 * big.size()}));
}
