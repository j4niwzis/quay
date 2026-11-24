// SPDX-License-Identifier: AGPL-3.0-only
// quay.hpack against RFC 7541's own examples (Appendix C): requests with
// Huffman coding (C.4), responses with Huffman coding and evictions from a
// 256-byte table (C.6); and our encoding decoded back.
import std;
import gtest;
import quay.bytes;
import quay.hpack;
#include "gtest/gtest-macros.h"

using namespace quay;

namespace {
bytes hex(std::string_view s) {
  bytes out;
  std::uint32_t pending = 0;
  int nibbles = 0;
  for (const char c : s) {
    if (c == ' ') continue;
    pending = pending * 16 + static_cast<std::uint32_t>(c >= 'a' ? c - 'a' + 10 : c - '0');
    if (++nibbles == 2) out.push_back(static_cast<byte>(pending)), pending = 0, nibbles = 0;
  }
  return out;
}
using fields = std::vector<hpack::field>;
}  // namespace

TEST(Hpack, RequestsWithHuffman) {
  hpack::decoder d;
  const auto first = d.decode(hex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff"));
  ASSERT_TRUE(first.has_value());
  EXPECT_TRUE(*first == (fields{{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":authority", "www.example.com"}}));
  EXPECT_EQ(d.table_size(), 57u);
  const auto second = d.decode(hex("8286 84be 5886 a8eb 1064 9cbf"));
  ASSERT_TRUE(second.has_value());
  EXPECT_TRUE(*second == (fields{{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":authority", "www.example.com"}, {"cache-control", "no-cache"}}));
  EXPECT_EQ(d.table_size(), 110u);
  const auto third = d.decode(hex("8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf"));
  ASSERT_TRUE(third.has_value());
  EXPECT_TRUE(*third == (fields{{":method", "GET"}, {":scheme", "https"}, {":path", "/index.html"}, {":authority", "www.example.com"}, {"custom-key", "custom-value"}}));
  EXPECT_EQ(d.table_size(), 164u);
}

TEST(Hpack, ResponsesWithHuffmanAndEviction) {
  hpack::decoder d(256);
  const auto first = d.decode(hex("4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6 2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3"));
  ASSERT_TRUE(first.has_value());
  EXPECT_TRUE(*first == (fields{{":status", "302"}, {"cache-control", "private"}, {"date", "Mon, 21 Oct 2013 20:13:21 GMT"}, {"location", "https://www.example.com"}}));
  EXPECT_EQ(d.table_size(), 222u);
  const auto second = d.decode(hex("4883 640e ffc1 c0bf"));
  ASSERT_TRUE(second.has_value());
  EXPECT_TRUE(*second == (fields{{":status", "307"}, {"cache-control", "private"}, {"date", "Mon, 21 Oct 2013 20:13:21 GMT"}, {"location", "https://www.example.com"}}));
  EXPECT_EQ(d.table_size(), 222u);
  const auto third = d.decode(hex("88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab 77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f 9587 3160 65c0 03ed 4ee5 b106 3d50 07"));
  ASSERT_TRUE(third.has_value());
  EXPECT_TRUE(*third == (fields{{":status", "200"},
                                {"cache-control", "private"},
                                {"date", "Mon, 21 Oct 2013 20:13:22 GMT"},
                                {"location", "https://www.example.com"},
                                {"content-encoding", "gzip"},
                                {"set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"}}));
  EXPECT_EQ(d.table_size(), 215u);
  EXPECT_EQ(d.table().size(), 3u);
}

TEST(Hpack, OurRequestsReadBack) {
  const fields request{{":method", "POST"}, {":scheme", "https"}, {":path", "/"}, {":authority", "files.example:443"}, {"x-quay", "1"}};
  const auto block = hpack::encode(request);
  EXPECT_EQ(block[0], 0x83);  // :method POST, whole from the static table
  hpack::decoder d;
  const auto back = d.decode(block);
  ASSERT_TRUE(back.has_value());
  EXPECT_TRUE(*back == request);
  EXPECT_EQ(d.table_size(), 0u);  // nothing indexed
}

TEST(Hpack, Refusals) {
  hpack::decoder d;
  EXPECT_TRUE(!d.decode(hex("be")).has_value());  // index 62: no dynamic entry
  EXPECT_TRUE(!d.decode(hex("4185 ffff ffff ff")).has_value());  // Huffman padding longer than 7 bits / EOS
  EXPECT_TRUE(!d.decode(hex("41")).has_value());  // cut short
}
