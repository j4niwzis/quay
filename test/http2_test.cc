// SPDX-License-Identifier: AGPL-3.0-only
// quay.http2 against frames written by hand as a server writes them: the
// preface and settings, a body held to the windows and sent on as they
// open, a response's headers and body, pings, a reset.
import std;
import gtest;
import splice;
import quay.bytes;
import quay.http2;
#include "gtest/gtest-macros.h"

using namespace quay;

namespace {
struct frame {
  byte type = 0, flags = 0;
  std::uint32_t stream = 0;
  bytes payload;
};
// The frames in what the client wrote (after the preface, where there is one).
std::vector<frame> frames_of(bytes data) {
  const std::string_view preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
  std::size_t at = 0;
  if (data.size() >= preface.size() && std::ranges::equal(std::span(data).first(preface.size()), preface | std::views::transform([](char c) { return static_cast<byte>(c); }))) at = preface.size();
  std::vector<frame> out;
  while (data.size() - at >= 9) {
    const std::size_t length = (std::size_t{data[at]} << 16) | (std::size_t{data[at + 1]} << 8) | data[at + 2];
    frame f{data[at + 3], data[at + 4], ((std::uint32_t{data[at + 5]} << 24) | (std::uint32_t{data[at + 6]} << 16) | (std::uint32_t{data[at + 7]} << 8) | data[at + 8]) & 0x7fffffffu,
            bytes(data.begin() + static_cast<std::ptrdiff_t>(at + 9), data.begin() + static_cast<std::ptrdiff_t>(at + 9 + length))};
    out.push_back(std::move(f));
    at += 9 + length;
  }
  return out;
}
bytes frame_bytes(byte type, byte flags, std::uint32_t stream, const bytes& payload) {
  bytes out{static_cast<byte>(payload.size() >> 16), static_cast<byte>(payload.size() >> 8), static_cast<byte>(payload.size()), type, flags};
  put_u32(out, stream);
  put_bytes(out, payload);
  return out;
}
std::size_t data_sent(const std::vector<frame>& fs, bool& ended) {
  std::size_t n = 0;
  for (const auto& f : fs)
    if (f.type == 0) n += f.payload.size(), ended = ended || (f.flags & 1);
  return n;
}
}  // namespace

TEST(Http2, PrefaceSettingsAndABodyHeldToTheWindows) {
  http2::client c("files.example:443");
  const auto opening = c.take_outgoing();
  EXPECT_TRUE(std::ranges::equal(std::span(opening).first(3), bytes{'P', 'R', 'I'}));
  const auto first = frames_of(opening);
  ASSERT_EQ(first.size(), 2u);
  EXPECT_EQ(first[0].type, 4);  // SETTINGS
  EXPECT_EQ(first[1].type, 8);  // WINDOW_UPDATE: our connection window opened

  const auto id = c.post("/", bytes(70000, 'x'));
  EXPECT_EQ(id, 1u);
  bool ended = false;
  const auto sent = frames_of(c.take_outgoing());
  EXPECT_EQ(sent.front().type, 1);  // HEADERS
  EXPECT_EQ(data_sent(sent, ended), 65535u);  // the default windows
  EXPECT_TRUE(!ended);
  for (const auto& f : sent) EXPECT_TRUE(f.payload.size() <= 16384);

  // The server's settings (a larger stream window) and a connection window update.
  bytes settings;
  put_u16(settings, 4), put_u32(settings, 1u << 20);
  bytes increment;
  put_u32(increment, 100000);
  auto in = frame_bytes(4, 0, 0, settings);
  const auto w = frame_bytes(8, 0, 0, increment);
  in.insert(in.end(), w.begin(), w.end());
  c.received(in);
  const auto more = frames_of(c.take_outgoing());
  EXPECT_EQ(more.front().type, 4);  // our SETTINGS ack
  EXPECT_EQ(more.front().flags, 1);
  ended = false;
  EXPECT_EQ(data_sent(more, ended), 70000u - 65535u);
  EXPECT_TRUE(ended);
}

TEST(Http2, AResponseAndItsBody) {
  http2::client c("files.example:443");
  (void)c.take_outgoing();
  const auto id = c.post("/", bytes{1, 2, 3});
  (void)c.take_outgoing();
  // HEADERS: ":status: 200" (static index 8), then DATA in two frames, the last ending the stream.
  auto in = frame_bytes(1, 0x4, id, bytes{0x88});
  const auto d1 = frame_bytes(0, 0, id, bytes{'h', 'e', 'l'});
  const auto d2 = frame_bytes(0, 0x1, id, bytes{'l', 'o'});
  const auto ping = frame_bytes(6, 0, 0, bytes(8, 7));
  in.insert(in.end(), d1.begin(), d1.end());
  in.insert(in.end(), ping.begin(), ping.end());
  in.insert(in.end(), d2.begin(), d2.end());
  // Fed a byte at a time: frames are put together across reads.
  for (const byte b : in) c.received(std::span(&b, 1));
  const auto events = c.take_events();
  ASSERT_EQ(events.size(), 1u);
  const auto* r = events.front().template get_if<http2::event::response>();
  ASSERT_TRUE(r != nullptr);
  EXPECT_EQ(r->status, 200);
  EXPECT_TRUE(r->body == (bytes{'h', 'e', 'l', 'l', 'o'}));
  const auto replies = frames_of(c.take_outgoing());
  EXPECT_TRUE(std::ranges::any_of(replies, [](const frame& f) { return f.type == 6 && f.flags == 1 && f.payload == bytes(8, 7); }));  // the ping answered
  EXPECT_TRUE(std::ranges::any_of(replies, [](const frame& f) { return f.type == 8 && f.stream == 0; }));  // the window given back
}

TEST(Http2, ResetAndGoaway) {
  http2::client c("files.example:443");
  const auto id = c.post("/", {});
  bytes code;
  put_u32(code, 2);
  c.received(frame_bytes(3, 0, id, code));
  auto events = c.take_events();
  ASSERT_EQ(events.size(), 1u);
  EXPECT_TRUE(events.front().template get_if<http2::event::reset>() != nullptr);
  bytes away;
  put_u32(away, 0), put_u32(away, 0);
  c.received(frame_bytes(7, 0, 0, away));
  events = c.take_events();
  ASSERT_EQ(events.size(), 1u);
  EXPECT_TRUE(events.front().template get_if<http2::event::failed>() != nullptr);
}
