// SPDX-License-Identifier: AGPL-3.0-only
import std;
import gtest;
import splice;
import knot;
import quay.bytes;
import quay.compression;
import quay.chat;
#include "gtest/gtest-macros.h"

using namespace quay;

namespace {
bytes text(std::string_view s) { return s | std::views::transform([](char c) { return static_cast<byte>(c); }) | std::ranges::to<bytes>(); }
// As simplex-chat 7.1.4's CLI sent them to quay (live_connection).
constexpr std::string_view cli_info =
    R"({"v":"9-22","event":"x.info","params":{"profile":{"displayName":"cli","fullName":"","preferences":{"calls":{"allow":"yes"},"files":{"allow":"always"}}}}})";
constexpr std::string_view cli_probe =
    R"({"v":"9-22","msgId":"cmhpWXZJQUNBMVkrbk5wRw==","event":"x.info.probe","params":{"probe":"VkpxazA="}})";
}  // namespace

TEST(Chat, ReadsTheCliInfo) {
  const auto got = chat::messages_of(text(cli_info));
  ASSERT_TRUE(got.has_value());
  ASSERT_EQ(got->size(), 1u);
  const auto& m = got->front();
  EXPECT_TRUE(m.v == std::optional<std::string>("9-22"));
  ASSERT_TRUE(m.params.is<chat::event::info>());
  EXPECT_EQ(m.params.as<chat::event::info>().profile.display_name, "cli");
  EXPECT_TRUE(m.params.as<chat::event::info>().profile.preferences.has_value());
}

TEST(Chat, ReadsAProbeAndKeepsUnknownEvents) {
  const auto probe = chat::messages_of(text(cli_probe));
  ASSERT_TRUE(probe.has_value());
  EXPECT_TRUE(probe->front().message_id == std::optional<std::string>("cmhpWXZJQUNBMVkrbk5wRw=="));
  ASSERT_TRUE(probe->front().params.is<chat::event::info_probe>());
  EXPECT_EQ(probe->front().params.as<chat::event::info_probe>().probe, "VkpxazA=");
  const auto other = chat::messages_of(text(R"({"v":"1-22","event":"x.grp.inv","params":{"groupInvitation":{"a":1}}})"));
  ASSERT_TRUE(other.has_value());
  ASSERT_TRUE(other->front().params.is<knot::raw>());
  EXPECT_EQ(other->front().event, "x.grp.inv");
}

TEST(Chat, ReadsMessagesAndTheirKinds) {
  const auto got = chat::messages_of(text(
      R"([{"v":"1-22","msgId":"YQ==","event":"x.msg.new","params":{"content":{"type":"text","text":"hi"}}},)"
      R"({"v":"1-22","msgId":"Yg==","event":"x.msg.new","params":{"content":{"type":"link","text":"see","preview":{"uri":"https://x"}},"ttl":60}},)"
      R"({"v":"1-22","event":"x.msg.react","params":{"msgId":"YQ==","reaction":{"type":"emoji","emoji":"👍"},"add":true}}])"));
  ASSERT_TRUE(got.has_value());
  ASSERT_EQ(got->size(), 3u);
  const auto& first = (*got)[0].params.as<chat::event::message_new>();
  EXPECT_EQ(first.content.text, "hi");
  EXPECT_EQ(chat::kind_of(first.content).index(), chat::kind_t(chat::kind::text{}).index());
  const auto& second = (*got)[1].params.as<chat::event::message_new>();
  EXPECT_EQ(chat::kind_of(second.content).index(), chat::kind_t(chat::kind::link{}).index());
  EXPECT_TRUE(second.content.preview.has_value());
  EXPECT_TRUE(second.ttl == std::optional<std::int64_t>(60));
  const auto& react = (*got)[2].params.as<chat::event::message_react>();
  EXPECT_EQ(react.message_id, "YQ==");
  EXPECT_TRUE(react.reaction.emoji == std::optional<std::string>("👍"));
}

TEST(Chat, WritesAndReadsBack) {
  for (const bool compress : {false, true}) {
    const auto m = chat::message_of(chat::event::message_new{chat::text_content(std::string(compress ? 500 : 5, 'q'))}, "cXVheQ==");
    EXPECT_EQ(m.event, "x.msg.new");
    const auto body = chat::body_of(m, compress);
    EXPECT_EQ(body.front(), compress ? 'X' : '{');
    const auto back = chat::messages_of(body);
    ASSERT_TRUE(back.has_value());
    ASSERT_TRUE(back->front().params.is<chat::event::message_new>());
    EXPECT_EQ(back->front().params.as<chat::event::message_new>().content.text, std::string(compress ? 500 : 5, 'q'));
    EXPECT_TRUE(back->front().message_id == std::optional<std::string>("cXVheQ=="));
  }
}

TEST(Chat, Refusals) {
  EXPECT_TRUE(!chat::messages_of(text("{\"event\":")).has_value());
  EXPECT_TRUE(!chat::messages_of(bytes{'X', 0}).has_value());
}
