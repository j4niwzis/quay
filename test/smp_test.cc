// SPDX-License-Identifier: AGPL-3.0-only
// quay.smp: queue URIs, commands, responses, transmissions in blocks, the
// handshake, and the layers a message goes through -- checked while
// compiling where no cryptography is in it, and run.
import std;
import splice;
import gtest;
import quay.bytes;
import quay.crypto;
import quay.smp;

#include "gtest/gtest-macros.h"

namespace {
using namespace quay;
using namespace quay::smp;

constexpr bytes of(std::string_view s) { return bytes(s.begin(), s.end()); }
constexpr bool starts(const bytes& b, std::string_view s) { return b.size() >= s.size() && std::ranges::equal(std::span(b).first(s.size()), s); }
template <class T> constexpr bool is(const response_t& r) { return r.template get_if<T>() != nullptr; }

constexpr queue_uri sample_queue() {
  queue_uri q;
  q.router = router{bytes{1, 2, 3, 4, 5, 6}, {"smp1.example.com", "abcdef.onion"}, std::uint16_t{5224}};
  q.sender_id = bytes{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 11, 12};
  q.versions = {1, 4};
  for (std::size_t i = 0; i < 32; ++i) q.dh.raw[i] = static_cast<byte>(i * 3);
  q.sender_can_secure = true;
  return q;
}

// A queue URI written and read back the same; one missing its key refused.
static_assert([] {
  const auto q = sample_queue();
  const std::string text = text_of(q);
  if (!text.starts_with("smp://AQIDBAUG@smp1.example.com,abcdef.onion:5224/") || !text.ends_with("&k=s")) return false;
  const auto back = queue_uri_of(text);
  return back && *back == q;
}());
static_assert(!queue_uri_of("smp://AQIDBAUG@h/AQID#/?v=1-4") && !queue_uri_of("https://x") && !queue_uri_of("smp://AQIDBAUG@h/AQID#/?v=4-1&dh=AA"));

// Commands as the wire has them.
static_assert([] {
  bytes out;
  put_command(out, command::ping{});
  bytes ack;
  put_command(ack, command::acknowledge{bytes{1, 2, 3}});
  bytes sub;
  put_command(sub, command::subscribe{});
  bytes send;
  put_command(send, command::send{false, of("xyz")});
  return out == of("PING") && ack == bytes{'A', 'C', 'K', ' ', 3, 1, 2, 3} && sub == of("SUB") && send == of("SEND F xyz");
}());
// NEW: its keys as SubjectPublicKeyInfo behind their lengths, then its flags.
static_assert([] {
  command::create c;
  c.recipient_key = public_key<curve::ed25519>{};
  c.recipient_dh = public_key<curve::x25519>{};
  c.subscribe = true;
  c.request = queue_request::messaging{};
  bytes out;
  put_command(out, c);
  // "NEW " + 1+44 (Ed25519) + 1+44 (X25519) + '0' 'S' '1' 'M' '0' '0'
  return starts(out, "NEW ") && out.size() == 4 + 45 + 45 + 6 && out[4] == 44 && out[49] == 44 &&
         std::ranges::equal(std::span(out).last(6), std::string_view("0S1M00"));
}());

// Responses read into their types.
static_assert([] {
  const auto ok = response_of(of("OK"));
  const auto pong = response_of(of("PONG"));
  const auto end = response_of(of("END"));
  const auto err = response_of(of("ERR CMD NO_AUTH"));
  const auto blocked = response_of(of("ERR BLOCKED reason=spam"));
  if (!ok || !is<response::ok>(*ok) || !pong || !is<response::pong>(*pong) || !end || !is<response::unsubscribed>(*end)) return false;
  const auto* f = err->template get_if<response::failed>();
  const auto* b = blocked->template get_if<response::failed>();
  return f && f->error.template get_if<error::command>() && b && b->error.template get_if<error::blocked>()->reason == "spam" &&
         !response_of(of("WHAT"));
}());
static_assert([] {
  bytes ids = of("IDS ");
  (void)put_short(ids, bytes{1, 1, 1, 1});
  (void)put_short(ids, bytes{2, 2, 2, 2});
  (void)put_short(ids, spki_of(public_key<curve::x25519>{}));
  ids.push_back('1'), ids.push_back('M'), ids.push_back('0'), ids.push_back('0'), ids.push_back('0');
  const auto got = response_of(ids);
  const auto* q = got ? got->template get_if<response::queue_ids>() : nullptr;
  return q && q->recipient_id == bytes{1, 1, 1, 1} && q->sender_id == bytes{2, 2, 2, 2} && q->mode == byte{'M'} && !q->link_id && !q->notifier;
}());
static_assert([] {
  bytes msg = of("MSG ");
  (void)put_short(msg, bytes(24, 7));
  msg.insert(msg.end(), {9, 9, 9});
  const auto got = response_of(msg);
  const auto* m = got ? got->template get_if<response::message>() : nullptr;
  return m && m->id == bytes(24, 7) && m->encrypted == bytes{9, 9, 9};
}());

// Transmissions in a block, and back.
static_assert([] {
  std::vector<transmission> sent;
  corr_id c{};
  for (std::size_t i = 0; i < 24; ++i) c[i] = static_cast<byte>(i);
  sent.push_back(transmission{bytes{}, c, bytes{}, of("PING")});
  sent.push_back(transmission{bytes(64, 5), c, bytes{1, 2, 3}, of("SUB")});
  sent.push_back(transmission{bytes{}, std::nullopt, bytes{4}, of("END")});  // a notification: no correlation id
  for (const std::uint16_t version : {std::uint16_t{15}, std::uint16_t{18}, std::uint16_t{23}}) {
    const auto block = block_of(sent, version);
    if (!block || block->size() != block_size) return false;
    const auto back = transmissions_of(*block, version);
    if (!back || *back != sent) return false;
  }
  // From v16 an authorized transmission has its service signature's place: one byte more.
  bytes v15, v16;
  put_transmission(v15, sent[1], 15), put_transmission(v16, sent[1], 16);
  return v16.size() == v15.size() + 1 && v16[65] == '0';
}());

// The handshake: a router's hello read; the client's written.
static_assert([] {
  bytes content;
  put_u16(content, 6), put_u16(content, 23);
  (void)put_short(content, bytes(32, 1));
  put_byte(content, 2);
  (void)put_large(content, bytes{0x30, 1}), (void)put_large(content, bytes{0x30, 2});
  (void)put_large(content, bytes{0x30, 3});
  content.push_back(0xee);  // what a later version adds: ignored
  bytes block;
  (void)put_padded(block, content, block_size);
  const auto hello = router_hello_of(block);
  return hello && hello->versions == version_range{6, 23} && hello->certificates.size() == 2 && hello->signed_key == bytes{0x30, 3} &&
         agreed_version(hello->versions) == std::uint16_t{23} && !agreed_version({30, 40});
}());
static_assert([] {
  const auto block = client_hello(23, bytes(32, 9));
  const auto content = unpadded(*block);
  return content && content->size() == 2 + 33 + 2 && (*content)[0] == 0 && (*content)[1] == 23 && (*content)[2] == 32 && (*content)[35] == 'F' &&
         (*content)[36] == '0';
}());

struct counting {
  byte next = 1;
  void operator()(std::span<byte> out) {
    for (auto& b : out) b = next++;
  }
};
}  // namespace

// The sender's layer: a message and a confirmation sealed, and opened by
// the recipient, whose key agrees with the sender's.
TEST(Smp, EndToEndLayer) {
  counting random;
  const auto recipient = crypto::generate<curve::x25519>(random);
  const auto sender = crypto::generate<curve::x25519>(random);
  const auto key = *crypto::box_key_of(recipient.pub, sender.priv);
  const auto sealed = e2e_message(key, 4, of("hello"), random);
  ASSERT_TRUE(sealed.has_value());
  EXPECT_EQ(sealed->size(), 2u + 1 + 24 + 16016);
  const auto opened = e2e_open(*sealed, [&](const std::optional<public_key<curve::x25519>>&) {
    return crypto::box_key_of(sender.pub, recipient.priv);
  });
  ASSERT_TRUE(opened.has_value());
  EXPECT_EQ(opened->first, 4);
  EXPECT_TRUE(opened->second.template get_if<e2e::message>()->body == of("hello"));

  const auto sender_auth = crypto::generate<curve::ed25519>(random);
  const auto confirmation = e2e_confirmation(key, 4, sender.pub, auth_key(sender_auth.pub), of("conn info"), random);
  ASSERT_TRUE(confirmation.has_value());
  const auto got = e2e_open(*confirmation, [&](const std::optional<public_key<curve::x25519>>& theirs) {
    return crypto::box_key_of(*theirs, recipient.priv);  // the key in the clear, as a confirmation carries it
  });
  ASSERT_TRUE(got.has_value());
  const auto* c = got->second.template get_if<e2e::confirmation>();
  ASSERT_TRUE(c != nullptr);
  EXPECT_TRUE(c->sender_dh == sender.pub);
  EXPECT_TRUE(c->sender_key && c->sender_key->template get_if<public_key<curve::ed25519>>() && c->body == of("conn info"));
}

// The router's layer: a body as the router seals it -- a box keyed by the
// queue's DH, its nonce the message id -- opened.
TEST(Smp, RouterLayer) {
  counting random;
  const auto recipient = crypto::generate<curve::x25519>(random);
  const auto router_key = crypto::generate<curve::x25519>(random);
  bytes inner;
  put_u64(inner, 1'700'000'000);
  inner.push_back('T'), inner.push_back(' ');
  inner.insert(inner.end(), {1, 2, 3});
  bytes padded;
  ASSERT_TRUE(put_padded(padded, inner, max_message_length + 2).has_value());
  const bytes id(24, 3);
  crypto::box_nonce nonce{};
  std::ranges::copy(id, nonce.begin());
  const response::message got{id, crypto::secretbox(*crypto::box_key_of(recipient.pub, router_key.priv), nonce, padded)};
  const auto opened = router_layer_off(*crypto::box_key_of(router_key.pub, recipient.priv), got);
  ASSERT_TRUE(opened.has_value());
  const auto* s = opened->template get_if<received::sent>();
  ASSERT_TRUE(s != nullptr);
  EXPECT_EQ(s->timestamp, 1'700'000'000u);
  EXPECT_TRUE(s->notify && s->message == bytes({1, 2, 3}));
}

// A recipient's command signed: verified by its public key over what is
// authorized (the session id included, though not sent).
TEST(Smp, SignedCommand) {
  counting random;
  const auto key = crypto::generate<curve::ed25519>(random);
  corr_id c{};
  c[0] = 1;
  const bytes session(32, 4), entity{5, 6};
  const bytes body = of("SUB");
  const bytes sig = signature_over(key.priv, session, c, entity, body);
  bytes authorized;
  put_authorized(authorized, session, c, entity, body);
  crypto::signature<curve::ed25519> s;
  std::ranges::copy(sig, s.raw.begin());
  EXPECT_TRUE(crypto::verify(key.pub, authorized, s));
  EXPECT_EQ(sender_id_for(c).size(), 24u);
}
