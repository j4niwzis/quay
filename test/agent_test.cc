// SPDX-License-Identifier: AGPL-3.0-only
// quay.agent: queues as agents carry them, agent messages, envelopes and
// connection links -- written and read back the same.
import std;
import splice;
import gtest;
import quay.bytes;
import quay.crypto;
import quay.smp;
import quay.ratchet;
import quay.agent;

#include "gtest/gtest-macros.h"

namespace {
using namespace quay;
using namespace quay::agent;

struct counting {
  std::uint32_t next = 7;
  void operator()(std::span<byte> out) {
    for (auto& b : out) b = static_cast<byte>((next = next * 1103515245u + 12345u) >> 16);
  }
};
smp::router sample_router() { return smp::router{bytes(32, 0xab), {"smp.example.com", "xyz.onion"}, std::uint16_t{5223}}; }
queue_address sample_address(counting& random) {
  return queue_address{sample_router(), bytes(24, 3), crypto::generate<curve::x25519>(random).pub, queue_mode_t(queue_mode::messaging{})};
}
template <class T, class Put, class Read>
bool round_trips(const T& value, Put put, Read read) {
  bytes wire;
  put(wire, value);
  auto in = reader_of(wire);
  const auto back = read(in);
  return back && in.done() && *back == value;
}
}  // namespace

TEST(Agent, QueueInfoAndAddresses) {
  counting random;
  const queue_info info{4, sample_address(random)};
  EXPECT_TRUE(round_trips(info, [](bytes& w, const queue_info& q) { put_queue_info(w, q); }, [](auto& in) { return read_queue_info(in); }));
  // An older client's: T, read as messaging.
  const queue_info older{3, sample_address(random)};
  EXPECT_TRUE(round_trips(older, [](bytes& w, const queue_info& q) { put_queue_info(w, q); }, [](auto& in) { return read_queue_info(in); }));
  const send_queue_address sq{sample_router(), bytes(24, 9)};
  EXPECT_TRUE(round_trips(sq, [](bytes& w, const send_queue_address& q) { put_send_queue_address(w, q); },
                          [](auto& in) { return read_send_queue_address(in); }));
}

TEST(Agent, MessagesRoundTrip) {
  counting random;
  const auto key = crypto::generate<curve::ed25519>(random).pub;
  const std::vector<agent_message_t> all{
      agent_message::conn_info{bytes{'h', 'i'}},
      agent_message::conn_info_reply{{queue_info{4, sample_address(random)}}, bytes{'p', 'r', 'o', 'f'}},
      agent_message::ratchet_info{bytes{'0'}},
      agent_message::message{{1, bytes{}}, a_message::hello{}},
      agent_message::message{{2, bytes(32, 1)}, a_message::msg{bytes{'b', 'o', 'd', 'y'}}},
      agent_message::message{{3, bytes(32, 2)}, a_message::received{{receipt{2, bytes(32, 5), bytes{'r'}}}}},
      agent_message::message{{4, bytes(32, 3)}, a_message::queue_keys{{{queue_info{4, sample_address(random)}, smp::auth_key(key)}}}},
      agent_message::message{{5, bytes(32, 4)}, a_message::use_queues{{{send_queue_address{sample_router(), bytes(24, 1)}, true}}}},
      agent_message::message{{6, bytes(32, 5)}, a_message::ready{5}},
  };
  for (const auto& m : all) {
    bytes wire;
    put_agent_message(wire, m);
    const auto back = agent_message_of(wire);
    ASSERT_TRUE(back.has_value());
    bytes again;
    put_agent_message(again, *back);
    EXPECT_TRUE(again == wire);
  }
}

TEST(Agent, EnvelopesRoundTrip) {
  counting random;
  auto [params, priv] = ratchet::make_params(ratchet::current_version, true, std::nullopt, random);
  const std::vector<envelope_t> all{envelope::confirmation{7, params, bytes(100, 1)}, envelope::confirmation{7, std::nullopt, bytes(10, 2)},
                                    envelope::message{7, bytes(50, 3)}, envelope::invitation{7, "simplex:/invitation#/?v=2-7", bytes{'x'}},
                                    envelope::ratchet_key{7, params, bytes{'i'}}};
  for (const auto& e : all) {
    bytes wire;
    put_envelope(wire, e);
    const auto back = envelope_of(wire);
    ASSERT_TRUE(back.has_value());
    bytes again;
    put_envelope(again, *back);
    EXPECT_TRUE(again == wire);
  }
}

TEST(Agent, LinksAsText) {
  counting random;
  auto [params, priv] = ratchet::make_params(ratchet::current_version, true, std::nullopt, random);
  link::invitation inv;
  inv.queues.push_back(queue_uri{{1, 4}, sample_address(random)});
  inv.e2e = e2e_params_uri{{2, 3}, params.key1, params.key2, params.kem->template get_if<ratchet::kem_params::proposed>()->key};
  const std::string text = text_of(link_t(inv));
  EXPECT_TRUE(text.starts_with("simplex:/invitation#/?v=2-7&smp=smp%3A%2F%2F"));
  EXPECT_TRUE(text.find("&e2e=v%3D2-3%26x3dh%3D") != std::string::npos);
  const auto back = link_of(text);
  ASSERT_TRUE(back.has_value());
  const auto* i = back->template get_if<link::invitation>();
  ASSERT_TRUE(i != nullptr);
  EXPECT_TRUE(i->queues.size() == 1 && i->queues[0] == inv.queues[0]);
  EXPECT_TRUE(i->e2e.key1 == params.key1 && i->e2e.key2 == params.key2 && i->e2e.kem_key == inv.e2e.kem_key);
  EXPECT_TRUE(text_of(*back) == text);

  link::contact c;
  c.queues.push_back(queue_uri{{1, 4}, sample_address(random)});
  c.client_data = "{\"type\":\"contact\"}";
  const auto contact_text = text_of(link_t(c));
  const auto contact_back = link_of(contact_text);
  ASSERT_TRUE(contact_back && contact_back->template get_if<link::contact>());
  EXPECT_TRUE(contact_back->template get_if<link::contact>()->client_data == c.client_data);
  // The same link, as a client app server's page gives it.
  EXPECT_TRUE(link_of("https://simplex.chat/contact#/?v=2-7&smp=" + contact_text.substr(contact_text.find("&smp=") + 5)).has_value());
}
